package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OAuth clients identify themselves with a Client ID Metadata Document
// (CIMD): the client_id IS an https URL, and the JSON document served there
// describes the client (redirect_uris, client_name, …). The authorization
// server fetches it, checks that the document's own `client_id` matches the
// URL, and that is the whole registration. No registration endpoint, no table
// of clients that nobody prunes, and a client called "Claude" is Claude
// because the URL is Anthropic's.
//
// The document is cached in memory (Cache-Control max-age, clamped to
// 1 min…24 h, default 1 h) and the last good copy is persisted in
// oauth_clients, so a hiccup at the metadata host does not break token
// refreshes: a persisted copy is trusted for up to seven days when a fresh
// fetch fails.
//
// Fetching URLs on behalf of strangers is an SSRF surface, so: https only,
// no redirects, hostname must not resolve to a loopback/private/link-local
// address, 10 s timeout, 64 KiB body cap.

const (
	cimdMinTTL     = time.Minute
	cimdMaxTTL     = 24 * time.Hour
	cimdDefaultTTL = time.Hour
	cimdStaleMax   = 7 * 24 * time.Hour
	cimdMaxBody    = 16 << 10 // draft recommends 5 KiB; be lenient, not unbounded
)

type cimdEntry struct {
	client  *OAuthClient
	expires time.Time
}

type cimdCache struct {
	mu      sync.Mutex
	entries map[string]cimdEntry
}

// isClientIDURL reports whether id is a syntactically acceptable CIMD
// client_id: https, a host, a real path, no fragment, no credentials.
func isClientIDURL(id string, allowHTTP bool) bool {
	u, err := url.Parse(id)
	if err != nil {
		return false
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return false
	}
	if u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	return true
}

func blockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// CGNAT 100.64.0.0/10 (tailnets live here) and IPv6 ULA fc00::/7.
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 100 && v4[1]&0xc0 == 64
	}
	return len(ip) == 16 && ip[0]&0xfe == 0xfc
}

func (a *App) cimdHostAllowed(host string) error {
	if a.cimdAllowLocal {
		return nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(a.ctx(), host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if blockedIP(ip.IP) {
			return fmt.Errorf("%s resolves to a non-public address", host)
		}
	}
	return nil
}

type clientMetadataDoc struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// fetchClientMetadata downloads and validates the document at clientID.
func (a *App) fetchClientMetadata(clientID string) (*OAuthClient, time.Duration, error) {
	u, _ := url.Parse(clientID)
	if err := a.cimdHostAllowed(u.Hostname()); err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest("GET", clientID, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "surveys-cimd/1")
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     a.http.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, 0, fmt.Errorf("metadata document: HTTP %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, cimdMaxBody+1))
	if err != nil {
		return nil, 0, err
	}
	if len(raw) > cimdMaxBody {
		return nil, 0, errors.New("metadata document too large")
	}
	var doc clientMetadataDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("metadata document is not JSON: %w", err)
	}
	if doc.ClientID != clientID {
		return nil, 0, fmt.Errorf("metadata document client_id %q does not match %q", doc.ClientID, clientID)
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, 0, errors.New("metadata document has no redirect_uris")
	}
	for _, r := range doc.RedirectURIs {
		if err := validateRedirectURI(r); err != nil {
			return nil, 0, err
		}
		// The document is self-asserted, so a redirect_uri must either live on
		// the client_id's own origin or be a loopback address for a native app.
		// Anything else would let one document hand codes to a third party.
		ru, _ := url.Parse(r)
		if !isLoopback(ru) && !(ru.Scheme == u.Scheme && strings.EqualFold(ru.Host, u.Host)) {
			return nil, 0, fmt.Errorf("redirect_uri %s is neither same-origin with the client_id nor loopback", r)
		}
	}
	if m := doc.TokenEndpointAuthMethod; m != "" && m != "none" {
		return nil, 0, fmt.Errorf("token_endpoint_auth_method %q not supported (public clients with PKCE only)", m)
	}
	grants := doc.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	c := &OAuthClient{
		ClientID:      clientID,
		ClientName:    strings.TrimSpace(doc.ClientName),
		RedirectURIs:  doc.RedirectURIs,
		GrantTypes:    grants,
		TokenAuthMeth: "none",
		CreatedAt:     nowMs(),
	}
	return c, cacheTTL(res.Header.Get("Cache-Control")), nil
}

func cacheTTL(cc string) time.Duration {
	ttl := cimdDefaultTTL
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(part, "max-age=")); err == nil {
				ttl = time.Duration(n) * time.Second
			}
		}
		if part == "no-store" || part == "no-cache" {
			ttl = cimdMinTTL
		}
	}
	if ttl < cimdMinTTL {
		ttl = cimdMinTTL
	}
	if ttl > cimdMaxTTL {
		ttl = cimdMaxTTL
	}
	return ttl
}

// resolveClient returns the client for a CIMD client_id: memory cache, then
// a fresh fetch, then (on fetch failure) the persisted last-good copy if it
// is younger than cimdStaleMax. Anything else is an unknown client.
func (a *App) resolveClient(clientID string) (*OAuthClient, error) {
	if !isClientIDURL(clientID, a.cimdAllowLocal) {
		return nil, nil
	}
	a.cimd.mu.Lock()
	if e, ok := a.cimd.entries[clientID]; ok && time.Now().Before(e.expires) {
		a.cimd.mu.Unlock()
		return e.client, nil
	}
	a.cimd.mu.Unlock()

	c, ttl, err := a.fetchClientMetadata(clientID)
	if err == nil {
		a.cimd.mu.Lock()
		a.cimd.entries[clientID] = cimdEntry{client: c, expires: time.Now().Add(ttl)}
		a.cimd.mu.Unlock()
		if err := a.persistClient(c); err != nil {
			return nil, err
		}
		return c, nil
	}
	logJSON("warn", "client metadata fetch failed", map[string]any{"client_id": clientID, "err": err.Error()})
	stale, dbErr := a.loadPersistedClient(clientID)
	if dbErr != nil {
		return nil, dbErr
	}
	if stale != nil && time.Since(time.UnixMilli(stale.CreatedAt)) < cimdStaleMax {
		a.cimd.mu.Lock()
		a.cimd.entries[clientID] = cimdEntry{client: stale, expires: time.Now().Add(cimdMinTTL)}
		a.cimd.mu.Unlock()
		return stale, nil
	}
	return nil, nil
}

func (a *App) persistClient(c *OAuthClient) error {
	ru, _ := json.Marshal(c.RedirectURIs)
	gt, _ := json.Marshal(c.GrantTypes)
	_, err := a.db.Exec(
		`INSERT INTO oauth_clients(client_id, client_secret, client_name, redirect_uris, grant_types, token_auth_method, created_at)
		 VALUES (?,NULL,?,?,?,?,?)
		 ON CONFLICT(client_id) DO UPDATE SET
		   client_name=excluded.client_name, redirect_uris=excluded.redirect_uris,
		   grant_types=excluded.grant_types, token_auth_method=excluded.token_auth_method,
		   created_at=excluded.created_at`,
		c.ClientID, nullStr(c.ClientName), string(ru), string(gt), c.TokenAuthMeth, c.CreatedAt,
	)
	return err
}
