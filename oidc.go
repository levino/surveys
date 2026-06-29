package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type teamMembership struct {
	Slug         string `json:"slug"`
	IsMaintainer bool   `json:"is_maintainer"`
}

type oidcProvider struct {
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	Issuer   string `json:"issuer"`
}

type oidcClaims struct {
	Subject string   `json:"sub"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
	Groups  []string `json:"groups"`
	Issuer  string   `json:"iss"`
	Expiry  int64    `json:"exp"`
}

func (a *App) ensureOIDC() (*oidcProvider, error) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	if a.oidc != nil {
		return a.oidc, nil
	}
	u := strings.TrimRight(a.cfg.OIDCIssuer, "/") + "/.well-known/openid-configuration"
	res, err := a.http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("oidc discovery: %d %s", res.StatusCode, string(raw))
	}
	var p oidcProvider
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("oidc discovery decode: %w", err)
	}
	if p.AuthURL == "" || p.TokenURL == "" {
		return nil, fmt.Errorf("oidc discovery: missing endpoints")
	}
	a.oidc = &p
	return a.oidc, nil
}

func (a *App) oidcAuthCodeURL(state string) (string, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", a.cfg.OIDCClientID)
	q.Set("redirect_uri", a.cfg.callbackURL())
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email groups")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (a *App) oidcExchange(code string) (*oidcClaims, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.callbackURL())

	req, err := http.NewRequest("POST", p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(a.cfg.OIDCClientID), url.QueryEscape(a.cfg.OIDCClientSecret))

	res, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc token exchange: %d %s", res.StatusCode, string(raw))
	}
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		ErrDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, err
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("oidc token error: %s %s", tok.Error, tok.ErrDesc)
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("oidc token exchange returned no id_token")
	}
	claims, err := parseIDToken(tok.IDToken)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != "" && strings.TrimRight(claims.Issuer, "/") != strings.TrimRight(a.cfg.OIDCIssuer, "/") {
		return nil, fmt.Errorf("oidc issuer mismatch: %q", claims.Issuer)
	}
	if claims.Expiry != 0 && claims.Expiry*1000 < nowMs() {
		return nil, fmt.Errorf("oidc id_token expired")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc id_token has no subject")
	}
	return claims, nil
}

func parseIDToken(idToken string) (*oidcClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("malformed id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("id_token payload decode: %w", err)
	}
	var c oidcClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("id_token claims decode: %w", err)
	}
	return &c, nil
}

func (a *App) teamsFromClaims(c *oidcClaims) []teamMembership {
	seen := map[string]bool{}
	var out []teamMembership
	for _, g := range c.Groups {
		slug := a.cfg.teamFromGroup(g)
		if slug == "" || seen[slug] {
			continue
		}
		seen[slug] = true
		out = append(out, teamMembership{Slug: slug})
	}
	return out
}
