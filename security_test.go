package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, string(b)
}

func formPost(ts *httptest.Server, path string, vals url.Values, headers map[string]string, cookies ...*http.Cookie) *http.Request {
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestCrossOriginRequestsRefused(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	session := &http.Cookie{Name: sessionCookie, Value: sid}

	crossSite := []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://evil.example"},
	}
	for _, path := range []string{"/revoke", "/logout", "/oauth/approve", "/oauth/deny", "/f/anything"} {
		for _, h := range crossSite {
			res, _ := do(t, formPost(ts, path, url.Values{"client_id": {"x"}}, h, session))
			if res.StatusCode != http.StatusForbidden {
				t.Fatalf("%s with %v: want 403, got %d", path, h, res.StatusCode)
			}
		}
	}

	for _, h := range []map[string]string{
		{"Sec-Fetch-Site": "same-origin"},
		{"Origin": ts.URL},
		{},
	} {
		res, _ := do(t, formPost(ts, "/revoke", url.Values{"client_id": {"x"}}, h, session))
		if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/" {
			t.Fatalf("same-origin revoke with %v: got %d %s", h, res.StatusCode, res.Header.Get("Location"))
		}
	}

	// Endpoints authenticated without cookies stay reachable cross-origin.
	mcp, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	mcp.Header.Set("Content-Type", "application/json")
	mcp.Header.Set("Sec-Fetch-Site", "cross-site")
	mcp.Header.Set("Origin", "https://claude.ai")
	if res, _ := do(t, mcp); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-origin /mcp must reach bearer auth, got %d", res.StatusCode)
	}
	tok := formPost(ts, "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}},
		map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://claude.ai"})
	if res, body := do(t, tok); res.StatusCode == http.StatusForbidden || !strings.Contains(body, "invalid_client") {
		t.Fatalf("cross-origin token endpoint must reach client checks, got %d %s", res.StatusCode, body)
	}
	// Server-to-server callbacks carry no browser headers and are signed.
	if res, body := do(t, formPost(ts, "/login/backchannel-logout", url.Values{"logout_token": {"x.y.z"}}, nil)); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("back-channel logout must reach token validation, got %d %s", res.StatusCode, body)
	}
	if res, _ := do(t, formPost(ts, "/login/zitadel-events", nil, nil)); res.StatusCode == http.StatusForbidden {
		t.Fatalf("webhook must not be refused as cross-origin")
	}
}

func TestFramingForbidden(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	for _, p := range []string{"/", "/login", "/docs"} {
		res := mustGet(t, ts.URL+p)
		if res.Header.Get("Content-Security-Policy") != "frame-ancestors 'none'" || res.Header.Get("X-Frame-Options") != "DENY" {
			t.Fatalf("%s: framing headers missing: %v", p, res.Header)
		}
	}
}

func setCookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestHostPrefixedSessionCookie(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}},
		mockUser{sub: "mallory", name: "Mallory", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	app.cfg.BaseURL = "https://umfragen.example"
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	const hostName = "__Host-" + sessionCookie
	home := func(cookies ...*http.Cookie) (*http.Response, bool) {
		req, _ := http.NewRequest("GET", ts.URL+"/", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, body := do(t, req)
		return res, strings.Contains(body, "Abmelden")
	}

	_, sid, _ := oidc.login(t, app, "alice")
	if _, in := home(&http.Cookie{Name: hostName, Value: sid}); !in {
		t.Fatal("__Host- session cookie must log in")
	}

	// A session from before the switch is moved to the prefixed cookie.
	_, oldSid, _ := oidc.login(t, app, "alice")
	app.db.Exec(`UPDATE sessions SET host_cookie = 0 WHERE id = ?`, oldSid)
	res, in := home(&http.Cookie{Name: sessionCookie, Value: oldSid})
	if !in {
		t.Fatal("pre-switch session must stay logged in")
	}
	moved, cleared := setCookieNamed(res, hostName), setCookieNamed(res, sessionCookie)
	if moved == nil || moved.Value != oldSid || !moved.Secure || moved.Path != "/" || moved.Domain != "" || moved.MaxAge <= 0 {
		t.Fatalf("session not moved to a valid __Host- cookie: %+v", moved)
	}
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("old cookie not cleared: %+v", cleared)
	}

	// A fresh session under the bare name was planted by another host.
	_, planted, _ := oidc.login(t, app, "mallory")
	if _, in := home(&http.Cookie{Name: sessionCookie, Value: planted}); in {
		t.Fatal("session issued as __Host- must not be accepted under the bare name")
	}

	// Two cookies with one name: neither wins.
	if _, in := home(&http.Cookie{Name: hostName, Value: planted}, &http.Cookie{Name: hostName, Value: sid}); in {
		t.Fatal("duplicate __Host- cookies must count as logged out")
	}
	app.db.Exec(`UPDATE sessions SET host_cookie = 0`)
	if _, in := home(&http.Cookie{Name: sessionCookie, Value: planted}, &http.Cookie{Name: sessionCookie, Value: oldSid}); in {
		t.Fatal("duplicate legacy cookies must count as logged out")
	}

	// Login state cookies carry the prefix too.
	start, _ := do(t, mustReq(t, "GET", ts.URL+"/login/start?next=/"))
	if c := setCookieNamed(start, "__Host-"+stateCookie); c == nil || !c.Secure || c.Path != "/" || c.Domain != "" {
		t.Fatalf("state cookie must be __Host-: %v", start.Cookies())
	}
}

func mustReq(t *testing.T, method, u string) *http.Request {
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestConsentBoundToSession(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}},
		mockUser{sub: "mallory", name: "Mallory", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, alice, _ := oidc.login(t, app, "alice")
	_, mallory, _ := oidc.login(t, app, "mallory")
	doc := newCIMDDoc(t, "Claude")

	au, _ := url.Parse(ts.URL + "/oauth/authorize")
	q := au.Query()
	q.Set("client_id", doc.url)
	q.Set("redirect_uri", doc.redirects[0])
	q.Set("response_type", "code")
	q.Set("code_challenge", b64Challenge("verifier-abc-123-verifier-abc-123-xxxxxx"))
	q.Set("code_challenge_method", "S256")
	au.RawQuery = q.Encode()
	req := mustReq(t, "GET", au.String())
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: mallory})
	_, body := do(t, req)
	id := regexp.MustCompile(`name="authz_id" value="([^"]+)"`).FindStringSubmatch(body)[1]

	res, _ := do(t, formPost(ts, "/oauth/approve", url.Values{"authz_id": {id}}, nil, &http.Cookie{Name: sessionCookie, Value: alice}))
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("approving a request shown to someone else must fail, got %d", res.StatusCode)
	}
	res, _ = do(t, formPost(ts, "/oauth/approve", url.Values{"authz_id": {id}}, nil, &http.Cookie{Name: sessionCookie, Value: mallory}))
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != http.StatusFound || loc.Query().Get("code") == "" || loc.Query().Get("iss") != "http://localhost:8080" {
		t.Fatalf("own approval must redirect with code and iss, got %d %s", res.StatusCode, loc)
	}
}

func TestValidateRedirectURI(t *testing.T) {
	for _, ok := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"http://localhost/callback",
		"http://127.0.0.1:3118/callback",
		"http://[::1]/callback",
	} {
		if err := validateRedirectURI(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"https://claude.ai/cb#frag",
		"https://claude.ai/cb#",
		"http://claude.ai/cb",
		"https://user:pw@claude.ai/cb",
		"javascript:alert(1)",
		"com.example.app:/cb",
		"/relative",
		"http://localhost.evil.example/cb",
	} {
		if err := validateRedirectURI(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}

func TestClientHostTrustPolicy(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	doc := newCIMDDoc(t, "Claude")
	authorize := func() (*http.Response, string) {
		au, _ := url.Parse(ts.URL + "/oauth/authorize")
		q := au.Query()
		q.Set("client_id", doc.url)
		q.Set("redirect_uri", doc.redirects[0])
		q.Set("response_type", "code")
		q.Set("code_challenge", b64Challenge("verifier-abc-123-verifier-abc-123-xxxxxx"))
		q.Set("code_challenge_method", "S256")
		au.RawQuery = q.Encode()
		req := mustReq(t, "GET", au.String())
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
		return do(t, req)
	}
	const warning = "nicht als bekannter Client eingetragen"

	res, body := authorize()
	if res.StatusCode != 200 || !strings.Contains(body, warning) || !strings.Contains(body, "nicht geprüft") {
		t.Fatalf("without a trust policy the consent page must warn: %d", res.StatusCode)
	}

	app.cfg.OAuthClientHosts = []string{"claude.ai"}
	app.cimd.entries = map[string]cimdEntry{}
	hits := doc.hits
	if res, body := authorize(); res.StatusCode != 400 || !strings.Contains(body, "does not accept clients from that host") {
		t.Fatalf("host outside OAUTH_CLIENT_HOSTS must be refused, got %d %s", res.StatusCode, body)
	}
	if doc.hits != hits {
		t.Fatal("metadata of an untrusted host must not even be fetched")
	}

	app.cfg.OAuthClientHosts = []string{"127.0.0.1"}
	if res, body := authorize(); res.StatusCode != 200 || strings.Contains(body, warning) {
		t.Fatalf("listed host: consent without warning expected, got %d", res.StatusCode)
	}
}

func TestPurgeDropsStaleClients(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	old := nowMs() - (cimdStaleMax + time.Hour).Milliseconds()
	for _, id := range []string{"cli_orphan", "cli_in_use", "https://fresh.example/c"} {
		created := old
		if strings.HasPrefix(id, "https") {
			created = nowMs()
		}
		app.db.Exec(`INSERT INTO oauth_clients(client_id, redirect_uris, created_at) VALUES (?, '[]', ?)`, id, created)
	}
	app.db.Exec(`INSERT INTO oauth_tokens(token, kind, client_id, github_id, expires_at, idp_session_id) VALUES ('t','refresh','cli_in_use','u',?, 'i')`, nowMs()+60000)
	app.cimd.entries["https://gone.example/c"] = cimdEntry{expires: time.Now().Add(-time.Minute)}
	app.cimd.entries["https://live.example/c"] = cimdEntry{expires: time.Now().Add(time.Minute)}

	app.purgeAuth()

	var ids []string
	rows, _ := app.db.Query(`SELECT client_id FROM oauth_clients ORDER BY client_id`)
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if strings.Join(ids, ",") != "cli_in_use,https://fresh.example/c" {
		t.Fatalf("stale unreferenced clients must be purged, left: %v", ids)
	}
	if _, ok := app.cimd.entries["https://gone.example/c"]; ok || len(app.cimd.entries) != 1 {
		t.Fatalf("expired cache entries must be evicted: %v", app.cimd.entries)
	}
}
