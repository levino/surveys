package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func newZitadelApp(t *testing.T, oidc *oidcMock) *App {
	t.Helper()
	app := newTestApp(t, oidc)
	app.cfg.Scopes = "openid profile email"
	app.cfg.GroupPrefix, app.cfg.MaintainerSuffix = "", ""
	app.cfg.ZitadelTeamProjects = map[string]string{"p-a": "klasse-a", "p-b": "klasse-b"}
	app.cfg.ZitadelMaintainerRole = "admin"
	return app
}

// makeStale pretends the access tokens of every provider session have
// expired, so the next use must refresh.
func makeStale(t *testing.T, app *App) {
	t.Helper()
	if _, err := app.db.Exec(`UPDATE idp_sessions SET refreshed_at = 0, access_expires_at = 0`); err != nil {
		t.Fatal(err)
	}
}

func countRows(t *testing.T, app *App, table string) int {
	t.Helper()
	var n int
	if err := app.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func listTeams(t *testing.T, ts *httptest.Server, tok string) string {
	t.Helper()
	return toolResultText(t, mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "list_teams", "arguments": map[string]any{}}))
}

func mcpStatus(t *testing.T, ts *httptest.Server, tok string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestLoginScopes(t *testing.T) {
	cfg := Config{Scopes: "openid profile email", ZitadelTeamProjects: map[string]string{
		"391868227468132459": "nordstemmen", "391879381867298923": "kreisvorstand"}}
	got := cfg.loginScopes()
	want := "openid profile email offline_access urn:zitadel:iam:org:projects:roles " +
		"urn:zitadel:iam:org:project:id:391868227468132459:aud urn:zitadel:iam:org:project:id:391879381867298923:aud"
	if got != want {
		t.Fatalf("scopes:\n got %q\nwant %q", got, want)
	}
	if got := (Config{Scopes: "openid profile email groups"}).loginScopes(); got != "openid profile email groups" {
		t.Fatalf("without ZITADEL projects the scopes stay as configured: %q", got)
	}
}

func TestRoleClaimShapes(t *testing.T) {
	projects := map[string]string{"p1": "a", "p2": "b", "p3": "c"}
	claims := map[string]json.RawMessage{
		"urn:zitadel:iam:org:project:p1:roles": json.RawMessage(`{"vorstand":{"o1":"x"},"mitglied":{"o1":"x"}}`),
		"urn:zitadel:iam:org:project:p2:roles": json.RawMessage(`[{"mitglied":{"o1":"x"}}]`),
		"urn:zitadel:iam:org:project:roles":    json.RawMessage(`{"vorstand":{"o1":"x"}}`), // own project, not configured by id
	}
	teams, asserted := zitadelTeams(claims, projects, "vorstand")
	if !asserted || len(teams) != 2 || teams[0] != (teamMembership{"a", true}) || teams[1] != (teamMembership{"b", false}) {
		t.Fatalf("teams=%v asserted=%v", teams, asserted)
	}
	if _, asserted := zitadelTeams(map[string]json.RawMessage{}, projects, "vorstand"); asserted {
		t.Fatalf("no claims must mean not asserted")
	}
}

// Login: PKCE, nonce and the ID token signature/iss/aud/exp are enforced.
func TestLoginValidatesIDToken(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)

	if _, _, err := oidc.login(t, app, "alice"); err != nil {
		t.Fatalf("good login failed: %v", err)
	}
	// wrong PKCE verifier: provider refuses the code
	att := newLoginAttempt("/")
	u, _ := app.oidcAuthCodeURL(att)
	code := oidc.authorize(t, u, "alice")
	att.Verifier = "tampered"
	if _, _, err := app.loginViaOIDC(code, att, "x"); err == nil {
		t.Fatalf("wrong code_verifier must fail")
	}
	cases := map[string]func(){
		"nonce":     func() { oidc.badNonce = true },
		"signature": func() { k, _ := rsa.GenerateKey(rand.Reader, 2048); oidc.signWith = k },
		"audience":  func() { oidc.audOverride = "someone-else" },
	}
	for name, breakIt := range cases {
		oidc.set(func() { oidc.badNonce, oidc.signWith, oidc.audOverride = false, nil, ""; breakIt() })
		if _, _, err := oidc.login(t, app, "alice"); err == nil {
			t.Fatalf("%s: login must fail", name)
		}
	}
	oidc.set(func() { oidc.badNonce, oidc.signWith, oidc.audOverride = false, nil, "" })

	// alg none is never accepted
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice"}`))
	if _, err := app.validateIDToken(hdr + "." + body + "."); err == nil {
		t.Fatalf("alg none must be rejected")
	}

	// the login cookie carries state+nonce+verifier; the callback checks state
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(ts.URL + "/login/start?next=/")
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	if loc.Query().Get("code_challenge_method") != "S256" || loc.Query().Get("nonce") == "" {
		t.Fatalf("login redirect lacks PKCE/nonce: %s", loc)
	}
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == stateCookie {
			cookie = c
		}
	}
	code = oidc.authorize(t, loc.String(), "alice")
	req, _ := http.NewRequest("GET", ts.URL+"/login/callback?code="+url.QueryEscape(code)+"&state=wrong", nil)
	req.AddCookie(cookie)
	if r, _ := client.Do(req); r.StatusCode != 400 {
		t.Fatalf("state mismatch must be 400, got %d", r.StatusCode)
	}
	req, _ = http.NewRequest("GET", ts.URL+"/login/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(loc.Query().Get("state")), nil)
	req.AddCookie(cookie)
	if r, _ := client.Do(req); r.StatusCode != 302 || r.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
}

// Teams come from the ZITADEL role claims in the user's own tokens and are
// re-derived on refresh; a rejected refresh ends browser session and MCP
// tokens; a provider outage denies without ending anything.
func TestZitadelRolesFromUserTokens(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied", "admin"}}},
		mockUser{sub: "bob", name: "Bob", roles: map[string][]string{"p-a": {"mitglied"}, "p-b": {"mitglied"}, "p-other": {"x"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	_, aliceSid, err := oidc.login(t, app, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, bobSid, err := oidc.login(t, app, "bob")
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := fullOAuthToken(t, ts, aliceSid), fullOAuthToken(t, ts, bobSid)

	teams := listTeams(t, ts, bob)
	if !strings.Contains(teams, `"klasse-a"`) || !strings.Contains(teams, `"klasse-b"`) || strings.Contains(teams, "is_maintainer\": true") {
		t.Fatalf("bob: member of both classes, maintainer of none, got %s", teams)
	}
	teams = listTeams(t, ts, alice)
	if !strings.Contains(teams, `"is_maintainer": true`) || strings.Contains(teams, `"klasse-b"`) {
		t.Fatalf("alice: maintainer of klasse-a only, got %s", teams)
	}
	create := mcpCall(t, ts, bob, "tools/call", map[string]any{"name": "create_form",
		"arguments": map[string]any{"title": "Fest", "owner_team": "klasse-b",
			"fields": []map[string]any{{"key": "n", "label": "N", "type": "text"}}}})
	var created map[string]any
	json.Unmarshal([]byte(toolResultText(t, create)), &created)
	formID := created["id"].(string)

	// Revoke bob's klasse-b role. Within the refresh interval nothing asks
	// the provider; once the tokens are stale, the next call refreshes.
	oidc.setUser("bob", func(u *mockUser) { delete(u.roles, "p-b") })
	calls := oidc.refreshCalls
	if !strings.Contains(listTeams(t, ts, bob), `"klasse-b"`) || oidc.refreshCalls != calls {
		t.Fatalf("fresh tokens must be used without asking the provider")
	}
	makeStale(t, app)
	res, _ := mcpCall(t, ts, bob, "tools/call", map[string]any{"name": "get_form", "arguments": map[string]any{"id": formID}})["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("revoked role must lose access after refresh")
	}
	if oidc.refreshCalls != calls+1 {
		t.Fatalf("expected exactly one refresh, got %d", oidc.refreshCalls-calls)
	}
	// the browser session sees the same re-derived teams
	if ctx, _ := app.resolveSession(bobSid); ctx == nil || ctx.isMember("klasse-b") || !ctx.isMember("klasse-a") {
		t.Fatalf("browser session teams not refreshed: %+v", ctx)
	}

	// Provider down: deny with 503 (fail closed), keep session and tokens.
	oidc.set(func() { oidc.down = true })
	makeStale(t, app)
	if s := mcpStatus(t, ts, alice); s != 503 {
		t.Fatalf("provider down: want 503, got %d", s)
	}
	if ctx, err := app.resolveSession(aliceSid); ctx != nil || err == nil {
		t.Fatalf("provider down: browser session must be denied with an error, got %v %v", ctx, err)
	}
	oidc.set(func() { oidc.down = false })
	if !strings.Contains(listTeams(t, ts, alice), `"klasse-a"`) {
		t.Fatalf("after recovery alice must work again")
	}

	// Blocked at the provider: refresh rejected -> session, MCP tokens gone.
	oidc.setUser("alice", func(u *mockUser) { u.blocked = true })
	makeStale(t, app)
	if s := mcpStatus(t, ts, alice); s != 401 {
		t.Fatalf("rejected refresh: want 401, got %d", s)
	}
	if ctx, _ := app.resolveSession(aliceSid); ctx != nil {
		t.Fatalf("browser session must be gone")
	}
	var n int
	app.db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE github_id = 'alice'`).Scan(&n)
	if n != 0 {
		t.Fatalf("alice's MCP tokens must be deleted, %d left", n)
	}
	// bob is untouched
	if s := mcpStatus(t, ts, bob); s != 200 {
		t.Fatalf("bob must be unaffected, got %d", s)
	}
}

// Without roles in the ID token, the teams come from userinfo.
func TestRolesFromUserinfoFallback(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "carol", name: "Carol", roles: map[string][]string{"p-b": {"admin"}}})
	oidc.noRolesInToken = true
	app := newZitadelApp(t, oidc)
	_, sid, err := oidc.login(t, app, "carol")
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := app.resolveSession(sid)
	if ctx == nil || !ctx.isMaintainer("klasse-b") || oidc.userinfoCalls != 1 {
		t.Fatalf("userinfo fallback: ctx=%+v calls=%d", ctx, oidc.userinfoCalls)
	}
}

// Our own refresh grant runs the same freshness check: once the provider
// session is dead, the MCP client gets invalid_grant.
func TestMcpRefreshFollowsProviderSession(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	fullOAuthToken(t, ts, sid)

	var rt, client string
	app.db.QueryRow(`SELECT token, client_id FROM oauth_tokens WHERE kind = 'refresh'`).Scan(&rt, &client)
	refresh := func() (int, map[string]any) {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {rt}}
		res, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	code, out := refresh()
	if code != 200 {
		t.Fatalf("refresh while alive: %d %v", code, out)
	}
	rt = out["refresh_token"].(string)
	var unbound, sessions int
	app.db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE idp_session_id IS NULL`).Scan(&unbound)
	app.db.QueryRow(`SELECT COUNT(DISTINCT idp_session_id) FROM oauth_tokens`).Scan(&sessions)
	if unbound != 0 || sessions != 1 {
		t.Fatalf("new tokens must stay bound to the provider session: unbound=%d sessions=%d", unbound, sessions)
	}
	oidc.setUser("alice", func(u *mockUser) { u.blocked = true })
	makeStale(t, app)
	if code, out := refresh(); code != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("dead provider session: want invalid_grant, got %d %v", code, out)
	}
}

// Rows from before the session binding are not accepted any more.
func TestLegacyUnboundSessionsRejected(t *testing.T) {
	oidc := newOIDCMock(t)
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	now := nowMs()
	app.db.Exec(`INSERT INTO users(github_id, github_username, cached_at) VALUES ('old','old',?)`, now)
	app.db.Exec(`INSERT INTO sessions(id, github_id, created_at, expires_at) VALUES ('sess_old','old',?,?)`, now, now+100000)
	app.db.Exec(`INSERT INTO oauth_tokens(token, kind, client_id, github_id, expires_at) VALUES ('at_old','access','c','old',?)`, now+100000)
	if ctx, _ := app.resolveSession("sess_old"); ctx != nil {
		t.Fatalf("unbound browser session must be rejected")
	}
	if s := mcpStatus(t, ts, "at_old"); s != 401 {
		t.Fatalf("unbound MCP token must be 401, got %d", s)
	}
}

func TestBackchannelLogout(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}},
		mockUser{sub: "bob", name: "Bob", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	post := func(token string) *http.Response {
		res, err := http.PostForm(ts.URL+"/login/backchannel-logout", url.Values{"logout_token": {token}})
		if err != nil {
			t.Fatal(err)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("missing Cache-Control: no-store")
		}
		return res
	}

	_, aliceSid, _ := oidc.login(t, app, "alice")
	aliceTok := fullOAuthToken(t, ts, aliceSid)
	_, bobSid, _ := oidc.login(t, app, "bob")
	bobTok := fullOAuthToken(t, ts, bobSid)

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := signRS256(other, oidc.kid, map[string]any{"iss": oidc.URL, "aud": mockClientID, "iat": 1, "sid": "sid-alice",
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}}})
	bad := map[string]string{
		"missing":   "",
		"garbage":   "a.b.c",
		"signature": forged,
		"nonce":     oidc.logoutToken(map[string]any{"sid": "sid-alice", "nonce": "n"}),
		"aud":       oidc.logoutToken(map[string]any{"sid": "sid-alice", "aud": "other"}),
		"iss":       oidc.logoutToken(map[string]any{"sid": "sid-alice", "iss": "https://evil.example"}),
		"no event":  oidc.logoutToken(map[string]any{"sid": "sid-alice", "events": map[string]any{"x": map[string]any{}}}),
		"no subsid": oidc.logoutToken(nil),
		"no iat":    oidc.logoutToken(map[string]any{"sid": "sid-alice", "iat": nil}),
		"expired":   oidc.logoutToken(map[string]any{"sid": "sid-alice", "exp": 1}),
	}
	for name, tok := range bad {
		if r := post(tok); r.StatusCode != 400 {
			t.Fatalf("%s: want 400, got %d", name, r.StatusCode)
		}
	}
	if s := mcpStatus(t, ts, aliceTok); s != 200 {
		t.Fatalf("rejected logout tokens must not end anything, got %d", s)
	}

	// by sid: alice's session and MCP token are gone at once, bob stays
	if r := post(oidc.logoutToken(map[string]any{"sid": "sid-alice", "sub": "alice"})); r.StatusCode != 200 {
		t.Fatalf("valid logout token: %d", r.StatusCode)
	}
	if s := mcpStatus(t, ts, aliceTok); s != 401 {
		t.Fatalf("alice's MCP token must be dead, got %d", s)
	}
	if ctx, _ := app.resolveSession(aliceSid); ctx != nil {
		t.Fatalf("alice's browser session must be dead")
	}
	if s := mcpStatus(t, ts, bobTok); s != 200 {
		t.Fatalf("bob must be unaffected, got %d", s)
	}
	// by sub only
	if r := post(oidc.logoutToken(map[string]any{"sub": "bob"})); r.StatusCode != 200 {
		t.Fatalf("sub-only logout token: %d", r.StatusCode)
	}
	if s := mcpStatus(t, ts, bobTok); s != 401 {
		t.Fatalf("bob's MCP token must be dead, got %d", s)
	}
	if n := countRows(t, app, "idp_sessions"); n != 0 {
		t.Fatalf("provider sessions left: %d", n)
	}
	// unknown session: still 200 (nothing to do)
	if r := post(oidc.logoutToken(map[string]any{"sid": "nope"})); r.StatusCode != 200 {
		t.Fatalf("unknown sid: %d", r.StatusCode)
	}
}

func TestPurgeAuthDropsOrphans(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:x"}})
	app := newTestApp(t, oidc)
	_, sid, _ := oidc.login(t, app, "alice")
	app.db.Exec(`UPDATE idp_sessions SET created_at = 0`)
	app.purgeAuth()
	if countRows(t, app, "idp_sessions") != 1 {
		t.Fatalf("referenced provider session must survive")
	}
	app.destroySession(sid)
	app.purgeAuth()
	if countRows(t, app, "idp_sessions") != 0 {
		t.Fatalf("orphaned provider session (and its refresh token) must be purged")
	}
}

// The provider rotates refresh tokens: parallel requests on a stale session
// must share one refresh, not burn the token against each other.
func TestConcurrentRefreshIsSerialised(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	tok := fullOAuthToken(t, ts, sid)
	makeStale(t, app)
	calls := oidc.refreshCalls
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = mcpStatus(t, ts, tok) }(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	if oidc.refreshCalls != calls+1 {
		t.Fatalf("want exactly one refresh, got %d", oidc.refreshCalls-calls)
	}
}
