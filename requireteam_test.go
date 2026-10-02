package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// browserLogin drives /login/start -> provider -> /login/callback for sub
// with a cookie jar and returns the callback response (redirects not
// followed) and its body.
func browserLogin(t *testing.T, ts *httptest.Server, oidc *oidcMock, client *http.Client, startPath, sub string) (*http.Response, string) {
	t.Helper()
	res, err := client.Get(ts.URL + startPath)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 {
		t.Fatalf("login start: %d", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	code := oidc.authorize(t, loc.String(), sub)
	cb, err := client.Get(ts.URL + "/login/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(loc.Query().Get("state")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(cb.Body)
	cb.Body.Close()
	return cb, string(body)
}

func jarClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// OIDC_REQUIRE_TEAM: a login without any team gets a 403 page with the
// provider logout link and leaves nothing behind; a member logs in normally.
func TestRequireTeamLogin(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}},
		mockUser{sub: "dave", name: "Dave"},
		mockUser{sub: "erin", name: "Erin", roles: map[string][]string{"p-other": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	app.cfg.RequireTeam = true
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	for _, sub := range []string{"dave", "erin"} {
		res, body := browserLogin(t, ts, oidc, jarClient(), "/login/start?next=/", sub)
		if res.StatusCode != 403 {
			t.Fatalf("%s: want 403, got %d", sub, res.StatusCode)
		}
		if !strings.Contains(body, "Das Umfrage-Tool steht nur Mitgliedern offen") || !strings.Contains(body, oidc.URL+"/end_session?") {
			t.Fatalf("%s: refusal page lacks text or provider logout link: %s", sub, body)
		}
		for _, c := range res.Cookies() {
			if strings.Contains(c.Name, sessionCookie) && c.Value != "" {
				t.Fatalf("%s: no session cookie may be set, got %s", sub, c.Name)
			}
		}
	}
	for _, table := range []string{"sessions", "idp_sessions", "users"} {
		if n := countRows(t, app, table); n != 0 {
			t.Fatalf("refused logins must store nothing, %s has %d rows", table, n)
		}
	}

	res, _ := browserLogin(t, ts, oidc, jarClient(), "/login/start?next=/", "alice")
	if res.StatusCode != 302 || res.Header.Get("Location") != "/" {
		t.Fatalf("member login: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if countRows(t, app, "sessions") != 1 {
		t.Fatalf("member must get a session")
	}
}

// No role claims at all (ZITADEL omits the claim of a project without
// roles; userinfo has none either) means no access — not an error, not a
// pass. Same for a `groups` setup without any group.
func TestRequireTeamWithoutClaims(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "dave", name: "Dave"}, mockUser{sub: "carol", name: "Carol", roles: map[string][]string{"p-b": {"mitglied"}}})
	oidc.noRolesInToken = true
	app := newZitadelApp(t, oidc)
	app.cfg.RequireTeam = true
	if _, _, err := oidc.login(t, app, "dave"); !errors.Is(err, errNoTeam) {
		t.Fatalf("no claims anywhere: want errNoTeam, got %v", err)
	}
	if oidc.userinfoCalls == 0 {
		t.Fatalf("userinfo must have been asked")
	}
	if _, _, err := oidc.login(t, app, "carol"); err != nil {
		t.Fatalf("roles via userinfo must be enough: %v", err)
	}

	gOIDC := newOIDCMock(t,
		mockUser{sub: "nogroups", name: "N"},
		mockUser{sub: "empty", name: "E", groups: []string{}},
		mockUser{sub: "member", name: "M", groups: []string{"acme:marketing"}})
	gApp := newTestApp(t, gOIDC)
	gApp.cfg.RequireTeam = true
	for _, sub := range []string{"nogroups", "empty"} {
		if _, _, err := gOIDC.login(t, gApp, sub); !errors.Is(err, errNoTeam) {
			t.Fatalf("groups %s: want errNoTeam, got %v", sub, err)
		}
	}
	if _, _, err := gOIDC.login(t, gApp, "member"); err != nil {
		t.Fatalf("group member: %v", err)
	}
}

// The MCP OAuth flow logs in through the same callback: without a team it
// ends at the refusal page and no code or token is ever issued.
func TestRequireTeamMcpOAuth(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}},
		mockUser{sub: "dave", name: "Dave"})
	app := newZitadelApp(t, oidc)
	app.cfg.RequireTeam = true
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	doc := newCIMDDoc(t, "test")

	authorize := func(sub string) (*http.Client, *http.Response) {
		client := jarClient()
		au, _ := url.Parse(ts.URL + "/oauth/authorize")
		q := au.Query()
		q.Set("client_id", doc.url)
		q.Set("redirect_uri", doc.redirects[0])
		q.Set("response_type", "code")
		q.Set("resource", "http://localhost:8080/mcp")
		q.Set("code_challenge", b64Challenge("verifier-abc-123-verifier-abc-123-xxxxxx"))
		q.Set("code_challenge_method", "S256")
		q.Set("state", "xyz")
		au.RawQuery = q.Encode()
		res, err := client.Get(au.String())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		start, _ := url.Parse(res.Header.Get("Location"))
		if res.StatusCode != 302 || start.Path != "/login/start" {
			t.Fatalf("authorize without session must go to login: %d %s", res.StatusCode, start)
		}
		cb, _ := browserLogin(t, ts, oidc, client, start.String(), sub)
		return client, cb
	}

	client, cb := authorize("dave")
	if cb.StatusCode != 403 {
		t.Fatalf("no team: want 403, got %d", cb.StatusCode)
	}
	res, err := client.Get(ts.URL + "/oauth/continue")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("continue without session: want 401, got %d", res.StatusCode)
	}
	if n := countRows(t, app, "oauth_codes") + countRows(t, app, "oauth_tokens"); n != 0 {
		t.Fatalf("no codes or tokens may be issued, got %d", n)
	}

	client, cb = authorize("alice")
	if cb.StatusCode != 302 || cb.Header.Get("Location") != "/oauth/continue" {
		t.Fatalf("member: %d %s", cb.StatusCode, cb.Header.Get("Location"))
	}
	res, err = client.Get(ts.URL + "/oauth/continue")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), `name="authz_id"`) {
		t.Fatalf("member must reach the consent page: %d", res.StatusCode)
	}
}

// Losing the last team ends the session at the next refresh — browser
// session and MCP tokens, like a back-channel logout. Losing one of two
// teams does not. A grant event forces that refresh at once.
func TestRequireTeamRefreshEndsSession(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}, "p-b": {"mitglied"}}},
		mockUser{sub: "bob", name: "Bob", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	app.cfg.RequireTeam = true
	app.cfg.WebhookSigningKey = "k"
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

	oidc.setUser("alice", func(u *mockUser) { delete(u.roles, "p-b") })
	makeStale(t, app)
	if s := mcpStatus(t, ts, alice); s != 200 {
		t.Fatalf("one team left: want 200, got %d", s)
	}

	oidc.setUser("alice", func(u *mockUser) { u.roles = nil })
	makeStale(t, app)
	if s := mcpStatus(t, ts, alice); s != 401 {
		t.Fatalf("no team left: want 401, got %d", s)
	}
	if ctx, err := app.resolveSession(aliceSid); ctx != nil || err != nil {
		t.Fatalf("browser session must be gone: %v %v", ctx, err)
	}
	var n int
	app.db.QueryRow(`SELECT COUNT(*) FROM oauth_tokens WHERE github_id = 'alice'`).Scan(&n)
	if n != 0 {
		t.Fatalf("alice's MCP tokens must be deleted, %d left", n)
	}
	app.db.QueryRow(`SELECT COUNT(*) FROM idp_sessions WHERE github_id = 'alice'`).Scan(&n)
	if n != 0 {
		t.Fatalf("alice's provider session must be deleted")
	}

	// ZITADEL event: the changed grant forces the refresh, which ends bob.
	oidc.setUser("bob", func(u *mockUser) { u.roles = map[string][]string{"p-a": {}} })
	if out := app.handleZitadelEvent(zitadelEvent{EventTypeSnake: "user.grant.changed",
		EventPayloadSnk: []byte(`{"userId":"bob","projectId":"p-a"}`)}); out.Action != "refresh_user" {
		t.Fatalf("event: %+v", out)
	}
	if s := mcpStatus(t, ts, bob); s != 401 {
		t.Fatalf("bob without team after event: want 401, got %d", s)
	}
	if ctx, _ := app.resolveSession(bobSid); ctx != nil {
		t.Fatalf("bob's browser session must be gone")
	}
}

// Default (OIDC_REQUIRE_TEAM unset): users without a team log in and keep
// their session when they lose their last team.
func TestWithoutRequireTeamNoTeamIsFine(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "dave", name: "Dave"},
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	res, _ := browserLogin(t, ts, oidc, jarClient(), "/login/start?next=/", "dave")
	if res.StatusCode != 302 {
		t.Fatalf("no team, default config: want login, got %d", res.StatusCode)
	}
	_, sid, err := oidc.login(t, app, "alice")
	if err != nil {
		t.Fatal(err)
	}
	tok := fullOAuthToken(t, ts, sid)
	oidc.setUser("alice", func(u *mockUser) { u.roles = nil })
	makeStale(t, app)
	if s := mcpStatus(t, ts, tok); s != 200 {
		t.Fatalf("default config keeps the session without team, got %d", s)
	}
	if ctx, _ := app.resolveSession(sid); ctx == nil || len(ctx.Teams) != 0 {
		t.Fatalf("session must stay, without teams: %+v", ctx)
	}
}

func TestEnvBool(t *testing.T) {
	for v, want := range map[string]bool{"": false, "true": true, "TRUE": true, "1": true, "yes": true, "false": false, "0": false} {
		t.Setenv("X_BOOL", v)
		if got, err := envBool("X_BOOL", false); err != nil || got != want {
			t.Fatalf("%q: got %v %v", v, got, err)
		}
	}
	t.Setenv("X_BOOL", "ture")
	if _, err := envBool("X_BOOL", false); err == nil {
		t.Fatalf("a typo must be an error")
	}
}

// The share tool tells the AI that a share alone does not open the door.
func TestShareToolMentionsRequireTeam(t *testing.T) {
	desc := func(defs []map[string]any) string {
		for _, d := range defs {
			if d["name"] == "share_form" {
				return d["description"].(string)
			}
		}
		return ""
	}
	if strings.Contains(desc(toolDefs(false)), "Mitglieder eines Teams") || !strings.Contains(desc(toolDefs(true)), "Mitglieder eines Teams") {
		t.Fatalf("share_form description must mention the team requirement only when it is on")
	}
}
