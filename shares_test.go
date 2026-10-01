package main

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func isToolErr(res map[string]any) bool {
	r, _ := res["result"].(map[string]any)
	return r["isError"] == true
}

func callJSON(t *testing.T, ts *httptest.Server, tok, name string, args map[string]any) map[string]any {
	t.Helper()
	res := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": name, "arguments": args})
	if isToolErr(res) {
		t.Fatalf("%s failed: %s", name, toolResultText(t, res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(toolResultText(t, res)), &out); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return out
}

func listedForms(t *testing.T, ts *httptest.Server, tok string) []map[string]any {
	t.Helper()
	raw, _ := callJSON(t, ts, tok, "list_forms", map[string]any{})["forms"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, f := range raw {
		out = append(out, f.(map[string]any))
	}
	return out
}

func webGet(t *testing.T, ts *httptest.Server, sid, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func webPost(t *testing.T, ts *httptest.Server, sid, path string, form url.Values) int {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

// A survey without team belongs to its creator; a share by e-mail gives
// read access (case-insensitive, verified addresses only) but no rights to
// change anything. Everybody else sees nothing.
func TestPersonalSurveyAndEmailShares(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "levin", name: "Levin", email: "levin@example.org", emailVerified: true},
		mockUser{sub: "jutta", name: "Jutta", email: "Hartmann-Nordstemmen@T-Online.de", emailVerified: true},
		mockUser{sub: "mallory", name: "Mallory", email: "hartmann-nordstemmen@t-online.de", emailVerified: false},
		mockUser{sub: "nobody", name: "Nobody", email: "hartmann-nordstemmen@t-online.de"}, // no email_verified claim
		mockUser{sub: "teamie", name: "Teamie", groups: []string{"acme:marketing", "acme:marketing:admin"}, email: "teamie@example.org", emailVerified: true})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	sids := map[string]string{}
	tok := func(sub string) string {
		_, sid, err := oidc.login(t, app, sub)
		if err != nil {
			t.Fatalf("login %s: %v", sub, err)
		}
		sids[sub] = sid
		return fullOAuthToken(t, ts, sid)
	}
	levin, jutta, mallory, nobody, teamie := tok("levin"), tok("jutta"), tok("mallory"), tok("nobody"), tok("teamie")

	if got := callJSON(t, ts, jutta, "list_teams", map[string]any{}); got["email"] != "hartmann-nordstemmen@t-online.de" {
		t.Fatalf("verified e-mail must be stored lowercase, got %v", got["email"])
	}
	if got := callJSON(t, ts, mallory, "list_teams", map[string]any{}); got["email"] != "" {
		t.Fatalf("unverified e-mail must not be stored, got %v", got["email"])
	}

	// levin has no team at all and still creates a survey
	created := callJSON(t, ts, levin, "create_form", map[string]any{
		"title": "Vorstandsklausur", "shared_with": []string{" HARTMANN-nordstemmen@t-online.de "},
		"fields": []map[string]any{{"key": "termin", "label": "Termin", "type": "text"}},
	})
	formID := created["id"].(string)
	if created["owner_team"] != "" || created["can_manage"] != true {
		t.Fatalf("personal survey: %v", created)
	}
	if sw, _ := created["shared_with"].([]any); len(sw) != 1 || sw[0] != "hartmann-nordstemmen@t-online.de" {
		t.Fatalf("shared_with must be normalised: %v", created["shared_with"])
	}
	if _, err := app.insertSubmission(formID, map[string]string{"termin": "Samstag"}, "ua", "ip"); err != nil {
		t.Fatal(err)
	}
	var subID string
	app.db.QueryRow(`SELECT id FROM submissions WHERE form_id = ?`, formID).Scan(&subID)

	// creator lists it with its shares
	if lf := listedForms(t, ts, levin); len(lf) != 1 || lf[0]["can_manage"] != true || lf[0]["shared_with"] == nil {
		t.Fatalf("creator list: %v", lf)
	}

	// jutta: sees and reads, cannot change, does not see the share list
	lf := listedForms(t, ts, jutta)
	if len(lf) != 1 || lf[0]["can_manage"] != false {
		t.Fatalf("jutta must see the survey read-only: %v", lf)
	}
	if _, ok := lf[0]["shared_with"]; ok {
		t.Fatalf("shared_with is for managers only: %v", lf[0])
	}
	if g := callJSON(t, ts, jutta, "get_form", map[string]any{"id": formID}); g["shared_with"] != nil {
		t.Fatalf("get_form must not show shares to a reader: %v", g)
	}
	if s := callJSON(t, ts, jutta, "list_submissions", map[string]any{"form_id": formID}); s["count"] != float64(1) {
		t.Fatalf("jutta must read results: %v", s)
	}
	if isToolErr(mcpCall(t, ts, jutta, "tools/call", map[string]any{"name": "export_submissions", "arguments": map[string]any{"form_id": formID}})) {
		t.Fatalf("jutta must export results")
	}
	for name, args := range map[string]map[string]any{
		"update_form":       {"id": formID, "title": "x"},
		"disable_form":      {"id": formID},
		"delete_form":       {"id": formID},
		"share_form":        {"id": formID, "add": []string{"friend@example.org"}},
		"delete_submission": {"id": subID},
	} {
		if !isToolErr(mcpCall(t, ts, jutta, "tools/call", map[string]any{"name": name, "arguments": args})) {
			t.Fatalf("a share must not allow %s", name)
		}
	}

	// unverified or unconfirmed address, other teams: nothing
	for who, tk := range map[string]string{"mallory": mallory, "nobody": nobody, "teamie": teamie} {
		if lf := listedForms(t, ts, tk); len(lf) != 0 {
			t.Fatalf("%s must not see the survey: %v", who, lf)
		}
		if !isToolErr(mcpCall(t, ts, tk, "tools/call", map[string]any{"name": "get_form", "arguments": map[string]any{"id": formID}})) {
			t.Fatalf("%s must not read the survey", who)
		}
	}

	// web: jutta reads the results page without the share editor, cannot post to it
	ref := created["ref"].(string)
	if code, body := webGet(t, ts, sids["jutta"], "/surveys/"+ref); code != 200 || !strings.Contains(body, "Samstag") || strings.Contains(body, "Freigeben") {
		t.Fatalf("jutta results page: %d", code)
	}
	if code, _ := webGet(t, ts, sids["jutta"], "/surveys/"+ref+"/export.csv"); code != 200 {
		t.Fatalf("jutta csv: %d", code)
	}
	if code := webPost(t, ts, sids["jutta"], "/surveys/"+ref+"/shares", url.Values{"action": {"add"}, "email": {"x@example.org"}}); code != 403 {
		t.Fatalf("jutta must not edit shares, got %d", code)
	}
	if code, _ := webGet(t, ts, sids["mallory"], "/surveys/"+ref); code != 404 {
		t.Fatalf("mallory results page: want 404, got %d", code)
	}
	// web: levin sees and edits the shares
	if code, body := webGet(t, ts, sids["levin"], "/surveys/"+ref); code != 200 || !strings.Contains(body, "hartmann-nordstemmen@t-online.de") || !strings.Contains(body, "persönlich") {
		t.Fatalf("levin results page: %d", code)
	}
	if code := webPost(t, ts, sids["levin"], "/surveys/"+ref+"/shares", url.Values{"action": {"add"}, "email": {"Teamie@Example.org"}}); code != 303 {
		t.Fatalf("add share via web: %d", code)
	}
	if lf := listedForms(t, ts, teamie); len(lf) != 1 || lf[0]["can_manage"] != false {
		t.Fatalf("teamie (maintainer of another team) gets read access by share only: %v", lf)
	}
	if code, body := webGet(t, ts, sids["teamie"], "/"); code != 200 || !strings.Contains(body, "mit dir geteilt") {
		t.Fatalf("dashboard must list surveys shared with me: %d", code)
	}
	if code := webPost(t, ts, sids["levin"], "/surveys/"+ref+"/shares", url.Values{"action": {"add"}, "email": {"not-an-address"}}); code != 400 {
		t.Fatalf("invalid address: want 400, got %d", code)
	}

	// revoking the share ends jutta's access at once
	out := callJSON(t, ts, levin, "share_form", map[string]any{"id": formID, "remove": []string{"Hartmann-Nordstemmen@t-online.de"}})
	if sw, _ := out["shared_with"].([]any); len(sw) != 1 || sw[0] != "teamie@example.org" {
		t.Fatalf("after remove: %v", out)
	}
	if lf := listedForms(t, ts, jutta); len(lf) != 0 {
		t.Fatalf("revoked share must hide the survey: %v", lf)
	}
	if !isToolErr(mcpCall(t, ts, levin, "tools/call", map[string]any{"name": "share_form", "arguments": map[string]any{"id": formID, "add": []string{"kaputt"}}})) {
		t.Fatalf("invalid address must be refused")
	}

	// the creator still manages it; deleting it removes the shares
	if isToolErr(mcpCall(t, ts, levin, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{"id": formID, "title": "Klausur 2"}})) {
		t.Fatalf("creator must update")
	}
	if isToolErr(mcpCall(t, ts, levin, "tools/call", map[string]any{"name": "delete_form", "arguments": map[string]any{"id": formID}})) {
		t.Fatalf("creator must delete")
	}
	if n := countRows(t, app, "form_shares"); n != 0 {
		t.Fatalf("shares must go with the survey, %d left", n)
	}
}

// Team surveys keep working as before, and can additionally be shared with
// someone outside the team (read only). A team needs membership.
func TestTeamSurveyWithShare(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", groups: []string{"acme:klasse-a"}},
		mockUser{sub: "dave", name: "Dave", groups: []string{"acme:klasse-a", "acme:klasse-a:admin"}},
		mockUser{sub: "oma", name: "Oma", email: "oma@example.org", emailVerified: "true"})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	tok := func(sub string) string {
		_, sid, err := oidc.login(t, app, sub)
		if err != nil {
			t.Fatal(err)
		}
		return fullOAuthToken(t, ts, sid)
	}
	alice, dave, oma := tok("alice"), tok("dave"), tok("oma")
	fields := []map[string]any{{"key": "a", "label": "A", "type": "text"}}

	if !isToolErr(mcpCall(t, ts, oma, "tools/call", map[string]any{"name": "create_form", "arguments": map[string]any{"title": "X", "owner_team": "klasse-a", "fields": fields}})) {
		t.Fatalf("owner_team still requires membership")
	}
	created := callJSON(t, ts, alice, "create_form", map[string]any{"title": "Fest", "owner_team": "klasse-a", "fields": fields})
	id := created["id"].(string)
	// the maintainer manages the shares of a team survey
	callJSON(t, ts, dave, "share_form", map[string]any{"id": id, "add": []string{"OMA@example.org"}})
	lf := listedForms(t, ts, oma)
	if len(lf) != 1 || lf[0]["can_manage"] != false || lf[0]["owner_team"] != "klasse-a" {
		t.Fatalf("oma must read the shared team survey: %v", lf)
	}
	if !isToolErr(mcpCall(t, ts, oma, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{"id": id, "title": "x"}})) {
		t.Fatalf("a share must not allow changes to a team survey")
	}
	if lf := listedForms(t, ts, dave); len(lf) != 1 || lf[0]["shared_with"] == nil {
		t.Fatalf("maintainer sees the shares: %v", lf)
	}
}

func TestVerifiedEmailClaim(t *testing.T) {
	claims := func(js string) jwtClaims {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(js), &m); err != nil {
			t.Fatal(err)
		}
		return jwtClaims{raw: m}
	}
	for js, want := range map[string]string{
		`{"email":"A@B.de","email_verified":true}`:     "a@b.de",
		`{"email":" A@B.de ","email_verified":"true"}`: "a@b.de",
		`{"email":"a@b.de","email_verified":false}`:    "",
		`{"email":"a@b.de","email_verified":"false"}`:  "",
		`{"email":"a@b.de"}`:                           "",
		`{"email_verified":true}`:                      "",
	} {
		if got := verifiedEmail(claims(js)); got != want {
			t.Errorf("%s: got %q want %q", js, got, want)
		}
	}
}

// ZITADEL without "User Info inside ID Token": the address comes from
// userinfo, is re-read on every refresh, and an e-mail event forces that.
func TestEmailFromUserinfoAndRefresh(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "jutta", name: "Jutta", roles: map[string][]string{"p-a": {"mitglied"}},
		email: "Jutta@Example.org", emailVerified: true})
	oidc.emailOnlyInUserinfo = true
	app := newZitadelApp(t, oidc)
	_, sid, err := oidc.login(t, app, "jutta")
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := app.resolveSession(sid)
	if ctx == nil || ctx.User.Email != "jutta@example.org" || !ctx.isMember("klasse-a") {
		t.Fatalf("email from userinfo: %+v", ctx)
	}
	f := &Form{ID: "f", OwnerTeam: "", CreatedBy: "someone", SharedWith: []string{"jutta@example.org"}}
	if !ctx.canView(f) || ctx.canManage(f) {
		t.Fatalf("share: view yes, manage no")
	}

	// address changed and not yet verified: after the event-forced refresh it no longer counts
	oidc.setUser("jutta", func(u *mockUser) { u.email, u.emailVerified = "neu@example.org", false })
	var ev zitadelEvent
	json.Unmarshal([]byte(`{"event_type":"user.human.email.changed","aggregateID":"jutta"}`), &ev)
	if out := app.handleZitadelEvent(ev); out.Action != "refresh_user" || out.Sessions != 1 {
		t.Fatalf("email event: %+v", out)
	}
	ctx, _ = app.resolveSession(sid)
	if ctx == nil || ctx.User.Email != "" || ctx.canView(f) {
		t.Fatalf("unverified new address must clear access: %+v", ctx)
	}
	// verified later: counts again
	oidc.setUser("jutta", func(u *mockUser) { u.emailVerified = true })
	makeStale(t, app)
	if ctx, _ = app.resolveSession(sid); ctx == nil || ctx.User.Email != "neu@example.org" {
		t.Fatalf("verified address after refresh: %+v", ctx)
	}
}

// A database from before this change (owner_team NOT NULL without default,
// users without email, no form_shares) migrates without losing a row.
func TestMigrateLegacyFormsAndUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (github_id TEXT PRIMARY KEY, github_username TEXT NOT NULL, name TEXT, avatar_url TEXT, cached_at INTEGER NOT NULL)`,
		`CREATE TABLE forms (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, ref TEXT, title TEXT NOT NULL, description TEXT,
		   fields TEXT NOT NULL DEFAULT '[]', owner_team TEXT NOT NULL,
		   status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
		   allow_multiple INTEGER NOT NULL DEFAULT 1, expires_at INTEGER, created_by TEXT, created_at INTEGER NOT NULL, delete_at INTEGER)`,
		`CREATE TABLE submissions (id TEXT PRIMARY KEY, form_id TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
		   data TEXT NOT NULL DEFAULT '{}', user_agent TEXT, ip_hash TEXT, created_at INTEGER NOT NULL)`,
		`INSERT INTO users VALUES ('alice','Alice','Alice',NULL,1)`,
		`INSERT INTO forms(id, slug, ref, title, fields, owner_team, created_by, created_at) VALUES ('form_old','slugold','alt','Alt','[{"key":"a","label":"A","type":"text"}]','klasse-a','alice',1)`,
		`INSERT INTO submissions VALUES ('sub_old','form_old','{"a":"x"}',NULL,NULL,2)`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	old.Close()

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("migrate legacy db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	app := newApp(Config{BaseURL: "http://x"}, db)

	f, err := app.getFormByID("form_old")
	if err != nil || f == nil || f.OwnerTeam != "klasse-a" || f.CreatedBy != "alice" || len(f.SharedWith) != 0 {
		t.Fatalf("legacy form: %+v %v", f, err)
	}
	if n, _ := app.countSubmissions("form_old"); n != 1 {
		t.Fatalf("legacy submission lost")
	}
	u, err := app.readUser("alice")
	if err != nil || u == nil || u.Email != "" {
		t.Fatalf("legacy user: %+v %v", u, err)
	}
	member := &AuthContext{User: &User{GitHubID: "bob"}, Teams: []teamMembership{{Slug: "klasse-a"}}}
	if lf, err := app.listVisibleForms(member); err != nil || len(lf) != 1 {
		t.Fatalf("team member must still see the legacy survey: %v %v", lf, err)
	}
	// the migrated table takes personal surveys ('' = no team) and shares
	p, err := app.createForm(createFormInput{Title: "Neu", Fields: []FieldDef{{Key: "a", Label: "A", Type: "text"}},
		SharedWith: []string{"Bob@Example.org"}}, "alice")
	if err != nil || p.OwnerTeam != "" || len(p.SharedWith) != 1 {
		t.Fatalf("personal survey on legacy db: %+v %v", p, err)
	}
	outsider := &AuthContext{User: &User{GitHubID: "bob", Email: "bob@example.org"}}
	if lf, _ := app.listVisibleForms(outsider); len(lf) != 1 || lf[0].ID != p.ID {
		t.Fatalf("share on legacy db: %v", lf)
	}
	// migrating twice is a no-op
	if err := db.migrate(); err != nil {
		t.Fatal(err)
	}
}
