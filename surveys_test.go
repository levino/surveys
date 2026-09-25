package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestApp(t *testing.T, oidc *oidcMock) *App {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	cfg := Config{
		BaseURL:          "http://localhost:8080",
		AppName:          "Test",
		OIDCIssuer:       oidc.URL,
		OIDCClientID:     mockClientID,
		OIDCClientSecret: "secret",
		GroupPrefix:      "acme:",
		MaintainerSuffix: ":admin",
		Scopes:           "openid profile email offline_access groups",
		RefreshInterval:  10 * time.Minute,
		SessionSecret:    "test-secret",
	}
	app := newApp(cfg, db)
	app.cimdAllowLocal = true
	return app
}

// cimdDoc serves a Client ID Metadata Document and returns its URL (= the
// client_id). redirects default to a same-origin callback on the doc host.
type cimdDoc struct {
	srv       *httptest.Server
	url       string
	mu        sync.Mutex
	redirects []string
	selfID    string // what the document claims as client_id
	down      bool
	hits      int
}

func newCIMDDoc(t *testing.T, name string) *cimdDoc {
	t.Helper()
	d := &cimdDoc{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth/client.json", func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.hits++
		if d.down {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Cache-Control", "max-age=3600")
		writeJSON(w, 200, map[string]any{
			"client_id": d.selfID, "client_name": name, "redirect_uris": d.redirects,
			"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
		})
	})
	d.srv = httptest.NewServer(mux)
	t.Cleanup(d.srv.Close)
	d.url = d.srv.URL + "/oauth/client.json"
	d.selfID = d.url
	d.redirects = []string{d.srv.URL + "/cb"}
	return d
}

func newTestAppRetention(t *testing.T, oidc *oidcMock, days int) *App {
	app := newTestApp(t, oidc)
	app.cfg.RetentionDays = days
	return app
}

func b64Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestDiscoveryEndpoints(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	json.NewDecoder(res.Body).Decode(&meta)
	if meta["token_endpoint"] == nil || meta["registration_endpoint"] != nil ||
		meta["client_id_metadata_document_supported"] != true {
		t.Fatalf("missing AS metadata: %v", meta)
	}

	res2, _ := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	var pr map[string]any
	json.NewDecoder(res2.Body).Decode(&pr)
	if pr["resource"] != "http://localhost:8080/mcp" {
		t.Fatalf("unexpected resource: %v", pr["resource"])
	}
}

func TestOIDCLoginStoresTeams(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)

	user, sid, err := oidc.login(t, app, "alice")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if user.GitHubUsername != "Alice" {
		t.Fatalf("want Alice, got %s", user.GitHubUsername)
	}
	ctx, err := app.resolveSession(sid)
	if err != nil || ctx == nil {
		t.Fatalf("resolveSession: %v ctx=%v", err, ctx)
	}
	if !ctx.isMember("marketing") {
		t.Fatalf("alice should be member of marketing, teams=%v", ctx.teamSlugs())
	}
}

func TestMcpRequiresAuth(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	res, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 401 {
		t.Fatalf("want 401, got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("missing WWW-Authenticate challenge: %q", res.Header.Get("WWW-Authenticate"))
	}
}

func fullOAuthToken(t *testing.T, ts *httptest.Server, sid string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	doc := newCIMDDoc(t, "test")
	clientID, redirect := doc.url, doc.redirects[0]

	verifier := "verifier-abc-123-verifier-abc-123-xxxxxx"
	au, _ := url.Parse(ts.URL + "/oauth/authorize")
	q := au.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("response_type", "code")
	q.Set("resource", "http://localhost:8080/mcp") // the configured BaseURL, not the test listener
	q.Set("code_challenge", b64Challenge(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", "xyz")
	au.RawQuery = q.Encode()
	req, _ := http.NewRequest("GET", au.String(), nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	ar, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	cbody, _ := io.ReadAll(ar.Body)
	if ar.StatusCode != 200 {
		t.Fatalf("expected consent page, got %d: %s", ar.StatusCode, cbody)
	}
	m := regexp.MustCompile(`name="authz_id" value="([^"]+)"`).FindStringSubmatch(string(cbody))
	if m == nil {
		t.Fatalf("consent page missing authz_id: %s", cbody)
	}
	approve := url.Values{"authz_id": {m[1]}}
	apReq, _ := http.NewRequest("POST", ts.URL+"/oauth/approve", strings.NewReader(approve.Encode()))
	apReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	apReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	apRes, err := client.Do(apReq)
	if err != nil {
		t.Fatal(err)
	}
	loc := apRes.Header.Get("Location")
	if loc == "" {
		body, _ := io.ReadAll(apRes.Body)
		t.Fatalf("approve did not redirect (status %d): %s", apRes.StatusCode, body)
	}
	lu, _ := url.Parse(loc)
	code := lu.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("code_verifier", verifier)
	form.Set("resource", "http://localhost:8080/mcp")
	tr, err := client.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	var tok IssuedTokens
	json.NewDecoder(tr.Body).Decode(&tok)
	if tok.AccessToken == "" {
		t.Fatalf("no access token; status %d", tr.StatusCode)
	}
	return tok.AccessToken
}

func mcpCall(t *testing.T, ts *httptest.Server, token, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", ts.URL+"/mcp", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return out
}

func toolResultText(t *testing.T, resp map[string]any) string {
	t.Helper()
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", result)
	}
	first, _ := content[0].(map[string]any)
	return first["text"].(string)
}

func TestMcpOAuthAndCreateForm(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	_, sid, err := oidc.login(t, app, "alice")
	if err != nil {
		t.Fatal(err)
	}
	token := fullOAuthToken(t, ts, sid)

	list := mcpCall(t, ts, token, "tools/list", nil)
	if list["result"] == nil {
		t.Fatalf("tools/list failed: %v", list)
	}

	create := mcpCall(t, ts, token, "tools/call", map[string]any{
		"name": "create_form",
		"arguments": map[string]any{
			"title":      "Kandidaten",
			"owner_team": "marketing",
			"fields": []map[string]any{
				{"key": "name", "label": "Name", "type": "text", "required": true},
				{"key": "beruf", "label": "Beruf", "type": "text", "required": true},
			},
		},
	})
	txt := toolResultText(t, create)
	var created map[string]any
	if err := json.Unmarshal([]byte(txt), &created); err != nil {
		t.Fatalf("create result not JSON: %s", txt)
	}
	if created["slug"] == nil || created["url"] == nil {
		t.Fatalf("create_form missing slug/url: %v", created)
	}

	bad := mcpCall(t, ts, token, "tools/call", map[string]any{
		"name":      "create_form",
		"arguments": map[string]any{"title": "X", "owner_team": "sales", "fields": []map[string]any{{"key": "a", "label": "A", "type": "text"}}},
	})
	res, _ := bad["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatalf("expected isError for foreign team, got %v", bad)
	}
}

func TestPublicSubmissionAndVisibility(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}},
		mockUser{sub: "bob", name: "Bob", groups: []string{"acme:sales"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	_, aliceSid, _ := oidc.login(t, app, "alice")
	aliceTok := fullOAuthToken(t, ts, aliceSid)
	create := mcpCall(t, ts, aliceTok, "tools/call", map[string]any{
		"name": "create_form",
		"arguments": map[string]any{
			"title": "Kandidaten", "owner_team": "marketing",
			"fields": []map[string]any{
				{"key": "name", "label": "Name", "type": "text", "required": true},
				{"key": "email", "label": "E-Mail", "type": "email", "required": true},
			},
		},
	})
	var created map[string]any
	json.Unmarshal([]byte(toolResultText(t, create)), &created)
	slug := created["slug"].(string)
	formID := created["id"].(string)

	gres, _ := http.Get(ts.URL + "/f/" + slug)
	gbody, _ := io.ReadAll(gres.Body)
	if gres.StatusCode != 200 || !strings.Contains(string(gbody), "Kandidaten") {
		t.Fatalf("form GET failed: status %d", gres.StatusCode)
	}
	if gres.Header.Get("X-Robots-Tag") == "" {
		t.Fatalf("missing noindex header")
	}

	bad := url.Values{"name": {"Max"}, "t": {"0"}}
	pres, _ := http.PostForm(ts.URL+"/f/"+slug, bad)
	if pres.StatusCode != 400 {
		t.Fatalf("expected 400 for missing required, got %d", pres.StatusCode)
	}

	ok := url.Values{"name": {"Max Mustermann"}, "email": {"max@example.com"}, "t": {"0"}}
	ores, _ := http.PostForm(ts.URL+"/f/"+slug, ok)
	obody, _ := io.ReadAll(ores.Body)
	if ores.StatusCode != 200 || !strings.Contains(string(obody), "Vielen Dank") {
		t.Fatalf("valid submit failed: status %d body=%s", ores.StatusCode, obody)
	}

	hp := url.Values{"name": {"Bot"}, "email": {"bot@example.com"}, "website": {"spam"}, "t": {"0"}}
	http.PostForm(ts.URL+"/f/"+slug, hp)

	sub := mcpCall(t, ts, aliceTok, "tools/call", map[string]any{
		"name": "list_submissions", "arguments": map[string]any{"form_id": formID},
	})
	var subData map[string]any
	json.Unmarshal([]byte(toolResultText(t, sub)), &subData)
	if c, _ := subData["count"].(float64); c != 1 {
		t.Fatalf("expected 1 submission, got %v", subData["count"])
	}

	_, bobSid, _ := oidc.login(t, app, "bob")
	bobTok := fullOAuthToken(t, ts, bobSid)
	bobView := mcpCall(t, ts, bobTok, "tools/call", map[string]any{
		"name": "list_submissions", "arguments": map[string]any{"form_id": formID},
	})
	bres, _ := bobView["result"].(map[string]any)
	if bres["isError"] != true {
		t.Fatalf("bob must not read alice's submissions, got %v", bobView)
	}

	bobForms := mcpCall(t, ts, bobTok, "tools/call", map[string]any{"name": "list_forms", "arguments": map[string]any{}})
	var bf map[string]any
	json.Unmarshal([]byte(toolResultText(t, bobForms)), &bf)
	if forms, _ := bf["forms"].([]any); len(forms) != 0 {
		t.Fatalf("bob should see no forms, got %v", forms)
	}
}

func TestFormRendersMarkdownHelpAndInlineErrors(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	_, sid, _ := oidc.login(t, app, "alice")
	tok := fullOAuthToken(t, ts, sid)
	create := mcpCall(t, ts, tok, "tools/call", map[string]any{
		"name": "create_form",
		"arguments": map[string]any{
			"title": "Steckbrief", "owner_team": "marketing",
			"description": "Bitte **vollständig** ausfüllen.",
			"fields": []map[string]any{
				{"key": "name", "label": "Name", "type": "text", "required": true, "help": "So wie auf dem *Stimmzettel*."},
			},
		},
	})
	var created map[string]any
	json.Unmarshal([]byte(toolResultText(t, create)), &created)
	slug := created["slug"].(string)

	gbody, _ := io.ReadAll(mustGet(t, ts.URL+"/f/"+slug).Body)
	body := string(gbody)
	for _, want := range []string{"<strong>vollständig</strong>", "<em>Stimmzettel</em>", `data-error-for="name"`, "getElementById('surveyform')"} {
		if !strings.Contains(body, want) {
			t.Fatalf("form GET missing %q", want)
		}
	}

	pres, _ := http.PostForm(ts.URL+"/f/"+slug, url.Values{"name": {""}, "t": {"0"}})
	if pres.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", pres.StatusCode)
	}
	pbody, _ := io.ReadAll(pres.Body)
	for _, want := range []string{"Name ist erforderlich.", "input-error"} {
		if !strings.Contains(string(pbody), want) {
			t.Fatalf("invalid POST re-render missing %q", want)
		}
	}
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestSubmissionsWebPage(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}},
		mockUser{sub: "bob", name: "Bob", groups: []string{"acme:sales"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	_, aliceSid, _ := oidc.login(t, app, "alice")
	aliceTok := fullOAuthToken(t, ts, aliceSid)
	create := mcpCall(t, ts, aliceTok, "tools/call", map[string]any{
		"name": "create_form",
		"arguments": map[string]any{
			"title": "Kandidaten", "owner_team": "marketing",
			"fields": []map[string]any{
				{"key": "name", "label": "Name", "type": "text", "required": true},
				{"key": "ok", "label": "Einverstanden", "type": "checkbox"},
			},
		},
	})
	var created map[string]any
	json.Unmarshal([]byte(toolResultText(t, create)), &created)
	slug := created["slug"].(string)
	ref := created["ref"].(string)
	if ref != "kandidaten" {
		t.Fatalf("want readable ref %q, got %q", "kandidaten", ref)
	}

	http.PostForm(ts.URL+"/f/"+slug, url.Values{"name": {"Max Mustermann"}, "ok": {"on"}, "t": {"0"}})

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	anon, _ := http.NewRequest("GET", ts.URL+"/surveys/"+ref, nil)
	ares, _ := noRedirect.Do(anon)
	if ares.StatusCode != 302 {
		t.Fatalf("anon want 302 redirect to login, got %d", ares.StatusCode)
	}

	member, _ := http.NewRequest("GET", ts.URL+"/surveys/"+ref, nil)
	member.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceSid})
	mres, _ := http.DefaultClient.Do(member)
	mbody, _ := io.ReadAll(mres.Body)
	if mres.StatusCode != 200 {
		t.Fatalf("member want 200, got %d", mres.StatusCode)
	}
	for _, want := range []string{"Max Mustermann", "Ja", "Kandidaten"} {
		if !strings.Contains(string(mbody), want) {
			t.Fatalf("submissions page missing %q", want)
		}
	}

	csv, _ := http.NewRequest("GET", ts.URL+"/surveys/"+ref+"/export.csv", nil)
	csv.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceSid})
	cres, _ := http.DefaultClient.Do(csv)
	cbody, _ := io.ReadAll(cres.Body)
	if cres.StatusCode != 200 || !strings.Contains(string(cbody), "Max Mustermann") {
		t.Fatalf("csv export failed: status %d", cres.StatusCode)
	}

	_, bobSid, _ := oidc.login(t, app, "bob")
	nonMember, _ := http.NewRequest("GET", ts.URL+"/surveys/"+ref, nil)
	nonMember.AddCookie(&http.Cookie{Name: sessionCookie, Value: bobSid})
	nres, _ := http.DefaultClient.Do(nonMember)
	if nres.StatusCode != 404 {
		t.Fatalf("non-member want 404, got %d", nres.StatusCode)
	}
}

func TestMigrateBackfillsRefWithSlugify(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(
		`INSERT INTO forms(id, slug, ref, title, fields, owner_team, status, allow_multiple, created_at)
		 VALUES ('form_x','slugx',NULL,'Bäume für Rössing – Aktion 2026','[]','t','active',1,1)`,
	); err != nil {
		t.Fatal(err)
	}
	if err := db.migrate(); err != nil {
		t.Fatal(err)
	}
	var ref string
	if err := db.QueryRow(`SELECT ref FROM forms WHERE id='form_x'`).Scan(&ref); err != nil {
		t.Fatal(err)
	}
	if ref != "baeume-fuer-roessing-aktion-2026" {
		t.Fatalf("unexpected backfilled ref %q", ref)
	}
}

func TestExportCSV(t *testing.T) {
	form := &Form{Fields: []FieldDef{{Key: "name", Label: "Name", Type: "text"}, {Key: "ort", Label: "Ort", Type: "text"}}}
	subs := []*Submission{
		{ID: "s1", Values: map[string]string{"name": "Max", "ort": "Springfield"}, CreatedAt: 1000},
	}
	csv := exportCSV(form, subs)
	if !strings.Contains(csv, "id,created_at,name,ort") || !strings.Contains(csv, "Max,Springfield") {
		t.Fatalf("unexpected CSV:\n%s", csv)
	}
}

func TestPKCERejectsBadVerifier(t *testing.T) {
	if verifyPKCE(b64Challenge("right"), "S256", "wrong") {
		t.Fatal("PKCE accepted wrong verifier")
	}
	if !verifyPKCE(b64Challenge("right"), "S256", "right") {
		t.Fatal("PKCE rejected correct verifier")
	}
}

// Creator = admin, team members read, maintainers (":admin" suffix) manage,
// other teams see nothing — and no one is a global admin.
func TestCreatorAdminAndTeamRead(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", groups: []string{"acme:klasse-a"}},
		mockUser{sub: "carol", name: "Carol", groups: []string{"acme:klasse-a"}},
		mockUser{sub: "dave", name: "Dave", groups: []string{"acme:klasse-a", "acme:klasse-a:admin"}},
		mockUser{sub: "erin", name: "Erin", groups: []string{"acme:klasse-b", "acme:klasse-b:admin"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	tok := func(sub string) string {
		_, sid, err := oidc.login(t, app, sub)
		if err != nil {
			t.Fatalf("login %s: %v", sub, err)
		}
		return fullOAuthToken(t, ts, sid)
	}
	alice, carol, dave, erin := tok("alice"), tok("carol"), tok("dave"), tok("erin")

	teams := mcpCall(t, ts, dave, "tools/call", map[string]any{"name": "list_teams", "arguments": map[string]any{}})
	if txt := toolResultText(t, teams); !strings.Contains(txt, `"is_maintainer": true`) || !strings.Contains(txt, `"slug": "klasse-a"`) {
		t.Fatalf("dave should be maintainer of klasse-a, got %s", txt)
	}

	create := mcpCall(t, ts, alice, "tools/call", map[string]any{
		"name": "create_form",
		"arguments": map[string]any{"title": "Ausflug", "owner_team": "klasse-a",
			"fields": []map[string]any{{"key": "name", "label": "Name", "type": "text", "required": true}}},
	})
	var created map[string]any
	json.Unmarshal([]byte(toolResultText(t, create)), &created)
	formID := created["id"].(string)
	if created["can_manage"] != true || created["created_by"] != "alice" {
		t.Fatalf("creator must manage: %v", created)
	}

	isErr := func(res map[string]any) bool { r, _ := res["result"].(map[string]any); return r["isError"] == true }

	// carol: same class -> sees it, reads results, cannot change or delete
	lf := mcpCall(t, ts, carol, "tools/call", map[string]any{"name": "list_forms", "arguments": map[string]any{}})
	var lst map[string]any
	json.Unmarshal([]byte(toolResultText(t, lf)), &lst)
	forms, _ := lst["forms"].([]any)
	if len(forms) != 1 || forms[0].(map[string]any)["can_manage"] != false {
		t.Fatalf("carol should see 1 form without manage rights, got %v", lst)
	}
	if isErr(mcpCall(t, ts, carol, "tools/call", map[string]any{"name": "list_submissions", "arguments": map[string]any{"form_id": formID}})) {
		t.Fatalf("carol must be able to read results")
	}
	if !isErr(mcpCall(t, ts, carol, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{"id": formID, "title": "x"}})) {
		t.Fatalf("carol must not update")
	}
	if !isErr(mcpCall(t, ts, carol, "tools/call", map[string]any{"name": "delete_form", "arguments": map[string]any{"id": formID}})) {
		t.Fatalf("carol must not delete")
	}
	// dave: maintainer of klasse-a -> may change
	if isErr(mcpCall(t, ts, dave, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{"id": formID, "title": "Ausflug 2"}})) {
		t.Fatalf("maintainer must be able to update")
	}
	// erin: maintainer, but of another class -> nothing at all
	le := mcpCall(t, ts, erin, "tools/call", map[string]any{"name": "list_forms", "arguments": map[string]any{}})
	var el map[string]any
	json.Unmarshal([]byte(toolResultText(t, le)), &el)
	if ef, _ := el["forms"].([]any); len(ef) != 0 {
		t.Fatalf("erin must not see klasse-a surveys, got %v", el)
	}
	if !isErr(mcpCall(t, ts, erin, "tools/call", map[string]any{"name": "get_form", "arguments": map[string]any{"id": formID}})) {
		t.Fatalf("erin must not read klasse-a survey")
	}
	// alice deletes her own
	if isErr(mcpCall(t, ts, alice, "tools/call", map[string]any{"name": "delete_form", "arguments": map[string]any{"id": formID}})) {
		t.Fatalf("creator must be able to delete")
	}
}

// delete_at: explicit dates, the instance default, and the purge.
func TestRetentionAndPurge(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:klasse-a"}})
	app := newTestAppRetention(t, oidc, 30)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	tok := fullOAuthToken(t, ts, sid)
	fields := []map[string]any{{"key": "name", "label": "Name", "type": "text"}}

	// default retention applies
	c1 := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "create_form",
		"arguments": map[string]any{"title": "Default", "owner_team": "klasse-a", "fields": fields}})
	var f1 map[string]any
	json.Unmarshal([]byte(toolResultText(t, c1)), &f1)
	del1, _ := time.Parse(time.RFC3339, f1["delete_at"].(string))
	if d := time.Until(del1); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("default delete_at should be ~30d out, got %v", f1["delete_at"])
	}
	// clearing is refused while a default retention exists
	if r, _ := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "update_form",
		"arguments": map[string]any{"id": f1["id"], "delete_at": ""}})["result"].(map[string]any); r["isError"] != true {
		t.Fatalf("clearing delete_at must be refused under default retention")
	}
	// explicit past date: hidden immediately, purged by the sweeper, form + submissions gone
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	c2 := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "create_form",
		"arguments": map[string]any{"title": "Alt", "owner_team": "klasse-a", "fields": fields, "delete_at": past}})
	var f2 map[string]any
	json.Unmarshal([]byte(toolResultText(t, c2)), &f2)
	if res, _ := http.Get(ts.URL + "/f/" + f2["slug"].(string)); res.StatusCode != 404 {
		t.Fatalf("due survey must be gone from the public URL, got %d", res.StatusCode)
	}
	lf := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "list_forms", "arguments": map[string]any{}})
	if strings.Contains(toolResultText(t, lf), `"Alt"`) {
		t.Fatalf("due survey must not be listed")
	}
	n, err := app.purgeDueForms()
	if err != nil || n != 1 {
		t.Fatalf("purge: n=%d err=%v", n, err)
	}
	var left int
	app.db.QueryRow(`SELECT COUNT(*) FROM forms`).Scan(&left)
	if left != 1 {
		t.Fatalf("expected 1 form left, got %d", left)
	}
}

// What Claude needs to pick CIMD on its own, and the RFC 9728 chain from 401.
func TestDiscoveryForCIMDClients(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	res, _ := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	wa := res.Header.Get("WWW-Authenticate")
	if res.StatusCode != 401 || !strings.Contains(wa, `resource_metadata="`+"http://localhost:8080"+`/.well-known/oauth-protected-resource/mcp"`) || !strings.Contains(wa, `scope="mcp"`) || !strings.Contains(wa, `error="invalid_token"`) {
		t.Fatalf("401 challenge wrong: %d %q", res.StatusCode, wa)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		r, _ := http.Get(ts.URL + p)
		var prm map[string]any
		json.NewDecoder(r.Body).Decode(&prm)
		if r.StatusCode != 200 || prm["resource"] != "http://localhost:8080/mcp" || prm["authorization_servers"].([]any)[0] != "http://localhost:8080" {
			t.Fatalf("%s: %d %v", p, r.StatusCode, prm)
		}
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		r, _ := http.Get(ts.URL + p)
		var m map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		methods, _ := m["token_endpoint_auth_methods_supported"].([]any)
		if m["client_id_metadata_document_supported"] != true || len(methods) != 1 || methods[0] != "none" ||
			m["code_challenge_methods_supported"].([]any)[0] != "S256" || m["registration_endpoint"] != nil {
			t.Fatalf("%s: not CIMD-ready: %v", p, m)
		}
	}
}

// Client ID Metadata Documents: validation, loopback ports, resource, outages.
func TestCIMDClientRules(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")

	authorize := func(clientID, redirect, resource string) *http.Response {
		au, _ := url.Parse(ts.URL + "/oauth/authorize")
		q := au.Query()
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirect)
		q.Set("response_type", "code")
		q.Set("code_challenge", b64Challenge("verifier-abc-123-verifier-abc-123-xxxxxx"))
		q.Set("code_challenge_method", "S256")
		if resource != "" {
			q.Set("resource", resource)
		}
		au.RawQuery = q.Encode()
		req, _ := http.NewRequest("GET", au.String(), nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
		res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	body := func(r *http.Response) string { b, _ := io.ReadAll(r.Body); return string(b) }

	// not a URL -> unknown client
	if r := authorize("cli_123", "https://x/cb", ""); r.StatusCode != 400 || !strings.Contains(body(r), "invalid_client") {
		t.Fatalf("opaque client_id must be rejected, got %d", r.StatusCode)
	}
	// document must be self-referential
	bad := newCIMDDoc(t, "Evil")
	bad.selfID = "https://someone-else.example/client.json"
	if r := authorize(bad.url, bad.redirects[0], ""); r.StatusCode != 400 {
		t.Fatalf("client_id mismatch must be rejected, got %d %s", r.StatusCode, body(r))
	}
	// redirect must be in the document
	good := newCIMDDoc(t, "Claude")
	if r := authorize(good.url, good.srv.URL+"/other", ""); r.StatusCode != 400 || !strings.Contains(body(r), "invalid_redirect_uri") {
		t.Fatalf("unregistered redirect must be rejected, got %d", r.StatusCode)
	}
	// consent shows the client_id host, not just the self-asserted name
	r := authorize(good.url, good.redirects[0], "")
	if b := body(r); r.StatusCode != 200 || !strings.Contains(b, good.srv.Listener.Addr().String()) || !strings.Contains(b, "Claude") {
		t.Fatalf("consent must show the client host: %d %s", r.StatusCode, b[:min(len(b), 300)])
	}
	// wrong resource indicator
	if r := authorize(good.url, good.redirects[0], "https://other.example/mcp"); r.StatusCode != 400 || !strings.Contains(body(r), "invalid_target") {
		t.Fatalf("foreign resource must be rejected, got %d", r.StatusCode)
	}
	// loopback redirects: port ignored (Claude Code), non-loopback foreign origin refused in the doc
	native := newCIMDDoc(t, "Claude Code")
	native.redirects = []string{"http://localhost/callback", "http://127.0.0.1/callback"}
	if r := authorize(native.url, "http://localhost:3118/callback", ""); r.StatusCode != 200 || !strings.Contains(body(r), "eigenen Rechner") {
		t.Fatalf("loopback with ephemeral port must be accepted with a warning, got %d", r.StatusCode)
	}
	if r := authorize(native.url, "http://localhost:3118/elsewhere", ""); r.StatusCode != 400 {
		t.Fatalf("loopback with other path must be rejected, got %d", r.StatusCode)
	}
	foreign := newCIMDDoc(t, "Phish")
	foreign.redirects = []string{"https://attacker.example/cb"}
	if r := authorize(foreign.url, "https://attacker.example/cb", ""); r.StatusCode != 400 {
		t.Fatalf("cross-origin redirect in the document must be rejected, got %d", r.StatusCode)
	}
	// outage after a successful fetch: the persisted copy keeps the client working
	before := good.hits
	good.mu.Lock()
	good.down = true
	good.mu.Unlock()
	app.cimd.entries = map[string]cimdEntry{}
	if r := authorize(good.url, good.redirects[0], ""); r.StatusCode != 200 {
		t.Fatalf("stale copy must be used during an outage, got %d %s", r.StatusCode, body(r))
	}
	if good.hits != before+1 {
		t.Fatalf("expected one failed refetch, got %d", good.hits-before)
	}
	// error responses are never cached: back up -> served again
	good.mu.Lock()
	good.down = false
	good.mu.Unlock()
	app.cimd.entries = map[string]cimdEntry{}
	if r := authorize(good.url, good.redirects[0], ""); r.StatusCode != 200 {
		t.Fatalf("after recovery: %d", r.StatusCode)
	}
}
