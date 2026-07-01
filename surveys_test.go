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
	"testing"
	"time"
)

type mockUser struct {
	sub    string
	name   string
	groups []string
}

func mkIDToken(sub, name string, groups []string, iss string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"sub": sub, "name": name, "groups": groups, "iss": iss,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	body := base64.RawURLEncoding.EncodeToString(payload)
	return hdr + "." + body + "."
}

func newOIDCMock(t *testing.T, users ...mockUser) *httptest.Server {
	byCode := map[string]mockUser{}
	for _, u := range users {
		byCode["code-"+u.sub] = u
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		u, ok := byCode[r.PostForm.Get("code")]
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"access_token": "at", "token_type": "bearer",
			"id_token": mkIDToken(u.sub, u.name, u.groups, issuer),
		})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func newTestApp(t *testing.T, oidc *httptest.Server) *App {
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
		OIDCClientID:     "surveys",
		OIDCClientSecret: "secret",
		GroupPrefix:      "acme:",
		SessionSecret:    "test-secret",
	}
	return newApp(cfg, db)
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
	if meta["token_endpoint"] == nil || meta["registration_endpoint"] == nil {
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

	user, sid, err := app.loginViaOIDC("code-alice", "test-agent")
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

	regBody, _ := json.Marshal(map[string]any{"redirect_uris": []string{"https://claude.ai/cb"}, "client_name": "test"})
	rr, err := client.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(string(regBody)))
	if err != nil {
		t.Fatal(err)
	}
	var reg map[string]any
	json.NewDecoder(rr.Body).Decode(&reg)
	clientID, _ := reg["client_id"].(string)
	if clientID == "" {
		t.Fatalf("no client_id from register: %v", reg)
	}

	verifier := "verifier-abc-123-verifier-abc-123-xxxxxx"
	au, _ := url.Parse(ts.URL + "/oauth/authorize")
	q := au.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", "https://claude.ai/cb")
	q.Set("response_type", "code")
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
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
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

	_, sid, err := app.loginViaOIDC("code-alice", "agent")
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

	_, aliceSid, _ := app.loginViaOIDC("code-alice", "agent")
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

	_, bobSid, _ := app.loginViaOIDC("code-bob", "agent")
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

	_, sid, _ := app.loginViaOIDC("code-alice", "agent")
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

	_, aliceSid, _ := app.loginViaOIDC("code-alice", "agent")
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

	http.PostForm(ts.URL+"/f/"+slug, url.Values{"name": {"Max Mustermann"}, "ok": {"on"}, "t": {"0"}})

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	anon, _ := http.NewRequest("GET", ts.URL+"/surveys/"+slug, nil)
	ares, _ := noRedirect.Do(anon)
	if ares.StatusCode != 302 {
		t.Fatalf("anon want 302 redirect to login, got %d", ares.StatusCode)
	}

	member, _ := http.NewRequest("GET", ts.URL+"/surveys/"+slug, nil)
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

	csv, _ := http.NewRequest("GET", ts.URL+"/surveys/"+slug+"/export.csv", nil)
	csv.AddCookie(&http.Cookie{Name: sessionCookie, Value: aliceSid})
	cres, _ := http.DefaultClient.Do(csv)
	cbody, _ := io.ReadAll(cres.Body)
	if cres.StatusCode != 200 || !strings.Contains(string(cbody), "Max Mustermann") {
		t.Fatalf("csv export failed: status %d", cres.StatusCode)
	}

	_, bobSid, _ := app.loginViaOIDC("code-bob", "agent")
	nonMember, _ := http.NewRequest("GET", ts.URL+"/surveys/"+slug, nil)
	nonMember.AddCookie(&http.Cookie{Name: sessionCookie, Value: bobSid})
	nres, _ := http.DefaultClient.Do(nonMember)
	if nres.StatusCode != 404 {
		t.Fatalf("non-member want 404, got %d", nres.StatusCode)
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
