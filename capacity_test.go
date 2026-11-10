package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// capacityForm creates a registration form with a „personen“ number field.
func capacityForm(t *testing.T, app *App, capacity, tolerance int, field string) *Form {
	t.Helper()
	f, err := app.createForm(createFormInput{
		Title: "Betriebsbesichtigung",
		Fields: []FieldDef{
			{Key: "name", Label: "Name", Type: "text", Required: true},
			{Key: "personen", Label: "Personen", Type: "number"},
		},
		Capacity: capacity, CapacityTolerance: tolerance, CapacityField: field,
	}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func register(t *testing.T, app *App, f *Form, persons string) error {
	t.Helper()
	_, err := app.insertSubmission(f, map[string]string{"name": "X", "personen": persons}, "ua", "ip")
	if err != nil && err != errCapacity {
		t.Fatal(err)
	}
	return err
}

func wantTaken(t *testing.T, app *App, f *Form, want int) {
	t.Helper()
	if got, err := app.placesTaken(f); err != nil || got != want {
		t.Fatalf("places taken = %d (%v), want %d", got, err, want)
	}
}

func TestCapacityCountingRule(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))

	// 20 places, tolerance 2: at 18 taken, 4 more fit (22).
	f := capacityForm(t, app, 20, 2, "personen")
	if err := register(t, app, f, "18"); err != nil {
		t.Fatalf("18 of 20: %v", err)
	}
	if err := register(t, app, f, "5"); err != errCapacity {
		t.Fatalf("18+5 > 22 must be rejected, got %v", err)
	}
	if err := register(t, app, f, "4"); err != nil {
		t.Fatalf("18+4 = 22 must be accepted: %v", err)
	}
	wantTaken(t, app, f, 22)
	if err := register(t, app, f, "1"); err != errCapacity {
		t.Fatalf("over capacity: %v", err)
	}

	// At 20 taken nothing fits any more, not even 1.
	f = capacityForm(t, app, 20, 2, "personen")
	register(t, app, f, "20")
	if err := register(t, app, f, "1"); err != errCapacity {
		t.Fatalf("20+1 must be rejected, got %v", err)
	}
	wantTaken(t, app, f, 20)

	// At 19 at most 3 more.
	f = capacityForm(t, app, 20, 2, "personen")
	register(t, app, f, "19")
	if err := register(t, app, f, "4"); err != errCapacity {
		t.Fatalf("19+4 must be rejected, got %v", err)
	}
	if err := register(t, app, f, "3"); err != nil {
		t.Fatalf("19+3 must be accepted: %v", err)
	}
	wantTaken(t, app, f, 22)

	// Without tolerance the capacity is exact.
	f = capacityForm(t, app, 20, 0, "personen")
	register(t, app, f, "18")
	if err := register(t, app, f, "3"); err != errCapacity {
		t.Fatalf("18+3 without tolerance must be rejected, got %v", err)
	}
	if err := register(t, app, f, "2"); err != nil {
		t.Fatal(err)
	}
	wantTaken(t, app, f, 20)

	// An empty or missing persons value counts as 1.
	f = capacityForm(t, app, 20, 0, "personen")
	register(t, app, f, "")
	app.insertSubmission(f, map[string]string{"name": "Y"}, "ua", "ip")
	wantTaken(t, app, f, 2)
}

func TestCapacityDefaultsToOnePerSubmission(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	f := capacityForm(t, app, 2, 0, "")
	// without capacity_field the persons value is ignored
	if err := register(t, app, f, "5"); err != nil {
		t.Fatal(err)
	}
	if err := register(t, app, f, "5"); err != nil {
		t.Fatal(err)
	}
	if err := register(t, app, f, "1"); err != errCapacity {
		t.Fatalf("third submission must be rejected, got %v", err)
	}
	wantTaken(t, app, f, 2)

	// no capacity: no limit, places_taken still counts
	free := capacityForm(t, app, 0, 0, "")
	for i := 0; i < 5; i++ {
		if err := register(t, app, free, "1"); err != nil {
			t.Fatal(err)
		}
	}
	wantTaken(t, app, free, 5)
}

func TestCapacityParallelSubmissionsDoNotOverbook(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	f := capacityForm(t, app, 20, 2, "personen")
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			app.insertSubmission(f, map[string]string{"name": "X", "personen": "3"}, "ua", "ip")
		}()
	}
	wg.Wait()
	// 3 per submission: 7 fit (21 <= 22), the 8th would make 24.
	wantTaken(t, app, f, 21)
}

func TestCapacityMCPSettingsAndValidation(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", groups: []string{"acme:marketing"}})
	app := newTestApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	tok := fullOAuthToken(t, ts, sid)

	fields := []map[string]any{
		{"key": "name", "label": "Name", "type": "text", "required": true},
		{"key": "personen", "label": "Personen", "type": "number", "required": true},
		{"key": "firma", "label": "Firma", "type": "text"},
	}
	create := func(extra map[string]any) map[string]any {
		args := map[string]any{"title": "Besichtigung", "fields": fields}
		for k, v := range extra {
			args[k] = v
		}
		return mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "create_form", "arguments": args})
	}
	for name, bad := range map[string]map[string]any{
		"unknown field":      {"capacity": 20, "capacity_field": "anzahl"},
		"not a number field": {"capacity": 20, "capacity_field": "firma"},
		"negative capacity":  {"capacity": -1},
		"negative tolerance": {"capacity": 20, "capacity_tolerance": -2},
	} {
		if res := create(bad); !isToolErr(res) {
			t.Fatalf("%s: expected error, got %v", name, res)
		}
	}

	created := callJSON(t, ts, tok, "create_form", map[string]any{
		"title": "Besichtigung", "fields": fields,
		"capacity": 20, "capacity_tolerance": 2, "capacity_field": "personen",
	})
	if created["capacity"] != float64(20) || created["capacity_tolerance"] != float64(2) ||
		created["capacity_field"] != "personen" || created["places_taken"] != float64(0) {
		t.Fatalf("create_form capacity: %v", created)
	}
	id := created["id"].(string)
	form, _ := app.getFormByID(id)
	register(t, app, form, "3")

	got := callJSON(t, ts, tok, "get_form", map[string]any{"id": id})
	if got["capacity"] != float64(20) || got["capacity_tolerance"] != float64(2) ||
		got["capacity_field"] != "personen" || got["places_taken"] != float64(3) {
		t.Fatalf("get_form capacity: %v", got)
	}
	lf := listedForms(t, ts, tok)
	if len(lf) != 1 || lf[0]["capacity"] != float64(20) || lf[0]["places_taken"] != float64(3) ||
		lf[0]["capacity_field"] != "personen" || lf[0]["capacity_tolerance"] != float64(2) {
		t.Fatalf("list_forms capacity: %v", lf)
	}

	// Removing the capacity field from fields without clearing it fails.
	res := mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{
		"id": id, "fields": []map[string]any{{"key": "name", "label": "Name", "type": "text"}},
	}})
	if !isToolErr(res) || !strings.Contains(toolResultText(t, res), "capacity_field") {
		t.Fatalf("update_form must refuse dropping the capacity field: %v", res)
	}
	res = mcpCall(t, ts, tok, "tools/call", map[string]any{"name": "update_form", "arguments": map[string]any{
		"id": id, "capacity_field": "firma",
	}})
	if !isToolErr(res) {
		t.Fatalf("update_form must refuse a text capacity_field: %v", res)
	}

	upd := callJSON(t, ts, tok, "update_form", map[string]any{"id": id, "capacity": 30, "capacity_field": ""})
	if upd["capacity"] != float64(30) || upd["capacity_field"] != "" || upd["capacity_tolerance"] != float64(2) || upd["places_taken"] != float64(1) {
		t.Fatalf("update_form capacity: %v", upd)
	}
	upd = callJSON(t, ts, tok, "update_form", map[string]any{"id": id, "capacity": 0})
	if upd["capacity"] != float64(0) {
		t.Fatalf("capacity 0 must switch the limit off: %v", upd)
	}
}

func postForm(t *testing.T, ts *httptest.Server, slug, ip string, v url.Values) (int, string) {
	t.Helper()
	v.Set("t", "0")
	req, _ := http.NewRequest("POST", ts.URL+"/f/"+slug, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", ip)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func getForm(t *testing.T, ts *httptest.Server, slug string) (int, string) {
	t.Helper()
	res := mustGet(t, ts.URL+"/f/"+slug)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestCapacityPublicFormHintAndSoldOut(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	f := capacityForm(t, app, 20, 2, "personen")
	register(t, app, f, "18")

	status, body := getForm(t, ts, f.Slug)
	if status != 200 {
		t.Fatalf("GET: %d", status)
	}
	for _, want := range []string{"18 von 20 Plätzen belegt – noch 2 Plätze frei.", `id="surveyform"`, `min="1"`, `step="1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("form page missing %q", want)
		}
	}

	// not a whole number >= 1
	status, body = postForm(t, ts, f.Slug, "10.0.0.1", url.Values{"name": {"A"}, "personen": {"0"}})
	if status != 400 || !strings.Contains(body, "Personen muss eine ganze Zahl ab 1 sein.") {
		t.Fatalf("personen 0: %d", status)
	}
	// too many persons: field error with the real maximum (tolerance incl.)
	status, body = postForm(t, ts, f.Slug, "10.0.0.2", url.Values{"name": {"A"}, "personen": {"5"}})
	if status != 409 || !strings.Contains(body, "Es sind nur noch 4 Plätze frei.") || !strings.Contains(body, "input-error") {
		t.Fatalf("too many: %d %s", status, body)
	}
	wantTaken(t, app, f, 18)
	status, body = postForm(t, ts, f.Slug, "10.0.0.3", url.Values{"name": {"A"}, "personen": {"4"}})
	if status != 200 || !strings.Contains(body, "Vielen Dank") {
		t.Fatalf("18+4 via web: %d", status)
	}

	// sold out: friendly page without the form, not an error status
	status, body = getForm(t, ts, f.Slug)
	if status != 200 || !strings.Contains(body, "Ausgebucht – alle 20 Plätze sind belegt.") {
		t.Fatalf("sold out GET: %d", status)
	}
	if strings.Contains(body, `id="surveyform"`) || strings.Contains(body, "Absenden") {
		t.Fatalf("sold out page must not render the form")
	}
	status, body = postForm(t, ts, f.Slug, "10.0.0.4", url.Values{"name": {"B"}, "personen": {"1"}})
	if status != 409 || !strings.Contains(body, "Ausgebucht") {
		t.Fatalf("sold out POST: %d", status)
	}
	wantTaken(t, app, f, 22)
}

func TestCapacityPublicFormWithoutCountField(t *testing.T) {
	app := newTestApp(t, newOIDCMock(t))
	ts := httptest.NewServer(app.routes())
	defer ts.Close()

	f := capacityForm(t, app, 2, 0, "")
	_, body := getForm(t, ts, f.Slug)
	if !strings.Contains(body, "0 von 2 Plätzen belegt – noch 2 Plätze frei.") || strings.Contains(body, `step="1"`) {
		t.Fatalf("hint without count field missing")
	}
	for i := 1; i <= 2; i++ {
		if status, _ := postForm(t, ts, f.Slug, fmt.Sprintf("10.0.1.%d", i), url.Values{"name": {"A"}, "personen": {"7"}}); status != 200 {
			t.Fatalf("submission %d: %d", i, status)
		}
		if i == 1 {
			if _, body := getForm(t, ts, f.Slug); !strings.Contains(body, "1 von 2 Plätzen belegt – noch 1 Platz frei.") {
				t.Fatalf("singular hint missing")
			}
		}
	}
	if status, body := postForm(t, ts, f.Slug, "10.0.1.9", url.Values{"name": {"A"}}); status != 409 || !strings.Contains(body, "Ausgebucht – alle 2 Plätze sind belegt.") {
		t.Fatalf("third submission: %d", status)
	}

	// without capacity there is no hint at all
	free := capacityForm(t, app, 0, 0, "")
	if _, body := getForm(t, ts, free.Slug); strings.Contains(body, "Plätzen belegt") || strings.Contains(body, "Ausgebucht") {
		t.Fatalf("no hint without capacity")
	}
}

func TestCapacityMigrationAddsColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// forms as before the Teilnehmerbegrenzung
	if _, err := raw.Exec(`CREATE TABLE forms (
	  id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, ref TEXT, title TEXT NOT NULL, description TEXT,
	  fields TEXT NOT NULL DEFAULT '[]', owner_team TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'active',
	  allow_multiple INTEGER NOT NULL DEFAULT 1, expires_at INTEGER, created_by TEXT, created_at INTEGER NOT NULL, delete_at INTEGER);
	  INSERT INTO forms(id, slug, ref, title, created_at) VALUES ('form_old','oldslug','alt','Alt',1);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f, err := scanForm(db.QueryRow(`SELECT ` + formCols + ` FROM forms WHERE id = 'form_old'`))
	if err != nil {
		t.Fatal(err)
	}
	if f.Capacity != 0 || f.CapacityTolerance != 0 || f.CapacityField != "" {
		t.Fatalf("old survey must have no limit: %+v", f)
	}
}
