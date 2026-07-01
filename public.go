package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/levino/surveys/ui"
)

func (a *App) mountPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.db.Ping(); err != nil {
			http.Error(w, "db down", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})

	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /docs", a.handleDocs)
	mux.HandleFunc("GET /surveys/{id}", a.handleSubmissions)
	mux.HandleFunc("GET /surveys/{id}/export.csv", a.handleSubmissionsCSV)
	mux.HandleFunc("POST /revoke", a.handleRevoke)
	mux.HandleFunc("GET /f/{slug}", a.handleFormGet)
	mux.HandleFunc("POST /f/{slug}", a.handleFormPost)
}

func (a *App) handleDocs(w http.ResponseWriter, r *http.Request) {
	a.renderPage(w, r, http.StatusOK, ui.Docs(a.cfg.AppName, a.cfg.BaseURL+"/mcp"))
}

func (a *App) formForWeb(w http.ResponseWriter, r *http.Request) (*AuthContext, *Form, bool) {
	ctx, _ := a.resolveSession(cookieValue(r, sessionCookie))
	if ctx == nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.Path), http.StatusFound)
		return nil, nil, false
	}
	form, err := a.getFormByID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "error", 500)
		return nil, nil, false
	}
	if form == nil || !ctx.isMember(form.OwnerTeam) {
		a.notice(w, r, 404, "Nicht gefunden", "Diese Umfrage existiert nicht oder du hast keinen Zugriff darauf.")
		return nil, nil, false
	}
	return ctx, form, true
}

func (a *App) handleSubmissions(w http.ResponseWriter, r *http.Request) {
	ctx, form, ok := a.formForWeb(w, r)
	if !ok {
		return
	}
	subs, err := a.listSubmissions(form.ID, 0, 5000, 0)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	a.renderPage(w, r, http.StatusOK, ui.Submissions(submissionsView(a, ctx, form, subs)))
}

func (a *App) handleSubmissionsCSV(w http.ResponseWriter, r *http.Request) {
	_, form, ok := a.formForWeb(w, r)
	if !ok {
		return
	}
	subs, err := a.listSubmissions(form.ID, 0, 1000000, 0)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+form.Slug+`.csv"`)
	_, _ = w.Write([]byte(exportCSV(form, subs)))
}

func submissionsView(a *App, ctx *AuthContext, form *Form, subs []*Submission) ui.SubmissionsData {
	cols := make([]string, 0, len(form.Fields))
	for _, f := range form.Fields {
		cols = append(cols, f.Label)
	}
	rows := make([]ui.SubmissionRow, 0, len(subs))
	for _, s := range subs {
		vals := make([]string, 0, len(form.Fields))
		for _, f := range form.Fields {
			vals = append(vals, displayValue(f, s.Values[f.Key]))
		}
		rows = append(rows, ui.SubmissionRow{CreatedAt: fmtTime(s.CreatedAt), Values: vals})
	}
	return ui.SubmissionsData{
		AppName: a.cfg.AppName, UserName: ctx.User.GitHubUsername,
		ID: form.ID, Title: form.Title, OwnerTeam: form.OwnerTeam, Status: form.Status,
		PublicURL: form.publicURL(a.cfg.BaseURL), Count: len(subs),
		Columns: cols, Rows: rows,
	}
}

func displayValue(f FieldDef, v string) string {
	if f.Type == "checkbox" {
		if v == "true" {
			return "Ja"
		}
		return "Nein"
	}
	return v
}

func (a *App) notice(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	a.renderPage(w, r, status, ui.Notice(a.cfg.AppName, heading, message))
}

func formView(a *App, form *Form, fieldErrs map[string]string, values map[string]string) ui.FormView {
	fields := make([]ui.FormField, 0, len(form.Fields))
	for _, f := range form.Fields {
		fields = append(fields, ui.FormField{
			Key: f.Key, Label: f.Label, Type: f.Type, HelpHTML: mdToHTML(f.Help),
			Required: f.Required, MaxLength: f.MaxLength, Options: f.Options,
			Value: values[f.Key], Error: fieldErrs[f.Key],
		})
	}
	general := ""
	if len(fieldErrs) > 0 {
		general = "Bitte prüfen Sie die rot markierten Felder."
	}
	return ui.FormView{
		AppName: a.cfg.AppName, Title: form.Title, DescriptionHTML: mdToHTML(form.Description),
		Error: general, TimeToken: strconv.FormatInt(nowMs(), 10), Fields: fields,
	}
}

func (a *App) handleFormGet(w http.ResponseWriter, r *http.Request) {
	form, err := a.getFormBySlug(r.PathValue("slug"))
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	if form == nil {
		a.notice(w, r, 404, "Nicht gefunden", "Dieser Link ist ungültig oder die Umfrage wurde entfernt.")
		return
	}
	if !form.acceptsSubmissions() {
		a.notice(w, r, 410, "Geschlossen", "Diese Umfrage nimmt derzeit keine Einsendungen entgegen.")
		return
	}
	if !form.AllowMultiple && a.alreadySubmitted(r, form) {
		a.notice(w, r, 200, "Bereits ausgefüllt", "Sie haben dieses Formular bereits abgesendet. Vielen Dank!")
		return
	}
	a.renderPage(w, r, http.StatusOK, ui.FormPage(formView(a, form, nil, map[string]string{})))
}

func (a *App) handleFormPost(w http.ResponseWriter, r *http.Request) {
	form, err := a.getFormBySlug(r.PathValue("slug"))
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	if form == nil {
		a.notice(w, r, 404, "Nicht gefunden", "Dieser Link ist ungültig.")
		return
	}
	if !form.acceptsSubmissions() {
		a.notice(w, r, 410, "Geschlossen", "Diese Umfrage nimmt derzeit keine Einsendungen entgegen.")
		return
	}

	ip := clientIP(r)
	if !a.rl.allow(ip) {
		a.notice(w, r, 429, "Zu viele Anfragen", "Bitte versuchen Sie es in einer Minute erneut.")
		return
	}
	if err := r.ParseForm(); err != nil {
		a.notice(w, r, 400, "Fehler", "Die Anfrage konnte nicht verarbeitet werden.")
		return
	}

	if strings.TrimSpace(r.PostForm.Get("website")) != "" || tooFast(r.PostForm.Get("t")) {
		a.renderPage(w, r, http.StatusOK, ui.Confirm(a.cfg.AppName))
		return
	}
	if !form.AllowMultiple && a.alreadySubmitted(r, form) {
		a.notice(w, r, 200, "Bereits ausgefüllt", "Sie haben dieses Formular bereits abgesendet. Vielen Dank!")
		return
	}

	raw := map[string]string{}
	for _, f := range form.Fields {
		raw[f.Key] = r.PostForm.Get(f.Key)
	}
	clean, fieldErrs := validateSubmission(form, raw)
	if len(fieldErrs) > 0 {
		a.renderPage(w, r, http.StatusBadRequest, ui.FormPage(formView(a, form, fieldErrs, raw)))
		return
	}

	if _, err := a.insertSubmission(form.ID, clean, r.UserAgent(), a.hashIP(ip)); err != nil {
		a.notice(w, r, 500, "Fehler", "Ihre Angaben konnten nicht gespeichert werden. Bitte später erneut versuchen.")
		return
	}
	if !form.AllowMultiple {
		a.setCookie(w, "submitted_"+form.ID, "1", 365*24*60*60)
	}
	a.renderPage(w, r, http.StatusOK, ui.Confirm(a.cfg.AppName))
}

func (a *App) alreadySubmitted(r *http.Request, form *Form) bool {
	return cookieValue(r, "submitted_"+form.ID) != ""
}

func tooFast(token string) bool {
	t, err := strconv.ParseInt(token, 10, 64)
	if err != nil || t <= 0 {
		return false
	}
	return nowMs()-t < 1200
}

func (a *App) hashIP(ip string) string {
	sum := sha256.Sum256([]byte(a.cfg.SessionSecret + "|" + ip))
	return hex.EncodeToString(sum[:])[:32]
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
