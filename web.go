package main

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/a-h/templ"

	"github.com/levino/surveys/ui"
)

//go:embed assets/app.css
var appCSS []byte

func (a *App) renderPage(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = c.Render(r.Context(), w)
}

func (a *App) mountStatic(mux *http.ServeMux) {
	mux.HandleFunc("GET /static/app.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(appCSS)
	})
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	ctx, _ := a.resolveSession(cookieValue(r, sessionCookie))
	if ctx == nil {
		a.renderPage(w, r, http.StatusOK, ui.Landing(a.cfg.AppName))
		return
	}
	forms, _ := a.listFormsForTeams(ctx.teamSlugs())
	rows := make([]ui.SurveyRow, 0, len(forms))
	for _, f := range forms {
		n, _ := a.countSubmissions(f.ID)
		rows = append(rows, ui.SurveyRow{
			ID: f.ID, Title: f.Title, OwnerTeam: f.OwnerTeam, Status: f.Status,
			URL: f.publicURL(a.cfg.BaseURL), Submissions: n,
		})
	}
	clients, _ := a.listConnectedClients(ctx.User.GitHubID)
	crows := make([]ui.ClientRow, 0, len(clients))
	for _, c := range clients {
		name := c.ClientName
		if name == "" {
			name = c.ClientID
		}
		crows = append(crows, ui.ClientRow{ID: c.ClientID, Name: name, LastSeen: isoMs(c.LastSeen)})
	}
	d := ui.DashboardData{
		AppName:  a.cfg.AppName,
		UserName: ctx.User.GitHubUsername,
		MCPUrl:   a.cfg.BaseURL + "/mcp",
		Teams:    strings.Join(ctx.teamSlugs(), ", "),
		Surveys:  rows,
		Clients:  crows,
	}
	a.renderPage(w, r, http.StatusOK, ui.Dashboard(d))
}

func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	ctx, _ := a.resolveSession(cookieValue(r, sessionCookie))
	if ctx == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = r.ParseForm()
	if cid := r.PostForm.Get("client_id"); cid != "" {
		_ = a.revokeClient(ctx.User.GitHubID, cid)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
