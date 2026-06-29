package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/levino/surveys/ui"
)

const (
	stateCookie  = "surveys_oauth_state"
	stateTTLSec  = 10 * 60
	loginPageTTL = 0
)

func isLocalRelative(p string) bool {
	return p != "" && strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//")
}

func (a *App) mountWebAuth(mux *http.ServeMux) {

	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if !isLocalRelative(next) {
			next = "/"
		}
		a.renderPage(w, r, http.StatusOK, ui.Login(a.cfg.AppName, "/login/start?next="+url.QueryEscape(next)))
	})

	mux.HandleFunc("GET /login/start", func(w http.ResponseWriter, r *http.Request) {
		state := genID("s")
		next := r.URL.Query().Get("next")
		if !isLocalRelative(next) {
			next = "/"
		}
		authURL, err := a.oidcAuthCodeURL(state)
		if err != nil {
			log.Printf("[login] oidc discovery failed: %v", err)
			http.Error(w, "login temporarily unavailable", 503)
			return
		}
		payload, _ := json.Marshal(map[string]string{"s": state, "n": next})

		a.setCookie(w, stateCookie, base64.RawURLEncoding.EncodeToString(payload), stateTTLSec)
		http.Redirect(w, r, authURL, http.StatusFound)
	})

	mux.HandleFunc("GET /login/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			http.Error(w, "missing code/state", 400)
			return
		}
		raw := cookieValue(r, stateCookie)
		if raw == "" {
			http.Error(w, "missing state cookie", 400)
			return
		}
		decoded, derr := base64.RawURLEncoding.DecodeString(raw)
		if derr != nil {
			http.Error(w, "bad state cookie", 400)
			return
		}
		var parsed struct {
			S string `json:"s"`
			N string `json:"n"`
		}
		if err := json.Unmarshal(decoded, &parsed); err != nil {
			http.Error(w, "bad state cookie", 400)
			return
		}
		if parsed.S != state {
			http.Error(w, "state mismatch", 400)
			return
		}
		a.deleteCookie(w, stateCookie)

		_, sid, err := a.loginViaOIDC(code, r.UserAgent())
		if err != nil {
			log.Printf("[login] callback failed: %v", err)
			http.Error(w, "login failed", 500)
			return
		}
		a.setCookie(w, sessionCookie, sid, 7*24*60*60)
		next := parsed.N
		if !isLocalRelative(next) {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusFound)
	})

	logout := func(w http.ResponseWriter, r *http.Request) {
		if sid := cookieValue(r, sessionCookie); sid != "" {
			a.destroySession(sid)
		}
		a.deleteCookie(w, sessionCookie)
		http.Redirect(w, r, "/login?logged_out=1", http.StatusFound)
	}
	mux.HandleFunc("POST /logout", logout)
	mux.HandleFunc("GET /logout", logout)
}
