package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

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
		next := r.URL.Query().Get("next")
		if !isLocalRelative(next) {
			next = "/"
		}
		att := newLoginAttempt(next)
		authURL, err := a.oidcAuthCodeURL(att)
		if err != nil {
			log.Printf("[login] oidc discovery failed: %v", err)
			http.Error(w, "login temporarily unavailable", 503)
			return
		}
		// state, nonce and PKCE verifier travel in an HttpOnly cookie that
		// only this browser holds; the code alone is useless without it.
		payload, _ := json.Marshal(att)

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
		var parsed loginAttempt
		if err := json.Unmarshal(decoded, &parsed); err != nil {
			http.Error(w, "bad state cookie", 400)
			return
		}
		if parsed.State == "" || parsed.State != state {
			http.Error(w, "state mismatch", 400)
			return
		}
		a.deleteCookie(w, stateCookie)

		_, sid, err := a.loginViaOIDC(code, parsed, r.UserAgent())
		if err != nil {
			log.Printf("[login] callback failed: %v", err)
			http.Error(w, "login failed", 500)
			return
		}
		a.setCookie(w, sessionCookie, sid, 7*24*60*60)
		next := parsed.Next
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

	// OIDC Back-Channel Logout 1.0: the provider POSTs a logout_token when a
	// user's session there ends (logout, block, admin kill). Register
	// <base>/login/backchannel-logout as the client's back-channel logout URI.
	mux.HandleFunc("POST /login/backchannel-logout", a.handleBackchannelLogout)
}

const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

func (a *App) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(msg string) {
		logJSON("warn", "back-channel logout rejected", map[string]any{"err": msg})
		writeJSON(w, 400, map[string]string{"error": "invalid_request", "error_description": msg})
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		fail("bad form body")
		return
	}
	token := r.PostForm.Get("logout_token")
	if token == "" {
		fail("missing logout_token")
		return
	}
	sub, sid, err := a.validateLogoutToken(token)
	if err != nil {
		fail(err.Error())
		return
	}
	var n int
	switch {
	case sid != "" && sub != "":
		n = a.endIdpSessions("back-channel logout", `sid = ? AND github_id = ?`, sid, sub)
	case sid != "":
		n = a.endIdpSessions("back-channel logout", `sid = ?`, sid)
	default:
		n = a.endIdpSessions("back-channel logout", `github_id = ?`, sub)
	}
	logJSON("info", "back-channel logout", map[string]any{"sub": sub, "sid": sid, "ended": n})
	w.WriteHeader(http.StatusOK)
}

// validateLogoutToken implements OIDC Back-Channel Logout 1.0 §2.6.
func (a *App) validateLogoutToken(raw string) (sub, sid string, err error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return "", "", err
	}
	m, err := verifyJWT(raw, p.jwks, a.http) // 2: signature (alg none refused)
	if err != nil {
		return "", "", err
	}
	c := jwtClaims{raw: m}
	if err := c.checkIssAud(a.cfg.OIDCIssuer, a.cfg.OIDCClientID); err != nil { // 3: iss, aud
		return "", "", err
	}
	now := time.Now()
	iat, ok := c.num("iat") // 3: iat
	if !ok || time.Unix(iat, 0).After(now.Add(clockSkew)) {
		return "", "", errors.New("iat missing or in the future")
	}
	if exp, ok := c.num("exp"); ok && time.Unix(exp, 0).Add(clockSkew).Before(now) { // 3: exp
		return "", "", errors.New("logout token expired")
	}
	sub, sid = c.str("sub"), c.str("sid") // 4: sub and/or sid
	if sub == "" && sid == "" {
		return "", "", errors.New("neither sub nor sid")
	}
	var events map[string]json.RawMessage // 5: events member
	if err := json.Unmarshal(c.raw["events"], &events); err != nil {
		return "", "", errors.New("events claim missing")
	}
	ev, ok := events[backchannelLogoutEvent]
	var evObj map[string]any
	if !ok || json.Unmarshal(ev, &evObj) != nil || evObj == nil {
		return "", "", errors.New("events lacks the back-channel logout event")
	}
	if c.has("nonce") { // 6: no nonce
		return "", "", errors.New("logout token must not contain nonce")
	}
	return sub, sid, nil
}
