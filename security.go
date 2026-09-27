package main

import (
	"database/sql"
	"net/http"
	"net/url"
	"strings"
)

func (a *App) crossOriginProtection() *http.CrossOriginProtection {
	cop := http.NewCrossOriginProtection()
	// Bearer- or PKCE-authenticated and called cross-origin by design
	// (OAuth 2.1 token endpoint, MCP transport); neither reads a cookie.
	cop.AddInsecureBypassPattern("POST /mcp")
	cop.AddInsecureBypassPattern("POST /oauth/token")
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logJSON("warn", "cross-origin request refused", map[string]any{
			"method": r.Method, "path": r.URL.Path,
			"sec_fetch_site": r.Header.Get("Sec-Fetch-Site"), "origin": r.Header.Get("Origin"),
		})
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
	}))
	return cop
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// requestSession resolves the browser session. Sessions from before the
// __Host- cookie still arrive under the bare name; those are accepted once
// and moved to the prefixed cookie, so nobody is logged out by the switch.
func (a *App) requestSession(w http.ResponseWriter, r *http.Request) (*AuthContext, string) {
	if sid, ok := uniqueCookie(r, a.cookieName(sessionCookie)); ok {
		ctx, _ := a.resolveSession(sid)
		if ctx == nil {
			return nil, ""
		}
		return ctx, sid
	}
	if !a.secureCookies() {
		return nil, ""
	}
	sid, ok := uniqueCookie(r, sessionCookie)
	if !ok {
		return nil, ""
	}
	a.writeCookie(w, sessionCookie, "", -1)
	// A bare-named cookie pointing at a session issued since the switch was
	// planted by another host of the site (session fixation), not migrated.
	var expires int64
	err := a.db.QueryRow(`SELECT expires_at FROM sessions WHERE id = ? AND host_cookie = 0`, sid).Scan(&expires)
	if err == sql.ErrNoRows || err != nil {
		return nil, ""
	}
	ctx, _ := a.resolveSession(sid)
	if ctx == nil {
		return nil, ""
	}
	if remaining := (expires - nowMs()) / 1000; remaining > 0 {
		a.setCookie(w, sessionCookie, sid, int(remaining))
	}
	return ctx, sid
}

func (a *App) clearSessionCookies(w http.ResponseWriter) {
	a.deleteCookie(w, sessionCookie)
	if a.secureCookies() {
		a.writeCookie(w, sessionCookie, "", -1)
	}
}

// clientHostAllowed applies OAUTH_CLIENT_HOSTS (CIMD trust policy): when set,
// only metadata documents on these hosts can become clients.
func (a *App) clientHostAllowed(clientID string) bool {
	return len(a.cfg.OAuthClientHosts) == 0 || a.clientHostListed(clientID)
}

func (a *App) clientHostListed(clientID string) bool {
	u, err := url.Parse(clientID)
	if err != nil {
		return false
	}
	return contains(a.cfg.OAuthClientHosts, strings.ToLower(u.Hostname()))
}
