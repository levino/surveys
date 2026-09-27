package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

var errUnsupportedContentType = errors.New("unsupported content-type")

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

func contains2(haystack, needle string) bool { return strings.Contains(haystack, needle) }

func msPtr(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func (a *App) secureCookies() bool { return strings.HasPrefix(a.cfg.BaseURL, "https://") }

// cookieName: over https every cookie carries the __Host- prefix, so no
// sibling host under the same site can set or shadow it.
func (a *App) cookieName(name string) string {
	if a.secureCookies() {
		return "__Host-" + name
	}
	return name
}

func (a *App) setCookie(w http.ResponseWriter, name, value string, maxAgeSec int) {
	a.writeCookie(w, a.cookieName(name), value, maxAgeSec)
}

func (a *App) deleteCookie(w http.ResponseWriter, name string) {
	a.writeCookie(w, a.cookieName(name), "", -1)
}

func (a *App) writeCookie(w http.ResponseWriter, name, value string, maxAgeSec int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSec,
	})
}

func (a *App) cookieValue(r *http.Request, name string) string {
	v, _ := uniqueCookie(r, a.cookieName(name))
	return v
}

// uniqueCookie refuses a name sent more than once: the extra copy comes from
// a cookie some other host set for the whole domain, and neither copy can be
// told apart from the other.
func uniqueCookie(r *http.Request, name string) (string, bool) {
	cs := r.CookiesNamed(name)
	if len(cs) != 1 || cs[0].Value == "" {
		return "", false
	}
	return cs[0].Value, true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, err error) {
	if he, ok := err.(*httpError); ok {
		writeJSON(w, he.status, map[string]string{"error": he.code, "error_description": he.message})
		return
	}
	writeJSON(w, 500, map[string]string{"error": "server_error", "error_description": err.Error()})
}
