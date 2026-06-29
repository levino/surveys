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

func (a *App) setCookie(w http.ResponseWriter, name, value string, maxAgeSec int) {
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

func (a *App) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   a.secureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
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
