package main

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	BaseURL       string
	AppName       string
	Theme         string
	Port          string
	DatabasePath  string
	SessionSecret string

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string

	GroupPrefix string
	// A group ending in this suffix (e.g. ":admin") makes the user a
	// maintainer of the team named by the rest of the group. Empty = off.
	MaintainerSuffix string
	// OIDC scopes requested at login. Providers that emit `groups` via a
	// custom claim (ZITADEL action) do not need a `groups` scope.
	Scopes string
	// Default retention: new surveys get delete_at = created_at + N days
	// unless the creator sets an explicit delete_at. 0 = keep forever.
	RetentionDays int
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	return Config{
		BaseURL:          env("PUBLIC_BASE_URL", "http://localhost:8080"),
		AppName:          env("PUBLIC_APP_NAME", "Surveys"),
		Theme:            env("PUBLIC_THEME", "surveys"),
		Port:             env("PORT", "8080"),
		DatabasePath:     env("DATABASE_PATH", "./data/app.db"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
		OIDCIssuer:       env("OIDC_ISSUER", ""),
		OIDCClientID:     env("OIDC_CLIENT_ID", "surveys"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		GroupPrefix:      env("OIDC_GROUP_PREFIX", ""),
		MaintainerSuffix: env("OIDC_MAINTAINER_SUFFIX", ""),
		Scopes:           env("OIDC_SCOPES", "openid profile email groups"),
		RetentionDays:    envInt("DEFAULT_RETENTION_DAYS", 0),
	}
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return def
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func (c Config) callbackURL() string { return c.BaseURL + "/login/callback" }

func (c Config) teamFromGroup(group string) string {
	if c.GroupPrefix != "" && strings.HasPrefix(group, c.GroupPrefix) {
		return strings.TrimPrefix(group, c.GroupPrefix)
	}
	return group
}

// splitGroup maps one `groups` claim value to (team slug, maintainer?).
// "acme:marketing" -> ("marketing", false); with MaintainerSuffix ":admin",
// "acme:marketing:admin" -> ("marketing", true).
func (c Config) splitGroup(group string) (string, bool) {
	slug := c.teamFromGroup(group)
	if c.MaintainerSuffix != "" && strings.HasSuffix(slug, c.MaintainerSuffix) {
		base := strings.TrimSuffix(slug, c.MaintainerSuffix)
		if base != "" {
			return base, true
		}
	}
	return slug, false
}

type App struct {
	cfg    Config
	db     *DB
	rl     *rateLimiter
	http   *http.Client
	oidc   *oidcProvider
	oidcMu sync.Mutex
}

func newApp(cfg Config, db *DB) *App {
	return &App{
		cfg:  cfg,
		db:   db,
		rl:   newRateLimiter(),
		http: &http.Client{Timeout: 15 * time.Second},
	}
}
