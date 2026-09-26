package main

import (
	"context"
	"net/http"
	"os"
	"sort"
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
	// ZITADEL application key for private_key_jwt; wins over the secret.
	OIDCClientKey *clientKey

	// HMAC key of the ZITADEL Actions v2 target; empty = webhook off (404).
	WebhookSigningKey string

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

	// Teams from ZITADEL project roles in the user's own tokens (see
	// zitadel.go). When ZitadelTeamProjects is set, the `groups` claim is
	// ignored and the login requests the ZITADEL role/audience scopes.
	ZitadelTeamProjects   map[string]string
	ZitadelMaintainerRole string

	// Upper bound for how long provider tokens are used before the next use
	// refreshes them (and re-derives the teams); expires_in may shorten it.
	RefreshInterval time.Duration
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadConfig() (Config, error) {
	cfg := Config{
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
		Scopes:           env("OIDC_SCOPES", "openid profile email offline_access groups"),
		RetentionDays:    envInt("DEFAULT_RETENTION_DAYS", 0),

		ZitadelTeamProjects:   parseTeamProjects(env("ZITADEL_TEAM_PROJECTS", "")),
		ZitadelMaintainerRole: env("ZITADEL_MAINTAINER_ROLE", "admin"),
		RefreshInterval:       envDuration("OIDC_REFRESH_INTERVAL", 10*time.Minute),
		WebhookSigningKey:     strings.TrimSpace(os.Getenv("ZITADEL_WEBHOOK_SIGNING_KEY")),
	}
	if err := applyClientKey(&cfg, os.Getenv("OIDC_CLIENT_KEY"), strings.TrimSpace(os.Getenv("OIDC_CLIENT_ID"))); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// warnDeprecated logs (once, at start) about settings that are still
// accepted but no longer do anything, so old deployments keep starting.
func warnDeprecated() {
	for _, k := range []string{"ZITADEL_SERVICE_TOKEN", "ZITADEL_ORG_ID"} {
		if os.Getenv(k) != "" {
			logJSON("warn", "deprecated setting ignored", map[string]any{
				"var":    k,
				"detail": "teams now come from the user's own ZITADEL tokens (project role claims); remove this variable and the service user",
			})
		}
	}
}

// envDuration accepts a Go duration ("10m", "90s") or plain seconds.
func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n := envInt(key, -1); n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
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

// loginScopes: OIDC_SCOPES plus, with ZITADEL_TEAM_PROJECTS, what the role
// claims need — offline_access for the refresh token, the projects:roles
// scope and one audience scope per team project.
func (c Config) loginScopes() string {
	scopes := strings.Fields(c.Scopes)
	add := func(s string) {
		if !contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	add("openid")
	if len(c.ZitadelTeamProjects) > 0 {
		add("offline_access")
		add(zitadelScopeProjectsRoles)
		ids := make([]string, 0, len(c.ZitadelTeamProjects))
		for id := range c.ZitadelTeamProjects {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			add(zitadelAudScope(id))
		}
	}
	return strings.Join(scopes, " ")
}

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

	refreshMu    sync.Mutex
	refreshLocks map[string]*sync.Mutex // idp session id -> serialises its refresh

	credCheck credentialCache

	cimd           cimdCache
	cimdAllowLocal bool // tests only: allow http:// and loopback metadata hosts
}

func newApp(cfg Config, db *DB) *App {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 10 * time.Minute
	}
	return &App{
		cfg:          cfg,
		db:           db,
		rl:           newRateLimiter(),
		http:         &http.Client{Timeout: 15 * time.Second},
		refreshLocks: map[string]*sync.Mutex{},
		cimd:         cimdCache{entries: map[string]cimdEntry{}},
	}
}

func (a *App) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// The lookup is synchronous and short; letting the timer fire is the
	// documented way to release it without threading cancel through callers.
	_ = cancel
	return c
}
