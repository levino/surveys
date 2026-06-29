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
	}
}

func (c Config) callbackURL() string { return c.BaseURL + "/login/callback" }

func (c Config) teamFromGroup(group string) string {
	if c.GroupPrefix != "" && strings.HasPrefix(group, c.GroupPrefix) {
		return strings.TrimPrefix(group, c.GroupPrefix)
	}
	return group
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
