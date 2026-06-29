package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
-- github_id holds the OIDC subject (opaque user id from dex; with useLoginAsID
-- that is the GitHub login). github_username holds the display name.
CREATE TABLE IF NOT EXISTS users (
  github_id        TEXT PRIMARY KEY,
  github_username  TEXT NOT NULL,
  name             TEXT,
  avatar_url       TEXT,
  cached_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_teams (
  github_id     TEXT NOT NULL,
  team_slug     TEXT NOT NULL,
  is_maintainer INTEGER NOT NULL DEFAULT 0,
  cached_at     INTEGER NOT NULL,
  PRIMARY KEY (github_id, team_slug)
);

CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,
  github_id    TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  user_agent   TEXT,
  last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id         TEXT PRIMARY KEY,
  client_secret     TEXT,
  client_name       TEXT,
  redirect_uris     TEXT NOT NULL,
  grant_types       TEXT NOT NULL DEFAULT '["authorization_code","refresh_token"]',
  token_auth_method TEXT NOT NULL DEFAULT 'none',
  created_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authz_requests (
  id                    TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  scope                 TEXT,
  state                 TEXT,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL DEFAULT 'S256',
  resource              TEXT,
  created_at            INTEGER NOT NULL,
  expires_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  code                  TEXT PRIMARY KEY,
  client_id             TEXT NOT NULL,
  github_id             TEXT NOT NULL,
  redirect_uri          TEXT NOT NULL,
  code_challenge        TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  scope                 TEXT,
  resource              TEXT,
  expires_at            INTEGER NOT NULL,
  used                  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token      TEXT PRIMARY KEY,
  kind       TEXT NOT NULL CHECK (kind IN ('access','refresh')),
  client_id  TEXT NOT NULL,
  github_id  TEXT NOT NULL,
  scope      TEXT,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_tokens_github ON oauth_tokens(github_id);

CREATE TABLE IF NOT EXISTS forms (
  id             TEXT PRIMARY KEY,
  slug           TEXT NOT NULL UNIQUE,
  title          TEXT NOT NULL,
  description    TEXT,
  fields         TEXT NOT NULL DEFAULT '[]',
  owner_team     TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  allow_multiple INTEGER NOT NULL DEFAULT 1,
  expires_at     INTEGER,
  created_by     TEXT,
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS forms_owner_team ON forms(owner_team);

CREATE TABLE IF NOT EXISTS submissions (
  id         TEXT PRIMARY KEY,
  form_id    TEXT NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
  data       TEXT NOT NULL DEFAULT '{}',
  user_agent TEXT,
  ip_hash    TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS submissions_form ON submissions(form_id, created_at);
`

type DB struct{ *sql.DB }

func openDB(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	sqldb.SetMaxOpenConns(1)
	if err := sqldb.Ping(); err != nil {
		return nil, err
	}
	if _, err := sqldb.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &DB{sqldb}, nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

func genID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	h := hex.EncodeToString(b)
	if prefix == "" {
		return h
	}
	return prefix + "_" + h
}

func randomSlug() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
