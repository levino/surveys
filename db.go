package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
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
  ref            TEXT,
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
	db := &DB{sqldb}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func (db *DB) migrate() error {
	_, _ = db.Exec(`ALTER TABLE forms ADD COLUMN ref TEXT`)
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS forms_ref ON forms(ref)`); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, title FROM forms WHERE ref IS NULL OR ref = ''`)
	if err != nil {
		return err
	}
	type pending struct{ id, title string }
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.title); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, p)
	}
	rows.Close()
	for _, p := range todo {
		if _, err := db.Exec(`UPDATE forms SET ref = ? WHERE id = ?`, db.uniqueRef(slugify(p.title), p.id), p.id); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) uniqueRef(base, exceptID string) string {
	if base == "" {
		base = "umfrage"
	}
	ref := base
	for i := 2; i < 10000; i++ {
		var x int
		err := db.QueryRow(`SELECT 1 FROM forms WHERE ref = ? AND id != ?`, ref, exceptID).Scan(&x)
		if err == sql.ErrNoRows {
			return ref
		}
		if err != nil {
			return base + "-" + randomSlug()[:6]
		}
		ref = fmt.Sprintf("%s-%d", base, i)
	}
	return base + "-" + randomSlug()[:6]
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(
		"ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss",
		"á", "a", "à", "a", "â", "a", "é", "e", "è", "e", "ê", "e",
	).Replace(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = strings.Trim(out[:60], "-")
	}
	if out == "" {
		out = "umfrage"
	}
	return out
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
