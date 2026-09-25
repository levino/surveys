package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	sessionTTLMs  = 7 * 24 * 60 * 60 * 1000
	sessionCookie = "surveys_session"
)

type User struct {
	GitHubID       string
	GitHubUsername string
	Name           string
	AvatarURL      string
	CachedAt       int64
}

type AuthContext struct {
	User  *User
	Teams []teamMembership
	// The provider login this request rides on; MCP tokens issued from this
	// context are bound to it.
	IdpSessionID string
}

func (c *AuthContext) isMember(team string) bool {
	for _, t := range c.Teams {
		if t.Slug == team {
			return true
		}
	}
	return false
}

func (c *AuthContext) isMaintainer(team string) bool {
	for _, t := range c.Teams {
		if t.Slug == team {
			return t.IsMaintainer
		}
	}
	return false
}

// canManage: who may change or delete a survey (and its submissions).
// The creator always can; a team maintainer (e.g. the class's `admin` role)
// can for surveys of that team. Plain team members may only read.
func (c *AuthContext) canManage(f *Form) bool {
	if c == nil || c.User == nil || f == nil {
		return false
	}
	if f.CreatedBy != "" && f.CreatedBy == c.User.GitHubID {
		return true
	}
	return c.isMaintainer(f.OwnerTeam)
}

func (c *AuthContext) teamSlugs() []string {
	out := make([]string, 0, len(c.Teams))
	for _, t := range c.Teams {
		out = append(out, t.Slug)
	}
	return out
}

func (a *App) upsertUser(subject, username, name string) (*User, error) {
	if username == "" {
		username = subject
	}
	_, err := a.db.Exec(
		`INSERT INTO users(github_id, github_username, name, avatar_url, cached_at)
		 VALUES (?,?,?,NULL,?)
		 ON CONFLICT(github_id) DO UPDATE SET
		   github_username=excluded.github_username,
		   name=excluded.name,
		   cached_at=excluded.cached_at`,
		subject, username, nullStr(name), nowMs(),
	)
	if err != nil {
		return nil, err
	}
	return a.readUser(subject)
}

func (a *App) readUser(id string) (*User, error) {
	var (
		u            User
		name, avatar sql.NullString
	)
	err := a.db.QueryRow(
		`SELECT github_id, github_username, name, avatar_url, cached_at FROM users WHERE github_id = ?`, id,
	).Scan(&u.GitHubID, &u.GitHubUsername, &name, &avatar, &u.CachedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Name, u.AvatarURL = name.String, avatar.String
	return &u, nil
}

func (a *App) createSession(subject, idpSessionID, userAgent string) (string, error) {
	sid := genID("sess")
	now := nowMs()
	_, err := a.db.Exec(
		`INSERT INTO sessions(id, github_id, created_at, expires_at, user_agent, last_seen_at, idp_session_id) VALUES (?,?,?,?,?,?,?)`,
		sid, subject, now, now+sessionTTLMs, nullStr(userAgent), now, idpSessionID,
	)
	return sid, err
}

func (a *App) destroySession(sid string) {
	_, _ = a.db.Exec(`DELETE FROM sessions WHERE id = ?`, sid)
}

// ---- provider sessions ----------------------------------------------------

var (
	// errSessionEnded: the provider login is gone (refresh rejected, logged
	// out, never linked). The caller is unauthenticated.
	errSessionEnded = errors.New("session ended")
	// errIdPUnavailable: could not refresh right now. Deny, keep the session.
	errIdPUnavailable = errors.New("identity provider unavailable")
)

type idpSession struct {
	ID           string
	Subject      string
	SID          string
	RefreshToken string
	Teams        []teamMembership
	RefreshedAt  int64
}

func (a *App) createIdpSession(id *identity) (string, error) {
	sessID := genID("idp")
	teams, _ := json.Marshal(nonNilTeams(id.Teams))
	now := nowMs()
	_, err := a.db.Exec(
		`INSERT INTO idp_sessions(id, github_id, sid, refresh_token, teams, refreshed_at, created_at) VALUES (?,?,?,?,?,?,?)`,
		sessID, id.Subject, nullStr(id.SID), nullStr(id.RefreshToken), string(teams), now, now,
	)
	return sessID, err
}

func nonNilTeams(t []teamMembership) []teamMembership {
	if t == nil {
		return []teamMembership{}
	}
	return t
}

func (a *App) loadIdpSession(id string) (*idpSession, error) {
	var (
		s         idpSession
		sid, rt   sql.NullString
		teamsJSON string
	)
	err := a.db.QueryRow(
		`SELECT id, github_id, sid, refresh_token, teams, refreshed_at FROM idp_sessions WHERE id = ?`, id,
	).Scan(&s.ID, &s.Subject, &sid, &rt, &teamsJSON, &s.RefreshedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.SID, s.RefreshToken = sid.String, rt.String
	_ = json.Unmarshal([]byte(teamsJSON), &s.Teams)
	return &s, nil
}

func (a *App) refreshLock(id string) *sync.Mutex {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	m, ok := a.refreshLocks[id]
	if !ok {
		m = &sync.Mutex{}
		a.refreshLocks[id] = m
	}
	return m
}

// freshIdpSession returns the provider session, refreshing its tokens (and
// thereby its teams) first when they are older than cfg.RefreshInterval.
// Refreshes of one session are serialised: the provider rotates refresh
// tokens, and two parallel refreshes with the same token would kill it.
func (a *App) freshIdpSession(id string) (*idpSession, error) {
	if id == "" {
		return nil, errSessionEnded
	}
	s, err := a.loadIdpSession(id)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errSessionEnded
	}
	if time.Duration(nowMs()-s.RefreshedAt)*time.Millisecond < a.cfg.RefreshInterval {
		return s, nil
	}

	lock := a.refreshLock(id)
	lock.Lock()
	defer lock.Unlock()
	// Someone else may have refreshed (or ended it) while we waited.
	if s, err = a.loadIdpSession(id); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errSessionEnded
	}
	if time.Duration(nowMs()-s.RefreshedAt)*time.Millisecond < a.cfg.RefreshInterval {
		return s, nil
	}
	if s.RefreshToken == "" {
		a.endIdpSessions("no refresh token", `id = ?`, id)
		return nil, errSessionEnded
	}
	ident, err := a.oidcRefresh(s.RefreshToken, s.Subject)
	if err != nil {
		if isIdPRejection(err) {
			a.endIdpSessions("refresh rejected: "+err.Error(), `id = ?`, id)
			return nil, errSessionEnded
		}
		logJSON("error", "token refresh failed, denying", map[string]any{"user": s.Subject, "err": err.Error()})
		return nil, errIdPUnavailable
	}
	teams, _ := json.Marshal(nonNilTeams(ident.Teams))
	sid := s.SID
	if ident.SID != "" {
		sid = ident.SID
	}
	now := nowMs()
	if _, err := a.db.Exec(
		`UPDATE idp_sessions SET refresh_token = ?, sid = ?, teams = ?, refreshed_at = ? WHERE id = ?`,
		ident.RefreshToken, nullStr(sid), string(teams), now, id,
	); err != nil {
		return nil, err
	}
	if ident.Name != "" {
		_, _ = a.upsertUser(s.Subject, ident.Name, ident.Name)
	}
	s.RefreshToken, s.SID, s.Teams, s.RefreshedAt = ident.RefreshToken, sid, ident.Teams, now
	return s, nil
}

// endIdpSessions deletes the matching provider sessions together with every
// browser session, pending auth code and MCP token bound to them. where is
// a condition on idp_sessions with its args.
func (a *App) endIdpSessions(reason, where string, args ...any) int {
	rows, err := a.db.Query(`SELECT id FROM idp_sessions WHERE `+where, args...)
	if err != nil {
		logJSON("error", "end sessions: query failed", map[string]any{"err": err.Error()})
		return 0
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		for _, q := range []string{
			`DELETE FROM sessions WHERE idp_session_id = ?`,
			`DELETE FROM oauth_tokens WHERE idp_session_id = ?`,
			`DELETE FROM oauth_codes WHERE idp_session_id = ?`,
			`DELETE FROM idp_sessions WHERE id = ?`,
		} {
			if _, err := a.db.Exec(q, id); err != nil {
				logJSON("error", "end sessions: delete failed", map[string]any{"err": err.Error()})
			}
		}
		a.refreshMu.Lock()
		delete(a.refreshLocks, id)
		a.refreshMu.Unlock()
	}
	if len(ids) > 0 {
		logJSON("info", "sessions ended", map[string]any{"count": len(ids), "reason": reason})
	}
	return len(ids)
}

// purgeAuth removes expired browser sessions and provider sessions nothing
// refers to any more (the refresh token must not outlive its use).
func (a *App) purgeAuth() {
	now := nowMs()
	_, _ = a.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now)
	_, _ = a.db.Exec(`DELETE FROM oauth_tokens WHERE expires_at < ?`, now)
	_, _ = a.db.Exec(`DELETE FROM oauth_codes WHERE expires_at < ?`, now)
	_, _ = a.db.Exec(`DELETE FROM oauth_authz_requests WHERE expires_at < ?`, now)
	_, _ = a.db.Exec(
		`DELETE FROM idp_sessions WHERE created_at < ?
		   AND id NOT IN (SELECT idp_session_id FROM sessions WHERE idp_session_id IS NOT NULL)
		   AND id NOT IN (SELECT idp_session_id FROM oauth_tokens WHERE idp_session_id IS NOT NULL AND revoked_at IS NULL)
		   AND id NOT IN (SELECT idp_session_id FROM oauth_codes WHERE idp_session_id IS NOT NULL)`,
		now-codeTTLMs,
	)
}

// contextForIdpSession: the user and their (fresh) teams for a request.
func (a *App) contextForIdpSession(idpSessionID string) (*AuthContext, error) {
	s, err := a.freshIdpSession(idpSessionID)
	if err != nil {
		return nil, err
	}
	user, err := a.readUser(s.Subject)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errSessionEnded
	}
	return &AuthContext{User: user, Teams: s.Teams, IdpSessionID: s.ID}, nil
}

// resolveSession: nil, nil = not logged in.
func (a *App) resolveSession(sid string) (*AuthContext, error) {
	if sid == "" {
		return nil, nil
	}
	var (
		expires int64
		idp     sql.NullString
	)
	err := a.db.QueryRow(`SELECT expires_at, idp_session_id FROM sessions WHERE id = ?`, sid).Scan(&expires, &idp)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expires < nowMs() || !idp.Valid {
		a.destroySession(sid)
		return nil, nil
	}
	ctx, err := a.contextForIdpSession(idp.String)
	if errors.Is(err, errSessionEnded) {
		a.destroySession(sid)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_, _ = a.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, nowMs(), sid)
	return ctx, nil
}

func (a *App) loginViaOIDC(code string, att loginAttempt, userAgent string) (*User, string, error) {
	ident, err := a.oidcExchange(code, att)
	if err != nil {
		return nil, "", err
	}
	username := strings.TrimSpace(ident.Name)
	user, err := a.upsertUser(ident.Subject, username, ident.Name)
	if err != nil {
		return nil, "", err
	}
	idpID, err := a.createIdpSession(ident)
	if err != nil {
		return nil, "", err
	}
	sid, err := a.createSession(user.GitHubID, idpID, userAgent)
	if err != nil {
		return nil, "", err
	}
	return user, sid, nil
}
