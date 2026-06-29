package main

import (
	"database/sql"
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
}

func (c *AuthContext) isMember(team string) bool {
	for _, t := range c.Teams {
		if t.Slug == team {
			return true
		}
	}
	return false
}

func (c *AuthContext) teamSlugs() []string {
	out := make([]string, 0, len(c.Teams))
	for _, t := range c.Teams {
		out = append(out, t.Slug)
	}
	return out
}

func (a *App) upsertUserFromClaims(subject, username, name, avatar string, teams []teamMembership) (*User, error) {
	now := nowMs()
	if username == "" {
		username = subject
	}
	_, err := a.db.Exec(
		`INSERT INTO users(github_id, github_username, name, avatar_url, cached_at)
		 VALUES (?,?,?,?,?)
		 ON CONFLICT(github_id) DO UPDATE SET
		   github_username=excluded.github_username,
		   name=excluded.name,
		   avatar_url=excluded.avatar_url,
		   cached_at=excluded.cached_at`,
		subject, username, nullStr(name), nullStr(avatar), now,
	)
	if err != nil {
		return nil, err
	}

	if _, err := a.db.Exec(`DELETE FROM user_teams WHERE github_id = ?`, subject); err != nil {
		return nil, err
	}
	for _, t := range teams {
		m := 0
		if t.IsMaintainer {
			m = 1
		}
		if _, err := a.db.Exec(
			`INSERT INTO user_teams(github_id, team_slug, is_maintainer, cached_at) VALUES (?,?,?,?)`,
			subject, t.Slug, m, now,
		); err != nil {
			return nil, err
		}
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

func (a *App) createSession(subject, userAgent string) (string, error) {
	sid := genID("sess")
	now := nowMs()
	_, err := a.db.Exec(
		`INSERT INTO sessions(id, github_id, created_at, expires_at, user_agent, last_seen_at) VALUES (?,?,?,?,?,?)`,
		sid, subject, now, now+sessionTTLMs, nullStr(userAgent), now,
	)
	return sid, err
}

func (a *App) destroySession(sid string) {
	_, _ = a.db.Exec(`DELETE FROM sessions WHERE id = ?`, sid)
}

func (a *App) contextForUser(subject string) (*AuthContext, error) {
	user, err := a.readUser(subject)
	if err != nil || user == nil {
		return nil, err
	}
	rows, err := a.db.Query(`SELECT team_slug, is_maintainer FROM user_teams WHERE github_id = ?`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var teams []teamMembership
	for rows.Next() {
		var t teamMembership
		var m int
		if err := rows.Scan(&t.Slug, &m); err != nil {
			return nil, err
		}
		t.IsMaintainer = m != 0
		teams = append(teams, t)
	}
	return &AuthContext{User: user, Teams: teams}, nil
}

func (a *App) resolveSession(sid string) (*AuthContext, error) {
	if sid == "" {
		return nil, nil
	}
	var subject string
	var expires int64
	err := a.db.QueryRow(`SELECT github_id, expires_at FROM sessions WHERE id = ?`, sid).Scan(&subject, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expires < nowMs() {
		a.destroySession(sid)
		return nil, nil
	}
	_, _ = a.db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`, nowMs(), sid)
	return a.contextForUser(subject)
}

func (a *App) loginViaOIDC(code, userAgent string) (*User, string, error) {
	claims, err := a.oidcExchange(code)
	if err != nil {
		return nil, "", err
	}
	username := claims.Name
	if username == "" {
		username = claims.Subject
	}
	teams := a.teamsFromClaims(claims)
	user, err := a.upsertUserFromClaims(claims.Subject, username, claims.Name, "", teams)
	if err != nil {
		return nil, "", err
	}
	sid, err := a.createSession(user.GitHubID, userAgent)
	if err != nil {
		return nil, "", err
	}
	return user, sid, nil
}
