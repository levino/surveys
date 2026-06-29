package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

const (
	codeTTLMs     = 5 * 60 * 1000
	accessTTLMs   = 60 * 60 * 1000
	refreshTTLMs  = 30 * 24 * 60 * 60 * 1000
	authzReqTTLMs = 30 * 60 * 1000
)

var supportedScopes = []string{"mcp"}

const defaultScope = "mcp"

type httpError struct {
	status  int
	code    string
	message string
}

func (e *httpError) Error() string { return e.code + ": " + e.message }

func newHTTPError(status int, code, message string) *httpError {
	return &httpError{status: status, code: code, message: message}
}

type OAuthClient struct {
	ClientID      string
	ClientSecret  string
	ClientName    string
	RedirectURIs  []string
	GrantTypes    []string
	TokenAuthMeth string
	CreatedAt     int64
}

type registerClientInput struct {
	RedirectURIs            []string
	ClientName              string
	TokenEndpointAuthMethod string
	GrantTypes              []string
}

func (a *App) registerClient(in registerClientInput) (*OAuthClient, error) {
	if len(in.RedirectURIs) == 0 {
		return nil, newHTTPError(400, "invalid_redirect_uri", "redirect_uris required")
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return nil, err
		}
	}
	method := in.TokenEndpointAuthMethod
	if method == "" {
		method = "none"
	}
	if method != "none" && method != "client_secret_post" {
		return nil, newHTTPError(400, "invalid_client_metadata", "token_endpoint_auth_method not supported")
	}
	grants := in.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	c := &OAuthClient{
		ClientID:      genID("cli"),
		ClientName:    in.ClientName,
		RedirectURIs:  in.RedirectURIs,
		GrantTypes:    grants,
		TokenAuthMeth: method,
		CreatedAt:     nowMs(),
	}
	if method == "client_secret_post" {
		c.ClientSecret = genID("sec")
	}
	ru, _ := json.Marshal(c.RedirectURIs)
	gt, _ := json.Marshal(c.GrantTypes)
	var secret any
	if c.ClientSecret != "" {
		secret = c.ClientSecret
	}
	_, err := a.db.Exec(
		`INSERT INTO oauth_clients(client_id, client_secret, client_name, redirect_uris, grant_types, token_auth_method, created_at)
		 VALUES (?,?,?,?,?,?,?)`,
		c.ClientID, secret, nullStr(c.ClientName), string(ru), string(gt), c.TokenAuthMeth, c.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (a *App) getClient(clientID string) (*OAuthClient, error) {
	var (
		c      OAuthClient
		secret sql.NullString
		name   sql.NullString
		ru, gt string
	)
	err := a.db.QueryRow(
		`SELECT client_id, client_secret, client_name, redirect_uris, grant_types, token_auth_method, created_at
		 FROM oauth_clients WHERE client_id = ?`, clientID,
	).Scan(&c.ClientID, &secret, &name, &ru, &gt, &c.TokenAuthMeth, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.ClientSecret = secret.String
	c.ClientName = name.String
	_ = json.Unmarshal([]byte(ru), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(gt), &c.GrantTypes)
	return &c, nil
}

type PendingAuthz struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type beginAuthzInput struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

func (a *App) beginAuthz(in beginAuthzInput) (*PendingAuthz, error) {
	client, err := a.getClient(in.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, newHTTPError(400, "invalid_client", "unknown client_id")
	}
	if !contains(client.RedirectURIs, in.RedirectURI) {
		return nil, newHTTPError(400, "invalid_redirect_uri", "redirect_uri not registered")
	}
	if in.ResponseType != "code" {
		return nil, newHTTPError(400, "unsupported_response_type", "only \"code\" supported")
	}
	if in.CodeChallenge == "" {
		return nil, newHTTPError(400, "invalid_request", "PKCE code_challenge required")
	}
	method := in.CodeChallengeMethod
	if method == "" {
		method = "plain"
	}
	if method != "S256" {
		return nil, newHTTPError(400, "invalid_request", "only S256 PKCE supported")
	}
	if in.Scope != "" && !scopeIsSupported(in.Scope) {
		return nil, newHTTPError(400, "invalid_scope", "scope not supported")
	}
	p := &PendingAuthz{
		ID:                  genID("auz"),
		ClientID:            in.ClientID,
		RedirectURI:         in.RedirectURI,
		Scope:               in.Scope,
		State:               in.State,
		CodeChallenge:       in.CodeChallenge,
		CodeChallengeMethod: method,
		Resource:            in.Resource,
	}
	now := nowMs()
	_, err = a.db.Exec(
		`INSERT INTO oauth_authz_requests
		 (id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, resource, created_at, expires_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.ClientID, p.RedirectURI, nullStr(p.Scope), nullStr(p.State),
		p.CodeChallenge, p.CodeChallengeMethod, nullStr(p.Resource), now, now+authzReqTTLMs,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (a *App) loadAuthzRequest(id string) (*PendingAuthz, error) {
	var (
		p                      PendingAuthz
		scope, state, resource sql.NullString
		expires                int64
	)
	err := a.db.QueryRow(
		`SELECT id, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, resource, expires_at
		 FROM oauth_authz_requests WHERE id = ?`, id,
	).Scan(&p.ID, &p.ClientID, &p.RedirectURI, &scope, &state, &p.CodeChallenge, &p.CodeChallengeMethod, &resource, &expires)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if expires < nowMs() {
		_, _ = a.db.Exec(`DELETE FROM oauth_authz_requests WHERE id = ?`, id)
		return nil, nil
	}
	p.Scope, p.State, p.Resource = scope.String, state.String, resource.String
	return &p, nil
}

type completedAuthz struct {
	RedirectURI string
	Code        string
	State       string
}

func (a *App) completeAuthz(authzID, githubID string) (*completedAuthz, error) {
	req, err := a.loadAuthzRequest(authzID)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, newHTTPError(400, "invalid_request", "authorization request expired")
	}
	code := genID("code")
	now := nowMs()
	_, err = a.db.Exec(
		`INSERT INTO oauth_codes
		 (code, client_id, github_id, redirect_uri, code_challenge, code_challenge_method, scope, resource, expires_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		code, req.ClientID, githubID, req.RedirectURI, req.CodeChallenge, req.CodeChallengeMethod,
		nullStr(req.Scope), nullStr(req.Resource), now+codeTTLMs,
	)
	if err != nil {
		return nil, err
	}
	_, _ = a.db.Exec(`DELETE FROM oauth_authz_requests WHERE id = ?`, authzID)
	return &completedAuthz{RedirectURI: req.RedirectURI, Code: code, State: req.State}, nil
}

type IssuedTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type exchangeCodeInput struct {
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

func (a *App) exchangeAuthorizationCode(in exchangeCodeInput) (*IssuedTokens, error) {
	client, err := a.getClient(in.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, newHTTPError(401, "invalid_client", "unknown client")
	}
	if client.TokenAuthMeth == "client_secret_post" {
		if in.ClientSecret == "" || in.ClientSecret != client.ClientSecret {
			return nil, newHTTPError(401, "invalid_client", "client authentication failed")
		}
	}

	var (
		clientID, githubID, redirectURI string
		challenge, method               string
		scope                           sql.NullString
		expires                         int64
		used                            int
	)
	err = a.db.QueryRow(
		`SELECT client_id, github_id, redirect_uri, code_challenge, code_challenge_method, scope, expires_at, used
		 FROM oauth_codes WHERE code = ?`, in.Code,
	).Scan(&clientID, &githubID, &redirectURI, &challenge, &method, &scope, &expires, &used)
	if err == sql.ErrNoRows {
		return nil, newHTTPError(400, "invalid_grant", "unknown code")
	}
	if err != nil {
		return nil, err
	}
	if used != 0 {
		return nil, newHTTPError(400, "invalid_grant", "code already used")
	}
	if expires < nowMs() {
		return nil, newHTTPError(400, "invalid_grant", "code expired")
	}
	if clientID != in.ClientID {
		return nil, newHTTPError(400, "invalid_grant", "code/client mismatch")
	}
	if redirectURI != in.RedirectURI {
		return nil, newHTTPError(400, "invalid_grant", "redirect_uri mismatch")
	}
	if !verifyPKCE(challenge, method, in.CodeVerifier) {
		return nil, newHTTPError(400, "invalid_grant", "PKCE verification failed")
	}
	if _, err := a.db.Exec(`UPDATE oauth_codes SET used = 1 WHERE code = ?`, in.Code); err != nil {
		return nil, err
	}
	return a.mintTokens(clientID, githubID, scope.String)
}

type exchangeRefreshInput struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
}

func (a *App) exchangeRefreshToken(in exchangeRefreshInput) (*IssuedTokens, error) {
	client, err := a.getClient(in.ClientID)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, newHTTPError(401, "invalid_client", "unknown client")
	}
	if client.TokenAuthMeth == "client_secret_post" {
		if in.ClientSecret == "" || in.ClientSecret != client.ClientSecret {
			return nil, newHTTPError(401, "invalid_client", "client authentication failed")
		}
	}
	var (
		clientID, githubID string
		scope              sql.NullString
		expires            int64
		revoked            sql.NullInt64
	)
	err = a.db.QueryRow(
		`SELECT client_id, github_id, scope, expires_at, revoked_at
		 FROM oauth_tokens WHERE token = ? AND kind = 'refresh'`, in.RefreshToken,
	).Scan(&clientID, &githubID, &scope, &expires, &revoked)
	if err == sql.ErrNoRows {
		return nil, newHTTPError(400, "invalid_grant", "unknown refresh token")
	}
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		return nil, newHTTPError(400, "invalid_grant", "token revoked")
	}
	if expires < nowMs() {
		return nil, newHTTPError(400, "invalid_grant", "refresh token expired")
	}
	if clientID != in.ClientID {
		return nil, newHTTPError(400, "invalid_grant", "token/client mismatch")
	}

	if _, err := a.db.Exec(`UPDATE oauth_tokens SET revoked_at = ? WHERE token = ?`, nowMs(), in.RefreshToken); err != nil {
		return nil, err
	}
	return a.mintTokens(clientID, githubID, scope.String)
}

func (a *App) mintTokens(clientID, githubID, scope string) (*IssuedTokens, error) {
	access := genID("at")
	refresh := genID("rt")
	now := nowMs()
	if _, err := a.db.Exec(
		`INSERT INTO oauth_tokens(token, kind, client_id, github_id, scope, expires_at) VALUES (?,?,?,?,?,?)`,
		access, "access", clientID, githubID, nullStr(scope), now+accessTTLMs,
	); err != nil {
		return nil, err
	}
	if _, err := a.db.Exec(
		`INSERT INTO oauth_tokens(token, kind, client_id, github_id, scope, expires_at) VALUES (?,?,?,?,?,?)`,
		refresh, "refresh", clientID, githubID, nullStr(scope), now+refreshTTLMs,
	); err != nil {
		return nil, err
	}
	if scope == "" {
		scope = defaultScope
	}
	return &IssuedTokens{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    accessTTLMs / 1000,
		RefreshToken: refresh,
		Scope:        scope,
	}, nil
}

type accessInfo struct {
	GitHubID string
	ClientID string
	Scope    string
}

func (a *App) resolveAccessToken(token string) (*accessInfo, error) {
	var (
		info    accessInfo
		scope   sql.NullString
		expires int64
		revoked sql.NullInt64
	)
	err := a.db.QueryRow(
		`SELECT github_id, client_id, scope, expires_at, revoked_at
		 FROM oauth_tokens WHERE token = ? AND kind = 'access'`, token,
	).Scan(&info.GitHubID, &info.ClientID, &scope, &expires, &revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if revoked.Valid || expires < nowMs() {
		return nil, nil
	}
	info.Scope = scope.String
	return &info, nil
}

type connectedClient struct {
	ClientID   string
	ClientName string
	LastSeen   int64
}

func (a *App) listConnectedClients(githubID string) ([]connectedClient, error) {
	rows, err := a.db.Query(
		`SELECT t.client_id, COALESCE(c.client_name, ''), MAX(t.expires_at)
		 FROM oauth_tokens t LEFT JOIN oauth_clients c ON c.client_id = t.client_id
		 WHERE t.github_id = ? AND t.revoked_at IS NULL AND t.expires_at > ?
		 GROUP BY t.client_id
		 ORDER BY MAX(t.expires_at) DESC`, githubID, nowMs(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connectedClient
	for rows.Next() {
		var c connectedClient
		if err := rows.Scan(&c.ClientID, &c.ClientName, &c.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (a *App) revokeClient(githubID, clientID string) error {
	if _, err := a.db.Exec(
		`UPDATE oauth_tokens SET revoked_at = ? WHERE github_id = ? AND client_id = ? AND revoked_at IS NULL`,
		nowMs(), githubID, clientID,
	); err != nil {
		return err
	}
	_, _ = a.db.Exec(`DELETE FROM oauth_codes WHERE github_id = ? AND client_id = ?`, githubID, clientID)
	return nil
}

func verifyPKCE(challenge, method, verifier string) bool {
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func scopeIsSupported(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if !contains(supportedScopes, s) {
			return false
		}
	}
	return true
}

func validateRedirectURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" {
		return newHTTPError(400, "invalid_redirect_uri", "not a URL: "+uri)
	}
	if parsed.Scheme == "http" {
		h := parsed.Hostname()
		if h != "localhost" && h != "127.0.0.1" {
			return newHTTPError(400, "invalid_redirect_uri", "http redirect URIs must use localhost/127.0.0.1")
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
