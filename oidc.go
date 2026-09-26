package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Login and token refresh against the upstream OIDC provider (authorization
// code flow with PKCE S256 and nonce). Every ID token is verified: signature
// via the provider's JWKS, iss, aud/azp, exp, iat and — at login — nonce.
// Team membership is derived from the user's own tokens (see zitadel.go for
// ZITADEL project roles, splitGroup for a plain `groups` claim); it is
// re-derived on every refresh.

type teamMembership struct {
	Slug         string `json:"slug"`
	IsMaintainer bool   `json:"is_maintainer"`
}

type oidcProvider struct {
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	Issuer      string `json:"issuer"`
	JWKSURL     string `json:"jwks_uri"`
	UserinfoURL string `json:"userinfo_endpoint"`
	RevokeURL   string `json:"revocation_endpoint"`
	EndSession  string `json:"end_session_endpoint"`

	jwks *jwksCache
}

func (a *App) ensureOIDC() (*oidcProvider, error) {
	a.oidcMu.Lock()
	defer a.oidcMu.Unlock()
	if a.oidc != nil {
		return a.oidc, nil
	}
	u := strings.TrimRight(a.cfg.OIDCIssuer, "/") + "/.well-known/openid-configuration"
	res, err := a.http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("oidc discovery: %d %s", res.StatusCode, string(raw))
	}
	var p oidcProvider
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("oidc discovery decode: %w", err)
	}
	if p.AuthURL == "" || p.TokenURL == "" || p.JWKSURL == "" {
		return nil, fmt.Errorf("oidc discovery: missing endpoints")
	}
	p.jwks = &jwksCache{url: p.JWKSURL}
	a.oidc = &p
	return a.oidc, nil
}

// loginAttempt is what the browser carries (HttpOnly cookie) from
// /login/start to /login/callback.
type loginAttempt struct {
	State    string `json:"s"`
	Next     string `json:"n"`
	Nonce    string `json:"o"`
	Verifier string `json:"v"`
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func newLoginAttempt(next string) loginAttempt {
	return loginAttempt{State: randomToken(), Next: next, Nonce: randomToken(), Verifier: randomToken()}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (a *App) oidcAuthCodeURL(att loginAttempt) (string, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.AuthURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", a.cfg.OIDCClientID)
	q.Set("redirect_uri", a.cfg.callbackURL())
	q.Set("response_type", "code")
	q.Set("scope", a.cfg.loginScopes())
	q.Set("state", att.State)
	q.Set("nonce", att.Nonce)
	q.Set("code_challenge", pkceChallenge(att.Verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// identity is what one token response tells us about the user.
type identity struct {
	Subject      string
	Name         string
	SID          string // provider session id (for back-channel logout)
	RefreshToken string
	// Seconds the access token lives (expires_in); 0 = not sent.
	ExpiresIn int64
	Teams     []teamMembership
}

// idpRejected: the provider answered and said no (invalid_grant & co.). The
// grant is dead — end the session. Anything else (network, 5xx) is
// transient: deny the current request but keep the session.
type idpRejected struct {
	status int
	code   string
	desc   string
}

func (e *idpRejected) Error() string {
	return fmt.Sprintf("oidc token endpoint: %d %s %s", e.status, e.code, e.desc)
}

func isIdPRejection(err error) bool {
	var r *idpRejected
	return errors.As(err, &r)
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	ErrDesc      string `json:"error_description"`
}

func (a *App) tokenRequest(form url.Values) (*tokenResponse, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return nil, err
	}
	res, err := a.postToIdP(p.TokenURL, form)
	if err != nil {
		return nil, fmt.Errorf("oidc token endpoint: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var tok tokenResponse
	_ = json.Unmarshal(raw, &tok)
	if res.StatusCode >= 400 && res.StatusCode < 500 {
		return nil, &idpRejected{status: res.StatusCode, code: tok.Error, desc: tok.ErrDesc}
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc token endpoint: %d %s", res.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	if tok.Error != "" {
		return nil, &idpRejected{status: res.StatusCode, code: tok.Error, desc: tok.ErrDesc}
	}
	return &tok, nil
}

// oidcExchange redeems the authorization code (with the PKCE verifier) and
// validates the ID token including the nonce of this login attempt.
func (a *App) oidcExchange(code string, att loginAttempt) (*identity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", a.cfg.callbackURL())
	form.Set("code_verifier", att.Verifier)
	tok, err := a.tokenRequest(form)
	if err != nil {
		return nil, err
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("oidc token exchange returned no id_token")
	}
	claims, err := a.validateIDToken(tok.IDToken)
	if err != nil {
		return nil, err
	}
	if att.Nonce == "" || claims.str("nonce") != att.Nonce {
		return nil, fmt.Errorf("oidc id_token nonce mismatch")
	}
	return a.identityFrom(claims, tok)
}

// oidcRefresh uses the stored refresh token. The subject must not change.
func (a *App) oidcRefresh(refreshToken, subject string) (*identity, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	tok, err := a.tokenRequest(form)
	if err != nil {
		return nil, err
	}
	var claims jwtClaims
	if tok.IDToken != "" {
		if claims, err = a.validateIDToken(tok.IDToken); err != nil {
			return nil, err
		}
	} else {
		// No new ID token: everything must come from userinfo.
		claims = jwtClaims{raw: map[string]json.RawMessage{}}
		b, _ := json.Marshal(subject)
		claims.raw["sub"] = b
	}
	if claims.str("sub") != subject {
		return nil, &idpRejected{status: 200, code: "subject_changed"}
	}
	id, err := a.identityFrom(claims, tok)
	if err != nil {
		return nil, err
	}
	if id.RefreshToken == "" {
		id.RefreshToken = refreshToken // no rotation
	}
	return id, nil
}

func (a *App) validateIDToken(raw string) (jwtClaims, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return jwtClaims{}, err
	}
	m, err := verifyJWT(raw, p.jwks, a.http)
	if err != nil {
		return jwtClaims{}, fmt.Errorf("oidc id_token: %w", err)
	}
	c := jwtClaims{raw: m}
	if err := c.checkIssAud(a.cfg.OIDCIssuer, a.cfg.OIDCClientID); err != nil {
		return jwtClaims{}, fmt.Errorf("oidc id_token: %w", err)
	}
	now := time.Now()
	exp, ok := c.num("exp")
	if !ok || time.Unix(exp, 0).Add(clockSkew).Before(now) {
		return jwtClaims{}, fmt.Errorf("oidc id_token expired")
	}
	if iat, ok := c.num("iat"); !ok || time.Unix(iat, 0).After(now.Add(clockSkew)) {
		return jwtClaims{}, fmt.Errorf("oidc id_token iat missing or in the future")
	}
	if c.str("sub") == "" {
		return jwtClaims{}, fmt.Errorf("oidc id_token has no subject")
	}
	return c, nil
}

// identityFrom derives the user and their teams from the ID token claims;
// when the ID token does not carry the team claims (e.g. ZITADEL without
// "User roles inside ID Token"), it asks the userinfo endpoint with the
// user's own access token.
func (a *App) identityFrom(c jwtClaims, tok *tokenResponse) (*identity, error) {
	id := &identity{
		Subject:      c.str("sub"),
		Name:         c.str("name"),
		SID:          c.str("sid"),
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
	}
	teams, asserted := a.teamsFromClaims(c.raw)
	if !asserted {
		ui, err := a.userinfo(tok.AccessToken)
		if err != nil {
			// Do not guess teams; a rejection ends the session, anything
			// else only denies this request.
			return nil, err
		}
		if ui != nil {
			if s := ui.str("sub"); s != id.Subject {
				return nil, &idpRejected{status: 200, code: "userinfo_subject_mismatch"}
			}
			teams, _ = a.teamsFromClaims(ui.raw)
			if id.Name == "" {
				id.Name = ui.str("name")
			}
		}
	}
	id.Teams = teams
	return id, nil
}

// userinfo returns nil, nil when the provider has no userinfo endpoint or
// no access token was issued.
func (a *App) userinfo(accessToken string) (*jwtClaims, error) {
	p, err := a.ensureOIDC()
	if err != nil {
		return nil, err
	}
	if p.UserinfoURL == "" || accessToken == "" {
		return nil, nil
	}
	req, err := http.NewRequest("GET", p.UserinfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return nil, &idpRejected{status: res.StatusCode, code: "userinfo"}
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("userinfo: %d", res.StatusCode)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("userinfo decode: %w", err)
	}
	return &jwtClaims{raw: m}, nil
}

// teamsFromClaims maps claims to teams. With ZITADEL_TEAM_PROJECTS the
// project role claims decide (zitadel.go); otherwise the `groups` claim.
// asserted=false means the claims say nothing about teams at all.
func (a *App) teamsFromClaims(claims map[string]json.RawMessage) ([]teamMembership, bool) {
	if len(a.cfg.ZitadelTeamProjects) > 0 {
		return zitadelTeams(claims, a.cfg.ZitadelTeamProjects, a.cfg.ZitadelMaintainerRole)
	}
	raw, ok := claims["groups"]
	if !ok {
		return nil, false
	}
	var groups []string
	_ = json.Unmarshal(raw, &groups)
	idx := map[string]int{}
	var out []teamMembership
	for _, g := range groups {
		slug, maintainer := a.cfg.splitGroup(g)
		if slug == "" {
			continue
		}
		if i, ok := idx[slug]; ok {
			out[i].IsMaintainer = out[i].IsMaintainer || maintainer
			continue
		}
		idx[slug] = len(out)
		out = append(out, teamMembership{Slug: slug, IsMaintainer: maintainer})
	}
	return out, true
}
