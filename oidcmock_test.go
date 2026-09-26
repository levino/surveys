package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// An in-process OIDC provider that behaves like ZITADEL where it matters:
// RS256-signed ID tokens with kid, PKCE S256, nonce, sid, rotating refresh
// tokens, project role claims only for projects requested via the :aud scope,
// userinfo, and signed back-channel logout tokens.

const mockClientID = "surveys-client"

type mockUser struct {
	sub     string
	name    string
	groups  []string
	roles   map[string][]string // projectId -> role keys
	blocked bool
}

type mockCode struct {
	sub, nonce, challenge, scope string
	sid                          string
}

type oidcMock struct {
	URL string
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	mu             sync.Mutex
	users          map[string]*mockUser
	codes          map[string]mockCode
	refresh        map[string]mockCode // refresh token -> grant
	access         map[string]mockCode // access token -> grant
	down           bool
	noRolesInToken bool // like ZITADEL without "User roles inside ID Token"
	badNonce       bool // return a wrong nonce
	signWith       *rsa.PrivateKey
	audOverride    string // mint ID tokens for another audience
	refreshCalls   int
	userinfoCalls  int

	expiresIn  int            // expires_in of access tokens; 0 = omitted
	sessionTag string         // appended to the sid of the next logins (another device)
	clientPub  *rsa.PublicKey // accepts private_key_jwt signed by this key (kid mockAppKeyID)
	lastAuth   string         // "basic" or "private_key_jwt" of the last client-authenticated call
	revoked    []string       // tokens revoked via /revoke
}

const mockAppKeyID = "app-key-1"

func newOIDCMock(t *testing.T, users ...mockUser) *oidcMock {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &oidcMock{key: key, kid: "k1", users: map[string]*mockUser{}, codes: map[string]mockCode{},
		refresh: map[string]mockCode{}, access: map[string]mockCode{}, expiresIn: 3600}
	for i := range users {
		u := users[i]
		m.users[u.sub] = &u
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                 m.URL,
			"authorization_endpoint": m.URL + "/auth",
			"token_endpoint":         m.URL + "/token",
			"jwks_uri":               m.URL + "/keys",
			"userinfo_endpoint":      m.URL + "/userinfo",
			"revocation_endpoint":    m.URL + "/revoke",
			"end_session_endpoint":   m.URL + "/end_session",
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(m.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", m.token)
	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.down {
			w.WriteHeader(503)
			return
		}
		_ = r.ParseForm()
		if !m.clientAuthenticated(r) {
			writeJSON(w, 401, map[string]string{"error": "invalid_client"})
			return
		}
		tok := r.PostForm.Get("token")
		delete(m.refresh, tok)
		m.revoked = append(m.revoked, tok)
		w.WriteHeader(200)
	})
	mux.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.userinfoCalls++
		g, ok := m.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if !ok {
			w.WriteHeader(401)
			return
		}
		writeJSON(w, 200, m.claimsFor(g, true))
	})
	m.srv = httptest.NewServer(mux)
	m.URL = m.srv.URL
	t.Cleanup(m.srv.Close)
	return m
}

func (m *oidcMock) setUser(sub string, f func(u *mockUser)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m.users[sub])
}

func (m *oidcMock) set(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f()
}

// authorize plays the browser + login page: validates what the app put in
// the authorization URL and hands out a code for sub.
func (m *oidcMock) authorize(t *testing.T, authURL, sub string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorization URL lacks PKCE/nonce/state: %s", authURL)
	}
	if q.Get("client_id") != mockClientID {
		t.Fatalf("client_id %q", q.Get("client_id"))
	}
	code := "code-" + randomToken()
	m.mu.Lock()
	m.codes[code] = mockCode{sub: sub, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), scope: q.Get("scope"), sid: "sid-" + sub + m.sessionTag}
	m.mu.Unlock()
	return code
}

// login runs the whole browser login for sub against app.
func (m *oidcMock) login(t *testing.T, app *App, sub string) (*User, string, error) {
	t.Helper()
	att := newLoginAttempt("/")
	authURL, err := app.oidcAuthCodeURL(att)
	if err != nil {
		t.Fatal(err)
	}
	return app.loginViaOIDC(m.authorize(t, authURL, sub), att, "agent")
}

func (m *oidcMock) token(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.down {
		w.WriteHeader(503)
		return
	}
	_ = r.ParseForm()
	if !m.clientAuthenticated(r) {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	var g mockCode
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		c, ok := m.codes[r.PostForm.Get("code")]
		delete(m.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		g = c
	case "refresh_token":
		m.refreshCalls++
		c, ok := m.refresh[r.PostForm.Get("refresh_token")]
		delete(m.refresh, r.PostForm.Get("refresh_token")) // rotation
		if !ok || m.users[c.sub] == nil || m.users[c.sub].blocked {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		c.nonce = ""
		g = c
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if u := m.users[g.sub]; u == nil || u.blocked {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	at, rt := "at-"+randomToken(), "rt-"+randomToken()
	m.access[at] = g
	m.refresh[rt] = g
	claims := m.claimsFor(g, !m.noRolesInToken)
	aud := []string{mockClientID}
	for _, s := range strings.Fields(g.scope) {
		if strings.HasPrefix(s, "urn:zitadel:iam:org:project:id:") && strings.HasSuffix(s, ":aud") {
			aud = append(aud, strings.TrimSuffix(strings.TrimPrefix(s, "urn:zitadel:iam:org:project:id:"), ":aud"))
		}
	}
	if m.audOverride != "" {
		aud = []string{m.audOverride}
	}
	claims["iss"] = m.URL
	claims["aud"] = aud
	claims["azp"] = mockClientID
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	claims["sid"] = g.sid
	if g.nonce != "" {
		claims["nonce"] = g.nonce
		if m.badNonce {
			claims["nonce"] = "other"
		}
	}
	key := m.key
	if m.signWith != nil {
		key = m.signWith
	}
	resp := map[string]any{
		"access_token": at, "token_type": "Bearer",
		"refresh_token": rt, "id_token": signRS256(key, m.kid, claims),
	}
	if m.expiresIn > 0 {
		resp["expires_in"] = m.expiresIn
	}
	writeJSON(w, 200, resp)
}

// clientAuthenticated: client_secret_basic with "secret", or — when
// clientPub is set — a private_key_jwt assertion checked like ZITADEL does.
func (m *oidcMock) clientAuthenticated(r *http.Request) bool {
	if id, secret, ok := r.BasicAuth(); ok {
		m.lastAuth = "basic"
		return id == mockClientID && secret == "secret"
	}
	if m.clientPub == nil || r.PostForm.Get("client_assertion_type") != clientAssertionType || r.PostForm.Get("client_id") != mockClientID {
		return false
	}
	parts := strings.Split(r.PostForm.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return false
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	var hdr struct{ Alg, Kid string }
	var c struct {
		Iss, Sub, Aud, Jti string
		Iat, Exp           int64
	}
	if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &c) != nil || hdr.Alg != "RS256" || hdr.Kid != mockAppKeyID {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(m.clientPub, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	now := time.Now().Unix()
	if c.Iss != mockClientID || c.Sub != mockClientID || c.Aud != m.URL || c.Jti == "" || c.Exp < now || c.Exp-c.Iat > 3600 {
		return false
	}
	m.lastAuth = "private_key_jwt"
	return true
}

// claimsFor: sub/name, groups, and ZITADEL role claims for the projects the
// grant's scope put into the audience (only with projects:roles).
func (m *oidcMock) claimsFor(g mockCode, withRoles bool) map[string]any {
	u := m.users[g.sub]
	c := map[string]any{"sub": u.sub, "name": u.name}
	if u.groups != nil {
		c["groups"] = u.groups
	}
	if withRoles && strings.Contains(g.scope, zitadelScopeProjectsRoles) {
		for pid, roles := range u.roles {
			if !strings.Contains(g.scope, zitadelAudScope(pid)) || len(roles) == 0 {
				continue
			}
			obj := map[string]any{}
			for _, r := range roles {
				obj[r] = map[string]string{"org1": "org1.example"}
			}
			c[zitadelRolesClaim(pid)] = obj
		}
	}
	return c
}

func (m *oidcMock) logoutToken(overrides map[string]any) string {
	c := map[string]any{
		"iss": m.URL, "aud": mockClientID, "iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
		"jti":    randomToken(),
		"events": map[string]any{backchannelLogoutEvent: map[string]any{}},
	}
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return signRS256(m.key, m.kid, c)
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	body, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(fmt.Sprintf("sign: %v", err))
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}
