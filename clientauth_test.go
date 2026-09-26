package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// appKeyJSON builds the JSON ZITADEL hands out for an application key.
func appKeyJSON(t *testing.T, clientID string, pkcs8 bool) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	if pkcs8 {
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	raw, _ := json.Marshal(map[string]string{
		"type": "application", "keyId": mockAppKeyID, "key": string(pem.EncodeToMemory(block)),
		"appId": "app-1", "clientId": clientID,
	})
	return string(raw), k
}

// withClientKey switches app to private_key_jwt and makes the mock accept it.
func withClientKey(t *testing.T, app *App, oidc *oidcMock) {
	t.Helper()
	raw, k := appKeyJSON(t, mockClientID, false)
	if err := applyClientKey(&app.cfg, raw, ""); err != nil {
		t.Fatal(err)
	}
	oidc.set(func() { oidc.clientPub = &k.PublicKey })
}

func TestClientKeyConfig(t *testing.T) {
	good, _ := appKeyJSON(t, "client-1", true)
	cfg := Config{OIDCClientID: "surveys", OIDCClientSecret: "old"}
	if err := applyClientKey(&cfg, good, ""); err != nil {
		t.Fatalf("PKCS#8 key: %v", err)
	}
	if cfg.OIDCClientID != "client-1" || cfg.OIDCClientSecret != "" || cfg.clientAuthMethod() != "private_key_jwt" {
		t.Fatalf("the key must win over the secret and bring the client id: %+v", cfg)
	}
	if err := applyClientKey(&Config{}, good, "someone-else"); err == nil || !strings.Contains(err.Error(), "belongs to client client-1") {
		t.Fatalf("foreign key must be refused, got %v", err)
	}
	for name, raw := range map[string]string{
		"not json":   "{",
		"wrong type": `{"type":"serviceaccount","keyId":"k","key":"x","clientId":"c"}`,
		"incomplete": `{"type":"application","keyId":"k","clientId":"c"}`,
		"not pem":    `{"type":"application","keyId":"k","key":"nope","clientId":"c"}`,
	} {
		if err := applyClientKey(&Config{}, raw, ""); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
	}
	if err := applyClientKey(&cfg, "", ""); err != nil {
		t.Fatalf("no key is fine: %v", err)
	}
	if (Config{OIDCClientSecret: "s"}).clientAuthMethod() != "client_secret" || (Config{}).clientAuthMethod() != "none" {
		t.Fatalf("clientAuthMethod")
	}
}

// With a key, code exchange and refresh use private_key_jwt, not the secret.
func TestLoginWithPrivateKeyJWT(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	withClientKey(t, app, oidc)
	_, sid, err := oidc.login(t, app, "alice")
	if err != nil {
		t.Fatalf("login with key: %v", err)
	}
	if oidc.lastAuth != "private_key_jwt" {
		t.Fatalf("code exchange used %q", oidc.lastAuth)
	}
	makeStale(t, app)
	oidc.set(func() { oidc.lastAuth = "" })
	if ctx, err := app.resolveSession(sid); ctx == nil || err != nil || oidc.lastAuth != "private_key_jwt" {
		t.Fatalf("refresh with key: ctx=%v err=%v auth=%q", ctx, err, oidc.lastAuth)
	}
}

func TestRefreshFollowsExpiresIn(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	expiresAt := func() int64 {
		var v int64
		app.db.QueryRow(`SELECT access_expires_at FROM idp_sessions`).Scan(&v)
		return v
	}

	oidc.set(func() { oidc.expiresIn = 300 })
	_, sid, _ := oidc.login(t, app, "alice")
	if d := expiresAt() - nowMs(); d < 290_000 || d > 300_000 {
		t.Fatalf("access token lifetime must follow expires_in, got %d ms", d)
	}
	calls := oidc.refreshCalls
	app.resolveSession(sid)
	if oidc.refreshCalls != calls {
		t.Fatalf("valid access token must not refresh")
	}
	// inside the leeway before expiry: refresh
	app.db.Exec(`UPDATE idp_sessions SET access_expires_at = ?`, nowMs()+5_000)
	app.resolveSession(sid)
	if oidc.refreshCalls != calls+1 {
		t.Fatalf("expiring access token must refresh")
	}

	// long-lived tokens are capped by OIDC_REFRESH_INTERVAL, none sent = the interval
	for _, exp := range []int{86400, 0} {
		oidc.set(func() { oidc.expiresIn = exp })
		makeStale(t, app)
		app.resolveSession(sid)
		if d := expiresAt() - nowMs(); d < 590_000 || d > 600_000 {
			t.Fatalf("expires_in=%d: want the 10m interval, got %d ms", exp, d)
		}
	}
}

func signEvent(key, body string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(fmt.Sprintf("%d.%s", ts, body)))
	return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
}

func TestWebhookSignature(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"event_type":"user.locked"}`)
	good := signEvent("k", string(body), now.Unix())
	cases := map[string]struct {
		header, reason string
	}{
		"missing":   {"", "missing"},
		"malformed": {"garbage", "malformed"},
		"no v1":     {fmt.Sprintf("t=%d", now.Unix()), "malformed"},
		"expired":   {signEvent("k", string(body), now.Add(-10*time.Minute).Unix()), "expired"},
		"future":    {signEvent("k", string(body), now.Add(10*time.Minute).Unix()), "expired"},
		"wrong key": {signEvent("other", string(body), now.Unix()), "mismatch"},
	}
	for name, c := range cases {
		if ok, reason := verifyWebhookSignature(body, c.header, "k", now); ok || reason != c.reason {
			t.Fatalf("%s: ok=%v reason=%q", name, ok, reason)
		}
	}
	if ok, _ := verifyWebhookSignature(body, good, "k", now); !ok {
		t.Fatalf("good signature refused")
	}
	if ok, _ := verifyWebhookSignature(body, "v1=00,"+good, "k", now); !ok {
		t.Fatalf("one matching v1 among several must do")
	}
	if ok, _ := verifyWebhookSignature([]byte(`{"event_type":"user.removed"}`), good, "k", now); ok {
		t.Fatalf("changed body must not verify")
	}
}

func TestZitadelEvents(t *testing.T) {
	oidc := newOIDCMock(t,
		mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}},
		mockUser{sub: "bob", name: "Bob", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	send := func(body string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", ts.URL+"/login/zitadel-events", strings.NewReader(body))
		req.Header.Set("ZITADEL-Signature", signEvent("whk", body, time.Now().Unix()))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	if code, _ := send(`{"event_type":"user.locked","aggregateID":"alice"}`); code != 404 {
		t.Fatalf("without signing key the webhook must not exist, got %d", code)
	}
	app.cfg.WebhookSigningKey = "whk"

	// alice on two devices, bob on one
	_, aliceLaptop, _ := oidc.login(t, app, "alice")
	oidc.set(func() { oidc.sessionTag = "-phone" })
	_, alicePhone, _ := oidc.login(t, app, "alice")
	oidc.set(func() { oidc.sessionTag = "" })
	_, bobSid, _ := oidc.login(t, app, "bob")
	phoneTok := fullOAuthToken(t, ts, alicePhone)

	// wrong signature: 401, nothing ends
	req, _ := http.NewRequest("POST", ts.URL+"/login/zitadel-events", strings.NewReader(`{"event_type":"user.locked","aggregateID":"alice"}`))
	req.Header.Set("ZITADEL-Signature", signEvent("wrong", `{"event_type":"user.locked","aggregateID":"alice"}`, time.Now().Unix()))
	if res, _ := http.DefaultClient.Do(req); res.StatusCode != 401 {
		t.Fatalf("bad signature: want 401, got %d", res.StatusCode)
	}
	if ctx, _ := app.resolveSession(aliceLaptop); ctx == nil {
		t.Fatalf("a rejected event must not end anything")
	}

	// session.terminated ends only the device with that sid
	code, out := send(`{"event_type":"session.terminated","aggregateID":"sid-alice-phone"}`)
	if code != 200 || out["action"] != "revoke_sessions" || out["sessions"] != float64(1) || out["sub"] != "alice" {
		t.Fatalf("session.terminated: %d %v", code, out)
	}
	if ctx, _ := app.resolveSession(alicePhone); ctx != nil {
		t.Fatalf("the phone session must be gone")
	}
	if s := mcpStatus(t, ts, phoneTok); s != 401 {
		t.Fatalf("MCP token of the phone login must be dead, got %d", s)
	}
	if ctx, _ := app.resolveSession(aliceLaptop); ctx == nil {
		t.Fatalf("the laptop session must stay")
	}
	if _, out := send(`{"event_type":"session.terminated","aggregateID":"unknown"}`); out["action"] != "ignored" {
		t.Fatalf("unknown sid: %v", out)
	}

	// grant of a foreign project: ignored
	if _, out := send(`{"event_type":"user.grant.removed","aggregateID":"g1","event_payload":{"userId":"alice","projectId":"p-other"}}`); out["action"] != "ignored" {
		t.Fatalf("foreign project grant: %v", out)
	}
	// grant changed: forced refresh, session stays
	calls := oidc.refreshCalls
	if _, out := send(`{"eventType":"user.grant.changed","aggregateID":"g1","eventPayload":{"userId":"alice","projectId":"p-a"}}`); out["action"] != "refresh_user" || out["sessions"] != float64(1) {
		t.Fatalf("grant changed: %v", out)
	}
	if ctx, _ := app.resolveSession(aliceLaptop); ctx == nil || oidc.refreshCalls != calls+1 {
		t.Fatalf("grant change must refresh once and keep the session: ctx=%v refreshes=%d", ctx, oidc.refreshCalls-calls)
	}
	// grant deactivated without userId: everyone refreshes
	if _, out := send(`{"event_type":"user.grant.deactivated","aggregateID":"g1","event_payload":{"projectId":"p-a"}}`); out["action"] != "refresh_all" || out["sessions"] != float64(2) {
		t.Fatalf("grant deactivated: %v", out)
	}
	// grant removed with userId: that user's sessions end
	if _, out := send(`{"event_type":"user.grant.removed","aggregateID":"g1","event_payload":{"userId":"bob","projectId":"p-a"}}`); out["action"] != "revoke_user" || out["sessions"] != float64(1) {
		t.Fatalf("grant removed: %v", out)
	}
	if ctx, _ := app.resolveSession(bobSid); ctx != nil {
		t.Fatalf("bob's session must be gone")
	}

	// account locked: every session of the user ends, including MCP tokens
	laptopTok := fullOAuthToken(t, ts, aliceLaptop)
	if _, out := send(`{"event_type":"user.locked","aggregateID":"alice"}`); out["action"] != "revoke_user" || out["sessions"] != float64(1) {
		t.Fatalf("user.locked: %v", out)
	}
	if s := mcpStatus(t, ts, laptopTok); s != 401 {
		t.Fatalf("alice's MCP token must be dead, got %d", s)
	}
	if n := countRows(t, app, "idp_sessions"); n != 0 {
		t.Fatalf("provider sessions left: %d", n)
	}
	if _, out := send(`{"event_type":"org.added","aggregateID":"x"}`); out["action"] != "ignored" {
		t.Fatalf("unrelated event: %v", out)
	}
}

func TestLogoutEndsLoginAtProvider(t *testing.T) {
	oidc := newOIDCMock(t, mockUser{sub: "alice", name: "Alice", roles: map[string][]string{"p-a": {"mitglied"}}})
	app := newZitadelApp(t, oidc)
	withClientKey(t, app, oidc)
	ts := httptest.NewServer(app.routes())
	defer ts.Close()
	_, sid, _ := oidc.login(t, app, "alice")
	tok := fullOAuthToken(t, ts, sid)
	var rt string
	app.db.QueryRow(`SELECT refresh_token FROM idp_sessions`).Scan(&rt)

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("POST", ts.URL+"/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sid})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	if res.StatusCode != 302 || loc.Path != "/end_session" || loc.Query().Get("client_id") != mockClientID ||
		loc.Query().Get("post_logout_redirect_uri") != "http://localhost:8080/" {
		t.Fatalf("logout must continue at the provider: %d %s", res.StatusCode, loc)
	}
	if len(oidc.revoked) != 1 || oidc.revoked[0] != rt || oidc.lastAuth != "private_key_jwt" {
		t.Fatalf("refresh token must be revoked with client auth: %v %q", oidc.revoked, oidc.lastAuth)
	}
	if n := countRows(t, app, "idp_sessions") + countRows(t, app, "sessions"); n != 0 {
		t.Fatalf("sessions left: %d", n)
	}
	if s := mcpStatus(t, ts, tok); s != 401 {
		t.Fatalf("MCP token of the ended login must be dead, got %d", s)
	}
}

func TestHealth(t *testing.T) {
	get := func(app *App) (int, healthReport) {
		ts := httptest.NewServer(app.routes())
		defer ts.Close()
		res, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("health must not be cached")
		}
		var r healthReport
		json.NewDecoder(res.Body).Decode(&r)
		return res.StatusCode, r
	}

	oidc := newOIDCMock(t)
	app := newZitadelApp(t, oidc)
	app.cfg.WebhookSigningKey = "whk"
	withClientKey(t, app, oidc)
	code, r := get(app)
	if code != 200 || r.Status != "ok" || r.Auth.ClientAuthentication != "private_key_jwt" ||
		r.Auth.CredentialCheck.Status != "ok" || r.Webhook != "configured" || r.BackchannelLogout != "/login/backchannel-logout" {
		t.Fatalf("healthy: %d %+v", code, r)
	}

	// the key is no longer accepted: loud
	app = newZitadelApp(t, oidc)
	app.cfg.WebhookSigningKey = "whk"
	withClientKey(t, app, oidc)
	oidc.set(func() { oidc.clientPub = nil })
	if code, r := get(app); code != 503 || r.Auth.CredentialCheck.Status != "failing" || r.Auth.CredentialCheck.Error == nil {
		t.Fatalf("rejected key: %d %+v", code, r)
	}

	// secret still works during the transition
	app = newZitadelApp(t, oidc)
	app.cfg.WebhookSigningKey = "whk"
	if code, r := get(app); code != 200 || r.Auth.ClientAuthentication != "client_secret" {
		t.Fatalf("secret: %d %+v", code, r)
	}

	// ZITADEL teams without the webhook: sessions would outlive a lock, loud
	app = newZitadelApp(t, oidc)
	if code, r := get(app); code != 503 || r.Webhook != "not_configured" {
		t.Fatalf("webhook missing: %d %+v", code, r)
	}
	// generic provider without webhook is fine
	app = newTestApp(t, oidc)
	if code, _ := get(app); code != 200 {
		t.Fatalf("generic provider: %d", code)
	}

	// no client credential at all
	app = newTestApp(t, oidc)
	app.cfg.OIDCClientSecret = ""
	if code, r := get(app); code != 503 || r.Auth.ClientAuthentication != "none" {
		t.Fatalf("no credential: %d %+v", code, r)
	}

	// provider down: failing; the result is cached for a while
	app = newTestApp(t, oidc)
	oidc.set(func() { oidc.down = true })
	if code, r := get(app); code != 503 || r.Auth.CredentialCheck.Status != "failing" {
		t.Fatalf("provider down: %d %+v", code, r)
	}
	oidc.set(func() { oidc.down = false })
	if code, _ := get(app); code != 503 {
		t.Fatalf("the check result must be cached")
	}
	app.credCheck.at = time.Now().Add(-credentialFailureTTL - time.Second)
	if code, _ := get(app); code != 200 {
		t.Fatalf("a failure is re-checked after credentialFailureTTL")
	}
	oidc.set(func() { oidc.down = true })
	app.credCheck.at = time.Now().Add(-credentialFailureTTL - time.Second)
	if code, _ := get(app); code != 200 {
		t.Fatalf("a success stays valid for credentialCheckTTL")
	}
	oidc.set(func() { oidc.down = false })
}
