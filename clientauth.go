package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client authentication at the provider's token and revocation endpoints:
// private_key_jwt (RFC 7523) with a ZITADEL application key when
// OIDC_CLIENT_KEY is set, otherwise client_secret_basic.

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

const assertionLifetime = 60 * time.Second

type clientKey struct {
	KeyID    string
	ClientID string
	Private  *rsa.PrivateKey
}

// parseClientKey reads the JSON ZITADEL hands out for an application key:
// {"type":"application","keyId":…,"key":"-----BEGIN RSA PRIVATE KEY-----…","clientId":…}.
func parseClientKey(raw string) (*clientKey, error) {
	var k struct {
		Type     string `json:"type"`
		KeyID    string `json:"keyId"`
		Key      string `json:"key"`
		ClientID string `json:"clientId"`
	}
	if err := json.Unmarshal([]byte(raw), &k); err != nil {
		return nil, errors.New("OIDC_CLIENT_KEY is not JSON")
	}
	if k.Type != "application" {
		return nil, fmt.Errorf("OIDC_CLIENT_KEY has type %q, expected \"application\"", k.Type)
	}
	k.KeyID, k.ClientID = strings.TrimSpace(k.KeyID), strings.TrimSpace(k.ClientID)
	if k.KeyID == "" || k.ClientID == "" || strings.TrimSpace(k.Key) == "" {
		return nil, errors.New("OIDC_CLIENT_KEY incomplete: keyId, key and clientId are required")
	}
	block, _ := pem.Decode([]byte(k.Key))
	if block == nil {
		return nil, errors.New("OIDC_CLIENT_KEY: key is not PEM")
	}
	var priv *rsa.PrivateKey
	if p, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = p
	} else if p, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := p.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("OIDC_CLIENT_KEY: key is not RSA")
		}
		priv = rk
	} else {
		return nil, fmt.Errorf("OIDC_CLIENT_KEY: private key unreadable: %v", err)
	}
	return &clientKey{KeyID: k.KeyID, ClientID: k.ClientID, Private: priv}, nil
}

// applyClientKey parses OIDC_CLIENT_KEY into cfg. The key wins over
// OIDC_CLIENT_SECRET; the client id may come from the key alone.
func applyClientKey(cfg *Config, raw, explicitClientID string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	key, err := parseClientKey(raw)
	if err != nil {
		return err
	}
	if explicitClientID != "" && explicitClientID != key.ClientID {
		return fmt.Errorf("OIDC_CLIENT_KEY belongs to client %s, OIDC_CLIENT_ID is %s", key.ClientID, explicitClientID)
	}
	cfg.OIDCClientID = key.ClientID
	cfg.OIDCClientKey = key
	cfg.OIDCClientSecret = ""
	return nil
}

func (c Config) clientAuthMethod() string {
	switch {
	case c.OIDCClientKey != nil:
		return "private_key_jwt"
	case c.OIDCClientSecret != "":
		return "client_secret"
	}
	return "none"
}

func signClientAssertion(key *clientKey, audience string, now time.Time) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": key.KeyID})
	body, _ := json.Marshal(map[string]any{
		"iss": key.ClientID,
		"sub": key.ClientID,
		"aud": strings.TrimRight(audience, "/"),
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
		"jti": randomToken(),
	})
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.Private, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// postToIdP sends a form to one of the provider's client-authenticated
// endpoints (token, revocation).
func (a *App) postToIdP(endpoint string, form url.Values) (*http.Response, error) {
	body := url.Values{}
	for k, v := range form {
		body[k] = v
	}
	if a.cfg.OIDCClientKey != nil {
		assertion, err := signClientAssertion(a.cfg.OIDCClientKey, a.cfg.OIDCIssuer, time.Now())
		if err != nil {
			return nil, fmt.Errorf("client assertion: %w", err)
		}
		body.Set("client_id", a.cfg.OIDCClientID)
		body.Set("client_assertion_type", clientAssertionType)
		body.Set("client_assertion", assertion)
	}
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if a.cfg.OIDCClientKey == nil {
		// RFC 6749 §2.3.1: form-encode before Base64, or secrets with special characters fail.
		req.SetBasicAuth(url.QueryEscape(a.cfg.OIDCClientID), url.QueryEscape(a.cfg.OIDCClientSecret))
	}
	return a.http.Do(req)
}
