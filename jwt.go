package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Signature verification of the provider's JWTs (ID tokens, logout tokens)
// against its published JWKS. Standard library only: RS*, PS* and ES*.
// "none" and HMAC are refused — a token we cannot verify is no token.

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksCache struct {
	mu      sync.Mutex
	url     string
	keys    map[string]crypto.PublicKey // kid -> key
	anon    []crypto.PublicKey          // keys without kid
	fetched time.Time
}

// jwksMinRefetch bounds how often an unknown kid may trigger a refetch, so a
// flood of forged tokens cannot turn us into a JWKS amplifier.
const jwksMinRefetch = 30 * time.Second

func (c *jwksCache) key(client *http.Client, kid string) (crypto.PublicKey, []crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	lookup := func() (crypto.PublicKey, []crypto.PublicKey) {
		if kid != "" {
			if k, ok := c.keys[kid]; ok {
				return k, nil
			}
			return nil, nil
		}
		all := append([]crypto.PublicKey{}, c.anon...)
		for _, k := range c.keys {
			all = append(all, k)
		}
		return nil, all
	}
	if c.keys != nil {
		if k, all := lookup(); k != nil || len(all) > 0 {
			return k, all, nil
		}
		if time.Since(c.fetched) < jwksMinRefetch {
			return nil, nil, fmt.Errorf("jwks: unknown kid %q", kid)
		}
	}
	if err := c.refresh(client); err != nil {
		return nil, nil, err
	}
	k, all := lookup()
	if k == nil && len(all) == 0 {
		return nil, nil, fmt.Errorf("jwks: unknown kid %q", kid)
	}
	return k, all, nil
}

func (c *jwksCache) refresh(client *http.Client) error {
	if c.url == "" {
		return errors.New("jwks: provider publishes no jwks_uri")
	}
	res, err := client.Get(c.url)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return fmt.Errorf("jwks: %d", res.StatusCode)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("jwks decode: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	var anon []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		if k.Kid == "" {
			anon = append(anon, pub)
		} else {
			keys[k.Kid] = pub
		}
	}
	c.keys, c.anon, c.fetched = keys, anon, time.Now()
	return nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	}
	return nil, fmt.Errorf("unsupported kty %q", k.Kty)
}

// verifyJWT checks the compact JWS signature against the JWKS and returns
// the raw claims. Claim validation (iss, aud, exp, …) is up to the caller.
func verifyJWT(token string, keys *jwksCache, client *http.Client) (map[string]json.RawMessage, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("jwt header: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt signature: %w", err)
	}
	if _, err := hashFor(hdr.Alg); err != nil {
		return nil, err
	}
	key, candidates, err := keys.key(client, hdr.Kid)
	if err != nil {
		return nil, err
	}
	if key != nil {
		candidates = []crypto.PublicKey{key}
	}
	signed := []byte(parts[0] + "." + parts[1])
	ok := false
	for _, k := range candidates {
		if verifySig(hdr.Alg, k, signed, sig) == nil {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("jwt: signature invalid")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt payload: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, fmt.Errorf("jwt payload: %w", err)
	}
	return claims, nil
}

func hashFor(alg string) (crypto.Hash, error) {
	if len(alg) == 5 && (alg[:2] == "RS" || alg[:2] == "PS" || alg[:2] == "ES") {
		switch alg[2:] {
		case "256":
			return crypto.SHA256, nil
		case "384":
			return crypto.SHA384, nil
		case "512":
			return crypto.SHA512, nil
		}
	}
	return 0, fmt.Errorf("jwt: unsupported alg %q", alg)
}

func verifySig(alg string, key crypto.PublicKey, signed, sig []byte) error {
	h, err := hashFor(alg)
	if err != nil {
		return err
	}
	hh := h.New()
	hh.Write(signed)
	digest := hh.Sum(nil)
	switch alg[:2] {
	case "RS":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type")
		}
		return rsa.VerifyPKCS1v15(k, h, digest, sig)
	case "PS":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key type")
		}
		return rsa.VerifyPSS(k, h, digest, sig, nil)
	case "ES":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key type")
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("ecdsa signature length")
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("ecdsa verify")
		}
		return nil
	}
	return fmt.Errorf("jwt: unsupported alg %q", alg)
}

// jwtClaims is the typed view of the registered claims we validate.
type jwtClaims struct {
	raw map[string]json.RawMessage
}

func (c jwtClaims) str(name string) string {
	var s string
	if v, ok := c.raw[name]; ok {
		_ = json.Unmarshal(v, &s)
	}
	return s
}

func (c jwtClaims) num(name string) (int64, bool) {
	v, ok := c.raw[name]
	if !ok {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(v, &f); err != nil {
		return 0, false
	}
	return int64(f), true
}

func (c jwtClaims) has(name string) bool { _, ok := c.raw[name]; return ok }

// aud is a string or an array of strings.
func (c jwtClaims) aud() []string {
	v, ok := c.raw["aud"]
	if !ok {
		return nil
	}
	var one string
	if json.Unmarshal(v, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(v, &many)
	return many
}

// clockSkew tolerated on exp/iat.
const clockSkew = 2 * time.Minute

// checkIssAud validates iss (exact, modulo a trailing slash) and that the
// client id is among the audiences; with several audiences, azp (if sent)
// must be the client id (OIDC Core §3.1.3.7).
func (c jwtClaims) checkIssAud(issuer, clientID string) error {
	if strings.TrimRight(c.str("iss"), "/") != strings.TrimRight(issuer, "/") {
		return fmt.Errorf("iss mismatch: %q", c.str("iss"))
	}
	aud := c.aud()
	if !contains(aud, clientID) {
		return fmt.Errorf("aud does not contain client id")
	}
	if azp := c.str("azp"); azp != "" && azp != clientID {
		return fmt.Errorf("azp mismatch: %q", azp)
	}
	return nil
}
