package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GET /health reports whether the login can work, loudly (503) when not.
// /healthz stays pure liveness: a provider outage must not make Kubernetes
// restart the pod.

const credentialCheckTTL = 5 * time.Minute

type credentialCheck struct {
	Status    string  `json:"status"` // ok | failing | not_configured
	CheckedAt *string `json:"checkedAt"`
	Error     *string `json:"error"`
}

type healthReport struct {
	Status string `json:"status"` // ok | degraded
	Auth   struct {
		ClientAuthentication string          `json:"clientAuthentication"`
		CredentialCheck      credentialCheck `json:"credentialCheck"`
	} `json:"auth"`
	Webhook           string `json:"webhook"`
	BackchannelLogout string `json:"backchannelLogout"`
}

type credentialCache struct {
	mu     sync.Mutex
	at     time.Time
	result credentialCheck
}

// checkCredentials proves the client credential against the provider without
// a user: revoking an unknown token needs client authentication, and RFC 7009
// answers 200 for tokens it does not know. Parallel callers share one check.
func (a *App) checkCredentials() credentialCheck {
	c := &a.credCheck
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && time.Since(c.at) < credentialCheckTTL {
		return c.result
	}
	c.result, c.at = a.probeCredentials(), time.Now()
	if c.result.Status == "failing" {
		logJSON("error", "client credential check failed", map[string]any{"err": *c.result.Error})
	}
	return c.result
}

func (a *App) probeCredentials() credentialCheck {
	now := time.Now().UTC().Format(time.RFC3339)
	fail := func(msg string) credentialCheck {
		return credentialCheck{Status: "failing", CheckedAt: &now, Error: &msg}
	}
	if a.cfg.clientAuthMethod() == "none" {
		return credentialCheck{Status: "not_configured"}
	}
	p, err := a.ensureOIDC()
	if err != nil {
		return fail(err.Error())
	}
	if p.RevokeURL == "" {
		return credentialCheck{Status: "not_configured", CheckedAt: &now}
	}
	res, err := a.postToIdP(p.RevokeURL, url.Values{"token": {"probe-" + randomToken()}, "token_type_hint": {"refresh_token"}})
	if err != nil {
		return fail(err.Error())
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode == 200 {
		return credentialCheck{Status: "ok", CheckedAt: &now}
	}
	var body struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	_ = json.Unmarshal(raw, &body)
	if res.StatusCode >= 500 || res.StatusCode == 401 || body.Error == "invalid_client" || body.Error == "unauthorized_client" {
		return fail(strings.TrimSpace(fmt.Sprintf("revocation endpoint: HTTP %d %s %s", res.StatusCode, body.Error, body.Desc)))
	}
	// Any other 4xx means the client was authenticated and only the dummy token was refused.
	return credentialCheck{Status: "ok", CheckedAt: &now}
}

func (a *App) health() healthReport {
	var r healthReport
	r.Auth.ClientAuthentication = a.cfg.clientAuthMethod()
	r.Auth.CredentialCheck = a.checkCredentials()
	r.Webhook = "not_configured"
	if a.cfg.WebhookSigningKey != "" {
		r.Webhook = "configured"
	}
	r.BackchannelLogout = "/login/backchannel-logout"
	r.Status = "ok"
	if r.Auth.ClientAuthentication == "none" ||
		r.Auth.CredentialCheck.Status == "failing" ||
		(len(a.cfg.ZitadelTeamProjects) > 0 && r.Webhook == "not_configured") {
		r.Status = "degraded"
	}
	return r
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	report := a.health()
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if report.Status != "ok" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, report)
}
