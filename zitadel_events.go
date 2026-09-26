package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ZITADEL Actions v2 webhook (POST /login/zitadel-events): account, grant and
// session events end or refresh the affected provider sessions at once —
// the cases that do not produce a back-channel logout. Every call is signed
// (ZITADEL-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>">).

const webhookSignatureTolerance = 300 * time.Second

func verifyWebhookSignature(body []byte, header, key string, now time.Time) (bool, string) {
	if header == "" {
		return false, "missing"
	}
	var ts int64 = -1
	var sigs [][]byte
	for _, pair := range strings.Split(header, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || strings.Contains(value, "=") {
			return false, "malformed"
		}
		switch name {
		case "t":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return false, "malformed"
			}
			ts = n
		case "v1":
			if b, err := hex.DecodeString(value); err == nil {
				sigs = append(sigs, b)
			}
		}
	}
	if ts < 0 || len(sigs) == 0 {
		return false, "malformed"
	}
	if d := now.Sub(time.Unix(ts, 0)); d > webhookSignatureTolerance || d < -webhookSignatureTolerance {
		return false, "expired"
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	for _, s := range sigs {
		if hmac.Equal(s, want) {
			return true, ""
		}
	}
	return false, "mismatch"
}

type zitadelEvent struct {
	AggregateID      string          `json:"aggregateID"`
	EventTypeSnake   string          `json:"event_type"`
	EventTypeCamel   string          `json:"eventType"`
	EventPayloadSnk  json.RawMessage `json:"event_payload"`
	EventPayloadCaml json.RawMessage `json:"eventPayload"`
}

func (e zitadelEvent) eventType() string {
	if e.EventTypeSnake != "" {
		return e.EventTypeSnake
	}
	return e.EventTypeCamel
}

func (e zitadelEvent) payload() map[string]any {
	for _, raw := range []json.RawMessage{e.EventPayloadSnk, e.EventPayloadCaml} {
		var m map[string]any
		if len(raw) > 0 && json.Unmarshal(raw, &m) == nil && m != nil {
			return m
		}
	}
	return map[string]any{}
}

type eventOutcome struct {
	Action    string `json:"action"`
	Sub       string `json:"sub,omitempty"`
	Sessions  int    `json:"sessions"`
	EventType string `json:"eventType,omitempty"`
}

var (
	accountEvents     = set("user.locked", "user.deactivated", "user.removed")
	userTokenEvents   = set("user.token.removed", "user.human.signed.out", "user.human.refresh.token.removed")
	oidcSessionEvents = set("oidc_session.access_token.revoked", "oidc_session.refresh_token.revoked")
	revokeGrantEvents = set("user.grant.removed", "user.grant.cascade.removed", "user.grant.deactivated")
	// Changed roles need no new login: the forced refresh re-reads them.
	refreshGrantEvents = set("user.grant.changed", "user.grant.cascade.changed", "user.grant.added", "user.grant.reactivated")
)

func set(values ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range values {
		m[v] = true
	}
	return m
}

func (a *App) handleZitadelEvent(ev zitadelEvent) eventOutcome {
	typ := ev.eventType()
	agg := strings.TrimSpace(ev.AggregateID)
	p := ev.payload()
	str := func(k string) string { s, _ := p[k].(string); return s }
	ignored := eventOutcome{Action: "ignored", EventType: typ}

	switch {
	case accountEvents[typ] && agg != "":
		return eventOutcome{Action: "revoke_user", Sub: agg, Sessions: a.endIdpSessions(typ, `github_id = ?`, agg)}
	case userTokenEvents[typ] && agg != "":
		return eventOutcome{Action: "revoke_sessions", Sub: agg, Sessions: a.endIdpSessions(typ, `github_id = ?`, agg)}
	case typ == "session.terminated" && agg != "":
		var sub string
		if a.db.QueryRow(`SELECT github_id FROM idp_sessions WHERE sid = ? LIMIT 1`, agg).Scan(&sub) != nil {
			return ignored
		}
		return eventOutcome{Action: "revoke_sessions", Sub: sub, Sessions: a.endIdpSessions(typ, `sid = ?`, agg)}
	case oidcSessionEvents[typ]:
		// These events name only ZITADEL's internal OIDC session; a forced refresh fails for exactly the revoked tokens.
		return eventOutcome{Action: "refresh_all", Sessions: a.forceRefresh(`1 = 1`)}
	case strings.HasPrefix(typ, "user.grant."):
		if project := str("projectId"); project != "" && len(a.cfg.ZitadelTeamProjects) > 0 {
			if _, ours := a.cfg.ZitadelTeamProjects[project]; !ours {
				return ignored
			}
		}
		user := str("userId")
		switch {
		case revokeGrantEvents[typ] && user != "":
			return eventOutcome{Action: "revoke_user", Sub: user, Sessions: a.endIdpSessions(typ, `github_id = ?`, user)}
		case refreshGrantEvents[typ] && user != "":
			return eventOutcome{Action: "refresh_user", Sub: user, Sessions: a.forceRefresh(`github_id = ?`, user)}
		case revokeGrantEvents[typ] || refreshGrantEvents[typ]:
			// Deactivated/cascade grant events carry no userId; refreshing everyone re-reads the roles on the next request.
			return eventOutcome{Action: "refresh_all", Sessions: a.forceRefresh(`1 = 1`)}
		}
	}
	if typ == "" {
		ignored.EventType = "(empty)"
	}
	return ignored
}

func (a *App) handleZitadelWebhook(w http.ResponseWriter, r *http.Request) {
	if a.cfg.WebhookSigningKey == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeJSON(w, 413, map[string]string{"error": "body_too_large"})
		return
	}
	if ok, reason := verifyWebhookSignature(body, r.Header.Get("ZITADEL-Signature"), a.cfg.WebhookSigningKey, time.Now()); !ok {
		logJSON("warn", "zitadel event rejected", map[string]any{"reason": reason})
		writeJSON(w, 401, map[string]string{"error": "invalid_signature", "reason": reason})
		return
	}
	var ev zitadelEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_json"})
		return
	}
	out := a.handleZitadelEvent(ev)
	if out.Action != "ignored" {
		logJSON("info", "zitadel event", map[string]any{"event": ev.eventType(), "action": out.Action, "sub": out.Sub, "sessions": out.Sessions})
	}
	writeJSON(w, 200, out)
}
