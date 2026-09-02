package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Team membership looked up at ZITADEL at request time, instead of trusting
// whatever the ID token said at login.
//
// Why: an MCP token lives for a long time and refreshes itself; anything baked
// into it at login is stale by construction. A person who left a class would
// keep reading that class's surveys until the token finally dies, and a newly
// granted role would not arrive at all. ZITADEL runs next door, the lookup
// costs milliseconds, and a survey tool sees a handful of calls per hour — so
// ask every time (memoised for a few seconds), and DENY when ZITADEL does not
// answer. This mirrors the class sites' `svc-grants-reader` pattern.
//
// One configured project per team: ZITADEL_TEAM_PROJECTS="<projectId>=<slug>,…".
// The grants are fetched per project (projectIdQuery) and filtered by user in
// memory — a userIdQuery was measured to return nothing on the instance this
// was written for, so it is deliberately not used.

type zitadelGrants struct {
	issuer   string
	orgID    string
	token    string
	projects map[string]string // projectId -> team slug
	roleKey  string            // role that makes a member a maintainer
	http     *http.Client

	mu    sync.Mutex
	cache map[string]grantsCache // projectId -> rows
}

type grantsCache struct {
	at   time.Time
	rows []grantRow
}

type grantRow struct {
	UserID   string   `json:"userId"`
	RoleKeys []string `json:"roleKeys"`
	State    string   `json:"state"`
}

const grantsCacheTTL = 5 * time.Second

func newZitadelGrants(cfg Config, client *http.Client) *zitadelGrants {
	if cfg.ZitadelServiceToken == "" || len(cfg.ZitadelTeamProjects) == 0 {
		return nil
	}
	return &zitadelGrants{
		issuer:   strings.TrimRight(cfg.OIDCIssuer, "/"),
		orgID:    cfg.ZitadelOrgID,
		token:    cfg.ZitadelServiceToken,
		projects: cfg.ZitadelTeamProjects,
		roleKey:  cfg.ZitadelMaintainerRole,
		http:     client,
		cache:    map[string]grantsCache{},
	}
}

// teamsFor returns the user's teams from live grants. An error means
// "could not verify" and must be treated as "no access".
func (z *zitadelGrants) teamsFor(userID string) ([]teamMembership, error) {
	var out []teamMembership
	ids := make([]string, 0, len(z.projects))
	for id := range z.projects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, pid := range ids {
		rows, err := z.projectGrants(pid)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.UserID != userID || (r.State != "" && r.State != "USER_GRANT_STATE_ACTIVE") {
				continue
			}
			m := teamMembership{Slug: z.projects[pid]}
			for _, k := range r.RoleKeys {
				if k == z.roleKey {
					m.IsMaintainer = true
				}
			}
			out = append(out, m)
			break
		}
	}
	return out, nil
}

func (z *zitadelGrants) projectGrants(projectID string) ([]grantRow, error) {
	z.mu.Lock()
	if c, ok := z.cache[projectID]; ok && time.Since(c.at) < grantsCacheTTL {
		z.mu.Unlock()
		return c.rows, nil
	}
	z.mu.Unlock()

	body, _ := json.Marshal(map[string]any{
		"query":   map[string]any{"limit": 1000},
		"queries": []map[string]any{{"projectIdQuery": map[string]any{"projectId": projectID}}},
	})
	req, err := http.NewRequest("POST", z.issuer+"/management/v1/users/grants/_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+z.token)
	req.Header.Set("x-zitadel-orgid", z.orgID)
	req.Header.Set("Content-Type", "application/json")
	res, err := z.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("zitadel grants: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("zitadel grants: %d %s", res.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	var parsed struct {
		Result []grantRow `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("zitadel grants decode: %w", err)
	}
	z.mu.Lock()
	z.cache[projectID] = grantsCache{at: time.Now(), rows: parsed.Result}
	z.mu.Unlock()
	return parsed.Result, nil
}

// parseTeamProjects parses "id=slug,id=slug".
func parseTeamProjects(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out
}
