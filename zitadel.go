package main

import (
	"encoding/json"
	"sort"
	"strings"
)

// Team membership from the user's own ZITADEL tokens.
//
// The app holds no ZITADEL credential of its own and has no org-wide read
// access. At login it asks for the reserved scopes
//
//	urn:zitadel:iam:org:projects:roles              -> assert roles of every project in the audience
//	urn:zitadel:iam:org:project:id:<projectId>:aud  -> put each team project into the audience
//
// and ZITADEL answers with one claim per project:
//
//	"urn:zitadel:iam:org:project:<projectId>:roles": {"<roleKey>": {"<orgId>": "<orgDomain>"}, …}
//
// (https://zitadel.com/docs/apis/openidoauth/scopes, …/claims). Any role in a
// configured project makes the user a member of that project's team; the
// configured maintainer role makes them a maintainer. The tokens are
// refreshed every OIDC_REFRESH_INTERVAL (default 10 min), so a revoked grant
// is gone within that window — or at once via back-channel logout.
//
// One configured project per team: ZITADEL_TEAM_PROJECTS="<projectId>=<slug>,…".

const (
	zitadelScopeProjectsRoles = "urn:zitadel:iam:org:projects:roles"
	zitadelRolesClaimPrefix   = "urn:zitadel:iam:org:project:"
)

func zitadelAudScope(projectID string) string {
	return "urn:zitadel:iam:org:project:id:" + projectID + ":aud"
}

func zitadelRolesClaim(projectID string) string {
	return zitadelRolesClaimPrefix + projectID + ":roles"
}

// zitadelTeams reads the per-project role claims. asserted reports whether
// ANY configured project claim was present — ZITADEL omits the claim for a
// project without roles, so all-absent can also mean "not asserted in this
// token" and is answered from userinfo.
func zitadelTeams(claims map[string]json.RawMessage, projects map[string]string, maintainerRole string) ([]teamMembership, bool) {
	ids := make([]string, 0, len(projects))
	for id := range projects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []teamMembership
	asserted := false
	for _, pid := range ids {
		raw, ok := claims[zitadelRolesClaim(pid)]
		if !ok {
			continue
		}
		asserted = true
		roles := roleKeys(raw)
		if len(roles) == 0 {
			continue
		}
		m := teamMembership{Slug: projects[pid]}
		for _, r := range roles {
			if r == maintainerRole {
				m.IsMaintainer = true
			}
		}
		out = append(out, m)
	}
	return out, asserted
}

// roleKeys accepts the object form ZITADEL emits ({"role": {orgId: domain}})
// and, defensively, an array of such objects (as drawn in the docs example).
func roleKeys(raw json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		out := make([]string, 0, len(obj))
		for k := range obj {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	var arr []map[string]json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		seen := map[string]bool{}
		var out []string
		for _, o := range arr {
			for k := range o {
				if !seen[k] {
					seen[k] = true
					out = append(out, k)
				}
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
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
