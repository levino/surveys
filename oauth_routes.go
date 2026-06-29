package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/levino/surveys/ui"
)

const (
	pendingCookie = "surveys_oauth_pending"
	pendingTTLSec = 30 * 60
)

func (a *App) mountOauth(mux *http.ServeMux) {
	base := a.cfg.BaseURL

	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"resource":                 base + "/mcp",
			"authorization_servers":    []string{base},
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{"mcp"},
		})
	})

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/oauth/authorize",
			"token_endpoint":                        base + "/oauth/token",
			"registration_endpoint":                 base + "/oauth/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
			"scopes_supported":                      []string{"mcp"},
			"service_documentation":                 base + "/",
		})
	})

	mux.HandleFunc("POST /oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			RedirectURIs            []string `json:"redirect_uris"`
			ClientName              string   `json:"client_name"`
			TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
			GrantTypes              []string `json:"grant_types"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid_client_metadata", "error_description": "JSON body required"})
			return
		}
		client, err := a.registerClient(registerClientInput{
			RedirectURIs:            body.RedirectURIs,
			ClientName:              body.ClientName,
			TokenEndpointAuthMethod: body.TokenEndpointAuthMethod,
			GrantTypes:              body.GrantTypes,
		})
		if err != nil {
			writeOAuthError(w, err)
			return
		}
		resp := map[string]any{
			"client_id":                  client.ClientID,
			"client_name":                client.ClientName,
			"redirect_uris":              client.RedirectURIs,
			"grant_types":                client.GrantTypes,
			"token_endpoint_auth_method": client.TokenAuthMeth,
			"client_id_issued_at":        client.CreatedAt / 1000,
		}
		if client.ClientSecret != "" {
			resp["client_secret"] = client.ClientSecret
		}
		writeJSON(w, 201, resp)
	})

	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		pending, err := a.beginAuthz(beginAuthzInput{
			ClientID:            q.Get("client_id"),
			RedirectURI:         q.Get("redirect_uri"),
			ResponseType:        q.Get("response_type"),
			Scope:               q.Get("scope"),
			State:               q.Get("state"),
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			Resource:            q.Get("resource"),
		})
		if err != nil {
			if he, ok := err.(*httpError); ok {
				http.Error(w, he.code+": "+he.message, he.status)
				return
			}
			http.Error(w, err.Error(), 500)
			return
		}

		if auth, _ := a.resolveSession(cookieValue(r, sessionCookie)); auth != nil {
			a.renderConsent(w, r, pending.ID)
			return
		}

		a.setCookie(w, pendingCookie, pending.ID, pendingTTLSec)
		http.Redirect(w, r, "/login/start?next="+url.QueryEscape("/oauth/continue"), http.StatusFound)
	})

	mux.HandleFunc("GET /oauth/continue", func(w http.ResponseWriter, r *http.Request) {
		pendingID := cookieValue(r, pendingCookie)
		if pendingID == "" {
			http.Error(w, "no pending authorization", 400)
			return
		}
		auth, _ := a.resolveSession(cookieValue(r, sessionCookie))
		if auth == nil {
			http.Error(w, "not authenticated", 401)
			return
		}
		if req, _ := a.loadAuthzRequest(pendingID); req == nil {
			http.Error(w, "authorization expired", 400)
			return
		}
		a.deleteCookie(w, pendingCookie)
		a.renderConsent(w, r, pendingID)
	})

	mux.HandleFunc("POST /oauth/approve", func(w http.ResponseWriter, r *http.Request) {
		auth, _ := a.resolveSession(cookieValue(r, sessionCookie))
		if auth == nil {
			http.Error(w, "not authenticated", 401)
			return
		}
		_ = r.ParseForm()
		authzID := r.PostForm.Get("authz_id")
		if authzID == "" {
			http.Error(w, "missing authz_id", 400)
			return
		}
		a.finishAuthz(w, r, authzID, auth.User.GitHubID)
	})

	mux.HandleFunc("POST /oauth/deny", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		authzID := r.PostForm.Get("authz_id")
		req, _ := a.loadAuthzRequest(authzID)
		if req == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		_, _ = a.db.Exec(`DELETE FROM oauth_authz_requests WHERE id = ?`, authzID)
		u, err := url.Parse(req.RedirectURI)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		q := u.Query()
		q.Set("error", "access_denied")
		if req.State != "" {
			q.Set("state", req.State)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})

	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		form, err := parseTokenForm(r)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid_request", "error_description": err.Error()})
			return
		}
		switch form["grant_type"] {
		case "authorization_code":
			tokens, err := a.exchangeAuthorizationCode(exchangeCodeInput{
				ClientID:     form["client_id"],
				ClientSecret: form["client_secret"],
				Code:         form["code"],
				RedirectURI:  form["redirect_uri"],
				CodeVerifier: form["code_verifier"],
			})
			if err != nil {
				writeOAuthError(w, err)
				return
			}
			writeJSON(w, 200, tokens)
		case "refresh_token":
			tokens, err := a.exchangeRefreshToken(exchangeRefreshInput{
				ClientID:     form["client_id"],
				ClientSecret: form["client_secret"],
				RefreshToken: form["refresh_token"],
			})
			if err != nil {
				writeOAuthError(w, err)
				return
			}
			writeJSON(w, 200, tokens)
		default:
			writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type", "error_description": form["grant_type"]})
		}
	})
}

func (a *App) renderConsent(w http.ResponseWriter, r *http.Request, authzID string) {
	req, _ := a.loadAuthzRequest(authzID)
	if req == nil {
		http.Error(w, "authorization expired", 400)
		return
	}
	name := req.ClientID
	if client, _ := a.getClient(req.ClientID); client != nil && client.ClientName != "" {
		name = client.ClientName
	}
	scope := req.Scope
	if scope == "" {
		scope = defaultScope
	}
	a.renderPage(w, r, http.StatusOK, ui.Consent(ui.ConsentData{
		AppName: a.cfg.AppName, ClientName: name, AuthzID: authzID, Scope: scope,
	}))
}

func (a *App) finishAuthz(w http.ResponseWriter, r *http.Request, authzID, githubID string) {
	res, err := a.completeAuthz(authzID, githubID)
	if err != nil {
		if he, ok := err.(*httpError); ok {
			http.Error(w, he.code+": "+he.message, he.status)
			return
		}
		http.Error(w, err.Error(), 500)
		return
	}
	u, _ := url.Parse(res.RedirectURI)
	q := u.Query()
	q.Set("code", res.Code)
	if res.State != "" {
		q.Set("state", res.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func parseTokenForm(r *http.Request) (map[string]string, error) {
	ct := r.Header.Get("Content-Type")
	out := map[string]string{}
	switch {
	case contains2(ct, "application/x-www-form-urlencoded"):
		raw, _ := io.ReadAll(r.Body)
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			return nil, err
		}
		for k := range vals {
			out[k] = vals.Get(k)
		}
	case contains2(ct, "application/json"):
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			return nil, err
		}
	default:
		return nil, errUnsupportedContentType
	}
	return out, nil
}
