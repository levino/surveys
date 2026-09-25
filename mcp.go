package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
)

const mcpProtocolVersion = "2025-06-18"

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func jsonRPCResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "result": result}
}

func jsonRPCError(id json.RawMessage, code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "error": map[string]any{"code": code, "message": message}}
}

func rawOrNull(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	return id
}

var bearerRe = regexp.MustCompile(`^Bearer\s+(\S+)$`)

func (a *App) wwwAuthenticate(w http.ResponseWriter) {
	// The 401 + this header is the whole protocol signal that makes Claude show
	// its Connect card and start OAuth; scope tells it what to ask for.
	w.Header().Set("WWW-Authenticate",
		`Bearer error="invalid_token", error_description="Authentication required", `+
			`resource_metadata="`+a.cfg.BaseURL+`/.well-known/oauth-protected-resource/mcp", `+
			`scope="`+defaultScope+`"`)
}

func (a *App) mountMcp(mux *http.ServeMux) {
	mux.HandleFunc("OPTIONS /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		if _, err := a.bearerContext(r); err != nil {
			if errors.Is(err, errIdPUnavailable) {
				http.Error(w, "identity provider unavailable", 503)
				return
			}
			a.wwwAuthenticate(w)
			http.Error(w, "missing or invalid token", 401)
			return
		}
		http.Error(w, "Method Not Allowed", 405)
	})

	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ctx, err := a.bearerContext(r)
		if errors.Is(err, errIdPUnavailable) {
			// Fail closed, but do not make the client throw its token away.
			w.Header().Set("Retry-After", "30")
			writeJSON(w, 503, jsonRPCError(nil, -32002, "identity provider unavailable, retry later"))
			return
		}
		if err != nil {
			a.wwwAuthenticate(w)
			writeJSON(w, 401, jsonRPCError(nil, -32001, "missing or invalid token"))
			return
		}

		raw, _ := io.ReadAll(r.Body)
		var req jsonRPCRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSON(w, 400, jsonRPCError(nil, -32700, "parse error"))
			return
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			writeJSON(w, 200, jsonRPCError(req.ID, -32600, "invalid request"))
			return
		}

		result, rpcErr := a.dispatchRPC(&req, ctx)
		if rpcErr != nil {
			writeJSON(w, 200, jsonRPCError(req.ID, rpcErr.code, rpcErr.message))
			return
		}

		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, 200, jsonRPCResult(req.ID, result))
	})
}

type rpcError struct {
	code    int
	message string
}

func (a *App) dispatchRPC(req *jsonRPCRequest, ctx *AuthContext) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "surveys", "version": "0.1.0"},
		}, nil
	case "notifications/initialized":
		return nil, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolDefs()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.Name == "" {
			return nil, &rpcError{-32602, "tools/call requires name"}
		}
		return a.dispatchTool(p.Name, p.Arguments, ctx), nil
	default:
		return nil, &rpcError{-32601, "unknown method: " + req.Method}
	}
}

// bearerContext resolves the MCP access token and runs the same freshness
// check as a browser session: tokens older than the refresh interval are
// refreshed at the provider (teams re-derived) before the call proceeds.
// errIdPUnavailable = provider down (deny, keep token); any other error =
// unauthenticated.
func (a *App) bearerContext(r *http.Request) (*AuthContext, error) {
	m := bearerRe.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return nil, errSessionEnded
	}
	info, err := a.resolveAccessToken(m[1])
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, errSessionEnded
	}
	ctx, err := a.contextForIdpSession(info.IdpSessionID)
	if err != nil {
		return nil, err
	}
	if ctx.User.GitHubID != info.GitHubID {
		return nil, errSessionEnded
	}
	return ctx, nil
}
