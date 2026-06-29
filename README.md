# surveys

A lean, self-hosted service for collecting form submissions — a "self-hosted
Google Forms". **One Go binary, one container, one embedded SQLite file.**

Two surfaces, nothing more:

1. **Public HTML forms** at `/f/{random-slug}` — anonymous, no login, `noindex`,
   honeypot + rate-limit. Validation runs in the browser (native HTML5
   constraints + inline per-field errors) **and** on the server.
2. **MCP endpoint** at `/mcp` — the *only* authenticated interface. All CRUD
   operations (create/edit surveys, read/export submissions) happen here, driven
   by an AI assistant such as Claude. **No REST API, no admin UI.**

A survey belongs to a **group/team** taken from the OIDC `groups` claim; only
members of that group can manage it and read results. The form description and
each field's `help` text support **Markdown**. A built-in usage guide is served
at `/docs`.

> License: MIT, © Levin Keller.

## Authentication

The service ships its own OAuth 2.0 server (so Claude can connect as a remote
MCP connector via dynamic client registration + PKCE) and delegates the actual
login to an upstream **OIDC** identity provider. Any provider that emits the
user's group/team membership as a `groups` claim works — e.g. **Zitadel**,
Keycloak, or dex federating to GitHub. To switch providers you only change
`OIDC_ISSUER` (and client id/secret).

The `groups` claim values may be namespaced (e.g. `myorg:marketing`).
`OIDC_GROUP_PREFIX` optionally strips that prefix so a survey's `owner_team` is
the bare slug.

## Configuration (env only, 12-factor)

| Variable              | Default                 | Purpose |
|-----------------------|-------------------------|---------|
| `PORT`                | `8080`                  | HTTP port |
| `DATABASE_PATH`       | `./data/app.db`         | SQLite file (WAL) |
| `PUBLIC_BASE_URL`     | `http://localhost:8080` | Absolute base URL (links, OAuth discovery) |
| `PUBLIC_APP_NAME`     | `Surveys`               | Display name in the HTML |
| `PUBLIC_THEME`        | `surveys`               | DaisyUI `data-theme` (see `tailwind.config.js`) |
| `OIDC_ISSUER`         | –                       | OIDC provider issuer URL (required) |
| `OIDC_CLIENT_ID`      | `surveys`               | OIDC client id |
| `OIDC_CLIENT_SECRET`  | –                       | OIDC client secret (required) |
| `OIDC_GROUP_PREFIX`   | `` (empty)              | Prefix stripped from `groups` to form the team slug |
| `SESSION_SECRET`      | –                       | Salt for IP hashing (GDPR) |

See `.env.example`.

## Run locally

```bash
go run .            # http://localhost:8080
go test ./...       # in-process OIDC mock, no real network calls
```

The CSS (`assets/app.css`) is built from Tailwind + DaisyUI and embedded into the
binary. The Docker build does this for you; for `go run .` locally, build it once:

```bash
npm ci && npm run build:css
```

## OIDC provider setup

Register a client at your provider:
- Client ID: `surveys`
- Redirect URI: `https://<host>/login/callback`
- Scopes: `openid profile email groups`

The `groups` claim must carry the user's team/group membership.

## MCP in Claude

Claude discovers the OAuth server via `/.well-known/oauth-protected-resource`
and `/.well-known/oauth-authorization-server`, registers dynamically (RFC 7591)
and runs a PKCE auth-code flow. Resource URL for Claude: `https://<host>/mcp`.

MCP tools: `list_teams`, `create_form`, `list_forms`, `get_form`, `update_form`,
`disable_form`, `delete_form`, `list_submissions`, `export_submissions`,
`delete_submission`.

## Build & deploy

A multi-stage `Dockerfile` builds the CSS, cross-compiles a static CGO-free
binary and ships it on `distroless/static`. The container exposes `8080` and
persists its SQLite file under the `/data` volume.

```bash
docker build -t surveys .
docker run -p 8080:8080 -v $PWD/data:/data --env-file .env surveys
```

## Backup / restore

The DB is a single file on a volume ⇒ backup = copy the file
(`sqlite3 app.db ".backup backup.db"` for a consistent snapshot under load).
