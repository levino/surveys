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

A survey belongs to a **group/team** taken from the OIDC `groups` claim. Every
member of that team sees it and can read its results; **changing or deleting
it is reserved for whoever created it** — and for the team's *maintainers*,
if the provider marks any (see `OIDC_MAINTAINER_SUFFIX`). Nobody is a global
admin: a maintainer of one team sees nothing of another.

Surveys are meant to be short-lived. Each one carries an optional `delete_at`;
when it passes, the survey **and all its submissions** are purged
automatically (checked at start and hourly). `DEFAULT_RETENTION_DAYS` gives
new surveys a deletion date unless the creator sets one explicitly — set it
wherever data minimisation matters. The form description and
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
| `OIDC_MAINTAINER_SUFFIX` | `` (empty)           | A group ending in this suffix (e.g. `:admin`) makes the user a maintainer of the team named by the rest — maintainers may change/delete every survey of that team |
| `OIDC_SCOPES`         | `openid profile email groups` | Scopes requested at login. Drop `groups` when the claim is added by the provider itself (ZITADEL action) |
| `DEFAULT_RETENTION_DAYS` | `0`                  | New surveys get `delete_at = now + N days` unless set explicitly. `0` = keep until deleted by hand |
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

### ZITADEL without a `groups` scope

ZITADEL keeps project roles in a nested claim and an OIDC client only sees the
roles of *its own* project. To use one instance for several teams (e.g. one
school, classes as teams), add a ZITADEL **Action** on the *Complement Token*
flow (triggers *Pre Userinfo creation* + *Pre access token creation*) that
flattens the user's grants into `groups`, e.g. `["klasse-wiesen",
"klasse-wiesen:admin"]`, and run with `OIDC_SCOPES="openid profile email"`,
`OIDC_GROUP_PREFIX=""`, `OIDC_MAINTAINER_SUFFIX=":admin"`. The client needs
*ID token userinfo assertion* enabled so the claim lands in the ID token.

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
