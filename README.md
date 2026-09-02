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

The service ships its own OAuth 2.1 authorization server for MCP clients and
delegates the actual login to an upstream **OIDC** identity provider (ZITADEL,
Keycloak, dex …). To switch providers you only change `OIDC_ISSUER` (and
client id/secret).

MCP clients identify themselves with a **Client ID Metadata Document**
([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document),
MCP spec 2025-11-25): the `client_id` *is* an https URL, and the JSON served
there says who the client is and where it may be redirected. The server
fetches it (no redirects, public hosts only, 16 KiB cap, cached per
`Cache-Control`), checks it is self-referential, and requires every
`redirect_uri` to be same-origin with the document or a loopback address.
There is **no dynamic client registration** and no client table to prune;
public clients with PKCE (S256) only. The last good document is kept for
seven days so a metadata-host outage does not break token refreshes.

Claude picks this mode by itself: the authorization-server metadata
advertises `client_id_metadata_document_supported: true` and `"none"` in
`token_endpoint_auth_methods_supported`, the `401` from `/mcp` carries
`WWW-Authenticate: Bearer … resource_metadata=… scope="mcp"`, and the
protected-resource metadata is served at both `/.well-known/oauth-protected-resource`
and `…/mcp`. Loopback redirects (`http://localhost/…`, `http://127.0.0.1/…`)
match with the port ignored (RFC 8252) so Claude Code's ephemeral port works;
the consent page shows the client's **host** as the relying party and warns
when the redirect goes to a local process.

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

### ZITADEL: teams from live grants (recommended)

Instead of trusting a `groups` claim minted at login, the service can ask
ZITADEL **on every request** which projects the user holds a grant in. That is
the right choice when ZITADEL is close by: an MCP token lives long and refreshes
itself, so a class membership revoked in ZITADEL would otherwise linger until
the token dies — and a newly granted one would never arrive. Set:

| Variable | Purpose |
|---|---|
| `ZITADEL_ORG_ID` | The organisation the projects live in |
| `ZITADEL_SERVICE_TOKEN` | PAT of a **read-only** machine user (manager role `ORG_OWNER_VIEWER`) — an infrastructure credential, installed in the cluster, never committed |
| `ZITADEL_TEAM_PROJECTS` | `"<projectId>=<team-slug>,…"` — one team per ZITADEL project |
| `ZITADEL_MAINTAINER_ROLE` | Role key that makes a member a maintainer (default `admin`) |

With these set the `groups` claim is ignored; use `OIDC_SCOPES="openid profile
email"`. Lookups are memoised for five seconds. If ZITADEL does not answer,
the user has **no** teams for that call — deny, never wave through.

### ZITADEL without a `groups` scope (claim-based alternative)

ZITADEL keeps project roles in a nested claim and an OIDC client only sees the
roles of *its own* project. To use one instance for several teams (e.g. one
school, classes as teams), add a ZITADEL **Action** on the *Complement Token*
flow (triggers *Pre Userinfo creation* + *Pre access token creation*) that
flattens the user's grants into `groups`, e.g. `["klasse-wiesen",
"klasse-wiesen:admin"]`, and run with `OIDC_SCOPES="openid profile email"`,
`OIDC_GROUP_PREFIX=""`, `OIDC_MAINTAINER_SUFFIX=":admin"`. The client needs
*ID token userinfo assertion* enabled so the claim lands in the ID token.

## MCP in Claude

Add `https://<host>/mcp` as a custom connector. Claude discovers the
authorization server through the `401` → protected-resource metadata → server
metadata chain, sees CIMD support and uses its own hosted client metadata
document — nothing to choose or paste in the connector dialog.

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
