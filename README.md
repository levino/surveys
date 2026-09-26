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

A survey belongs to a **group/team** taken from the user's own OIDC tokens
(ZITADEL project roles or a `groups` claim). Every
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
| `OIDC_CLIENT_SECRET`  | –                       | OIDC client secret (`client_secret_basic`); required unless `OIDC_CLIENT_KEY` is set |
| `OIDC_CLIENT_KEY`     | –                       | ZITADEL application key JSON (`type` `application`, `keyId`, `key`, `clientId`) for `private_key_jwt`. Wins over `OIDC_CLIENT_SECRET`; `OIDC_CLIENT_ID` may be omitted (taken from the key), a mismatch stops the start |
| `OIDC_GROUP_PREFIX`   | `` (empty)              | Prefix stripped from `groups` to form the team slug |
| `OIDC_MAINTAINER_SUFFIX` | `` (empty)           | A group ending in this suffix (e.g. `:admin`) makes the user a maintainer of the team named by the rest — maintainers may change/delete every survey of that team |
| `OIDC_SCOPES`         | `openid profile email offline_access groups` | Scopes requested at login. With `ZITADEL_TEAM_PROJECTS` the ZITADEL role/audience scopes and `offline_access` are added automatically |
| `OIDC_REFRESH_INTERVAL` | `10m`                 | Upper bound for using the provider's access token: it is refreshed on the next request (browser or MCP) once it expires (`expires_in`) or is older than this, and the teams are re-derived. Go duration or seconds |
| `ZITADEL_TEAM_PROJECTS` | –                     | `"<projectId>=<team-slug>,…"` — one team per ZITADEL project (see below) |
| `ZITADEL_MAINTAINER_ROLE` | `admin`             | Role key in a team project that makes the user a maintainer |
| `ZITADEL_WEBHOOK_SIGNING_KEY` | –               | Signing key of the ZITADEL Actions v2 target calling `POST /login/zitadel-events`; unset = the route answers 404 |
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

Register a confidential web client (code flow, PKCE is always sent) at your
provider:
- Redirect URI: `https://<host>/login/callback`
- Post-logout redirect URI: `https://<host>/`
- Back-channel logout URI: `https://<host>/login/backchannel-logout`
- Client authentication: `private_key_jwt` (`OIDC_CLIENT_KEY`) or client
  secret (`OIDC_CLIENT_SECRET`)
- Grant types: authorization code **and refresh token**
- Scopes: `openid profile email offline_access groups` (plain OIDC) — for
  ZITADEL see below

How sessions stay current: every login keeps the provider's **refresh token**
server-side (never in the browser or the MCP client). When the tokens of a
session have expired (`expires_in`, at most `OIDC_REFRESH_INTERVAL`,
default 10 minutes), the next request — browser or MCP — refreshes them and re-derives the teams from the
new tokens. MCP tokens are bound to the login they were authorized from, so
they follow the same rule, including on their own refresh grant.

- Provider **rejects** the refresh (user blocked, grant or session revoked)
  → the browser session and **all MCP tokens of that login are deleted**;
  the MCP client has to re-authorize.
- Provider **unreachable** → the request is denied (browser: not logged in;
  MCP: `503`), nothing is deleted; it works again once the provider answers.
- **Back-channel logout** (OIDC Back-Channel Logout 1.0) at
  `POST /login/backchannel-logout`: the provider sends a signed
  `logout_token` when the user's session there ends; the service validates it
  (JWKS signature, `iss`, `aud` = client id, `iat`/`exp`, the
  `backchannel-logout` event, `sid` and/or `sub`, no `nonce`) and at once
  deletes the matching sessions and MCP tokens — by `sid` (stored at login)
  or, without `sid`, every session of `sub`.

- **Logout** (`/logout`) deletes the browser session and the login behind it
  (with its MCP tokens), revokes the refresh token at the provider's
  `revocation_endpoint` and continues at its `end_session_endpoint`
  (`client_id`, `post_logout_redirect_uri=<base>/`).

Every ID token is verified against the provider's JWKS (`iss`, `aud`/`azp`,
`exp`, `iat`, and the login `nonce`).

After upgrading from a version without this binding, existing browser
sessions and MCP tokens are no longer accepted: everybody logs in once more,
and MCP clients re-authorize.

### ZITADEL: teams from the user's project roles (recommended)

The service holds **no ZITADEL credential** of its own. Each team is one
ZITADEL project; membership is any role in it:

| Variable | Purpose |
|---|---|
| `ZITADEL_TEAM_PROJECTS` | `"<projectId>=<team-slug>,…"` — one team per ZITADEL project |
| `ZITADEL_MAINTAINER_ROLE` | Role key that makes a member a maintainer (default `admin`) |

At login the service adds these scopes to `OIDC_SCOPES`:
`offline_access`, `urn:zitadel:iam:org:projects:roles` and, per configured
project, `urn:zitadel:iam:org:project:id:<projectId>:aud`. ZITADEL then
asserts one claim per project,
`urn:zitadel:iam:org:project:<projectId>:roles` =
`{"<roleKey>": {"<orgId>": "<orgDomain>"}}`
([scopes](https://zitadel.com/docs/apis/openidoauth/scopes),
[claims](https://zitadel.com/docs/apis/openidoauth/claims)). If the ID token
does not carry them (the app's *User roles inside ID Token* is off), the
service reads them from the userinfo endpoint with the user's access token.
The `groups` claim is ignored in this mode.

ZITADEL app settings: *Web*, auth method *Private Key JWT* (application key
as `OIDC_CLIENT_KEY`; *Basic* with `OIDC_CLIENT_SECRET` still works), grant types *Authorization
Code* + *Refresh Token*, redirect `…/login/callback`, back-channel logout URI
`…/login/backchannel-logout` (back-channel logout must be enabled on the
instance). *User roles inside ID Token* is recommended (saves a userinfo
call); *User Info inside ID Token* is not needed.

**Events (Actions v2).** Locks, removed grants and ended sessions do not all
produce a back-channel logout. Create a REST-webhook target (non-interrupting)
for `https://<host>/login/zitadel-events`, put its signing key into
`ZITADEL_WEBHOOK_SIGNING_KEY`, and add event executions for it. Every call is
checked against the `ZITADEL-Signature` header (HMAC-SHA256, 5 minutes
tolerance). Effect:

| Event | Effect |
|---|---|
| `user.locked`, `user.deactivated`, `user.removed`, `user.token.removed`, `user.human.signed.out`, `user.human.refresh.token.removed` | every session and MCP token of the user ends |
| `session.terminated` | only the login with this `sid` ends (other devices stay) |
| `user.grant.removed`, `user.grant.cascade.removed`, `user.grant.deactivated` (team projects only) | the user's sessions end; without `userId` in the payload every session refreshes |
| `user.grant.changed`, `user.grant.cascade.changed`, `user.grant.added`, `user.grant.reactivated` (team projects only) | the user's sessions refresh on their next request (teams re-read) |
| `oidc_session.access_token.revoked`, `oidc_session.refresh_token.revoked` | every session refreshes (the revoked one fails and ends) |

`ZITADEL_SERVICE_TOKEN` and `ZITADEL_ORG_ID` (the former grants lookup) are
accepted but ignored with a deprecation warning at start — remove them and the
machine user.

### ZITADEL without project roles (`groups` via an Action)

Alternative when you would rather not list projects in the config: to use one instance for several teams (e.g. one
school, classes as teams), add a ZITADEL **Action** on the *Complement Token*
flow (triggers *Pre Userinfo creation* + *Pre access token creation*) that
flattens the user's grants into `groups`, e.g. `["klasse-wiesen",
"klasse-wiesen:admin"]`, and run with `OIDC_SCOPES="openid profile email offline_access"`,
`OIDC_GROUP_PREFIX=""`, `OIDC_MAINTAINER_SUFFIX=":admin"`. The client needs
*ID token userinfo assertion* enabled so the claim lands in the ID token.

## Health

- `GET /healthz` — liveness only (database ping); use it for probes.
- `GET /health` — whether logins can work, `503` when not:

```json
{"status":"ok","auth":{"clientAuthentication":"private_key_jwt",
 "credentialCheck":{"status":"ok","checkedAt":"2026-09-26T12:00:00Z","error":null}},
 "webhook":"configured","backchannelLogout":"/login/backchannel-logout"}
```

`credentialCheck` proves the client credential at most every 5 minutes by
revoking a random dummy token at the provider's `revocation_endpoint` (client
authentication required, unknown tokens answer `200`). `degraded` (`503`) when
no client credential is configured, the check fails, or `ZITADEL_TEAM_PROJECTS`
is set without `ZITADEL_WEBHOOK_SIGNING_KEY`.

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
