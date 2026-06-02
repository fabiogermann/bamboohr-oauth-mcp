# bamboohr-oauth-mcp

OAuth-aware wrapper around [`@twentytwokhz/bamboohr-mcp`](https://www.npmjs.com/package/@twentytwokhz/bamboohr-mcp).

**Why this exists.** The upstream MCP server reads `BAMBOOHR_API_KEY` once at boot and shares a single client across all HTTP requests — fine for stdio or single-user HTTP, but it cannot do per-user OAuth. This adapter terminates the BambooHR OAuth flow, mints a stateless encrypted bearer for each user, and runs the upstream MCP server with a per-request bearer-authenticated client. **All 79 upstream tools work unchanged** — no fork, no copy-paste.

## How it works

This adapter is a full OAuth 2.0 Authorization Server in front of BambooHR. MCP clients (Cursor, Claude Desktop, etc.) discover it via `/.well-known/oauth-authorization-server`, dance with `/authorize` → `/token` using PKCE S256, and end up with an opaque wrapper bearer they pass to `POST /mcp`.

1. **One BambooHR OAuth app** (registered in the BambooHR Developer Portal).
2. **One adapter deployment** scoped to **one BambooHR tenant** (set via `BAMBOOHR_COMPANY_DOMAIN`).
3. MCP client browser-redirects user to `/authorize?response_type=code&client_id=...&redirect_uri=...&state=...&code_challenge=...&code_challenge_method=S256&scope=...`.
4. Adapter validates the request (PKCE mandatory, `redirect_uri` must be in the env allowlist), encrypts the client's parameters into an AES-256-GCM `AuthRequest` token, and 302-redirects the user to BambooHR's `authorize.php` carrying that token as `state`.
5. User authorizes at BambooHR; BambooHR redirects to `<PUBLIC_BASE_URL>/connect/callback?code=...&state=...`.
6. Adapter decrypts the state, exchanges the BambooHR `code` for `{access_token, refresh_token}`, mints a wrapper bearer (encrypted, self-contained), wraps that bearer in an encrypted one-time `AuthCode` carrying the original PKCE challenge + client redirect, and 302-redirects to the **client's** `redirect_uri` with `code=<auth_code>&state=<original_client_state>`.
7. Client POSTs `/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`. Adapter decrypts the code, verifies PKCE (`sha256(verifier) == challenge`), verifies redirect match, returns the wrapper bearer as the `access_token`.
8. Client calls `POST /mcp` with `Authorization: Bearer <wrapper-bearer>`. Adapter decrypts, refreshes upstream BambooHR token if it expires within `WRAPPER_REFRESH_SKEW_SECONDS`, constructs a fresh `BambooHRClient` configured with the user's access token, runs the MCP request inside `AsyncLocalStorage`. If the wrapper was re-minted on refresh, it's returned in the `X-Wrapper-Token` response header.

No database. No session state. Adapter pods are horizontally scalable: every token (wrapper bearer, OAuth `state`/AuthRequest, one-time AuthCode) is an AES-256-GCM self-contained ciphertext; any replica can handle any request. The only shared dependency is the encryption key.

## Why an "adapter" and not a fork

The upstream package exposes the right primitives:

- `BambooHRClient` from `dist/services/bamboohr-client.js`
- Tool registration as `registerXxxTools(server, client)` functions from `dist/tools/*.js`

So we never import `dist/index.js` (which would auto-start its own server). We:

- Build our own `McpServer`.
- Pass a **proxy `BambooHRClient`** as the `client` to every `registerXxxTools(...)`. Each tool handler closes over this proxy.
- On every request, set the live client into `AsyncLocalStorage`. The proxy's `get` handler resolves every property access to the live client.
- The "live client" is `BambooHRClient` with `getAuthHeader()` patched on the prototype to return `Bearer <token>` when an instance has `__bearerToken` set. The original `Basic` behavior is preserved as a fallback.

All of this is in `adapter/src/`. ~80 lines of real logic; the rest is OAuth wiring and config.

## Environment variables

| Variable                          | Required | Default       | Description |
|-----------------------------------|----------|---------------|-------------|
| `BAMBOOHR_COMPANY_DOMAIN`         | yes      | —             | Subdomain part of `<x>.bamboohr.com` |
| `BAMBOOHR_OAUTH_CLIENT_ID`        | yes      | —             | From BambooHR Developer Portal |
| `BAMBOOHR_OAUTH_CLIENT_SECRET`    | yes      | —             | From BambooHR Developer Portal |
| `WRAPPER_ENC_KEY_BASE64`          | yes      | —             | 32 bytes, base64. `openssl rand -base64 32` |
| `PUBLIC_BASE_URL`                 | yes      | —             | External URL of the adapter, e.g. `https://bamboo-mcp.example.com`. Used in OAuth `redirect_uri` and `.well-known` docs. |
| `OAUTH_ALLOWED_REDIRECT_URIS`     | yes      | —             | Comma-separated allowlist of MCP-client redirect URIs. `/authorize`, `/register`, and `/connect/callback` all reject any URI not in this list (open-redirect protection). Example: `cursor://anysphere.cursor-deeplink/sso/login,http://127.0.0.1:39000/callback`. Exact-string match, case-sensitive. |
| `PORT`                            | no       | `3000`        | HTTP listen port |
| `BAMBOOHR_OAUTH_SCOPES`           | no       | `offline_access openid email` | Space- or plus-separated scope list. Sent to BambooHR verbatim — **do not include scopes your app is not configured for** or BambooHR returns `invalid_scope`. `offline_access` is **always appended** if not present (refresh tokens). Examples: `mcp`, `time_off`, `company:info`, `company:details`, `ask_bamboohr:chat_messages`. If your BambooHR OAuth app does not allow `offline_access`, you must reconfigure the app — there is no opt-out at this layer. |
| `WRAPPER_BEARER_TTL_SECONDS`      | no       | `3600`        | Wrapper bearer lifetime |
| `WRAPPER_REFRESH_SKEW_SECONDS`    | no       | `60`          | Refresh upstream token if it expires within this many seconds |
| `OAUTH_AUTH_CODE_TTL_SECONDS`     | no       | `60`          | TTL of the one-time authorization code returned from `/connect/callback`. Keep short. |

Register your redirect URI in the **BambooHR** Developer Portal as exactly: `<PUBLIC_BASE_URL>/connect/callback`. (This is the adapter's callback from BambooHR — distinct from the MCP-client redirect URIs you list in `OAUTH_ALLOWED_REDIRECT_URIS`.)

## Endpoints

| Method | Path                                          | Description |
|--------|-----------------------------------------------|-------------|
| GET    | `/healthz`                                    | Liveness/info |
| GET    | `/authorize`                                  | Client-facing OAuth AS endpoint. Requires `response_type=code`, `client_id`, `redirect_uri` (in allowlist), `state`, `code_challenge`, `code_challenge_method=S256`, optional `scope`. 302s to BambooHR. |
| GET    | `/connect/callback`                           | BambooHR returns here. Mints a one-time auth code and 302s to the client's `redirect_uri` with `code` + original `state`. |
| POST   | `/token`                                      | OAuth token endpoint. Body (form-urlencoded or JSON): `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`. Returns `{access_token, token_type:"Bearer", expires_in, scope}`. |
| POST   | `/mcp`                                        | MCP Streamable HTTP. Requires `Authorization: Bearer <wrapper-bearer>`. May return `X-Wrapper-Token` if upstream was refreshed. |
| POST   | `/disconnect`                                 | No-op (stateless); discard the bearer client-side |
| GET    | `/.well-known/oauth-authorization-server`    | OAuth AS metadata (issuer, /authorize, /token, /register, S256, scopes) |
| GET    | `/.well-known/oauth-protected-resource`      | OAuth resource metadata |
| POST   | `/register`                                   | Dynamic Client Registration (RFC 7591). Validates requested `redirect_uris` against the env allowlist. |

## Local dev

```bash
cd adapter
npm install
npm run build
node dist/index.js
```

## Container

The repo-root `Dockerfile` builds the adapter (multi-stage, TypeScript compile, prod prune, non-root, tini PID 1).

```bash
docker build -t bamboohr-oauth-mcp:latest .
docker run --rm -p 3000:3000 \
  -e BAMBOOHR_COMPANY_DOMAIN=mycompany \
  -e BAMBOOHR_OAUTH_CLIENT_ID=... \
  -e BAMBOOHR_OAUTH_CLIENT_SECRET=... \
  -e WRAPPER_ENC_KEY_BASE64="$(openssl rand -base64 32)" \
  -e PUBLIC_BASE_URL=https://bamboo-mcp.example.com \
  bamboohr-oauth-mcp:latest
```

## Kubernetes notes

- Put `BAMBOOHR_OAUTH_CLIENT_SECRET` and `WRAPPER_ENC_KEY_BASE64` in a `Secret` (never a `ConfigMap`).
- Probes:
  - liveness: `GET /healthz`
  - readiness: `GET /healthz`
- Rotation: changing `WRAPPER_ENC_KEY_BASE64` invalidates all outstanding bearers AND any in-flight OAuth state (users must restart any auth dance and re-auth). This is the documented revocation mechanism for a stateless deployment.
- Multi-replica: every token is a self-contained encrypted ciphertext; any pod can serve any request. **For best concurrent-refresh behavior, enable Authorization-header affinity at the ingress** (see below). Without it, the per-pod single-flight only deduplicates collisions that happen to land on the same replica.
- The upstream client's 5-min response cache is effectively disabled (fresh per-request client). For high-traffic deployments where this matters, add a wrapper-layer cache keyed by `(userSubject, endpoint)`.

### Ingress affinity (recommended for multi-replica)

The adapter has a per-process single-flight that coalesces concurrent refreshes of the same bearer into one upstream call. To make that effective when running multiple replicas, route requests carrying the same `Authorization` header to the same pod.

**nginx-ingress** — annotate the Ingress:

```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/upstream-hash-by: "$http_authorization"
```

**Traefik v2** — add a `headerValue` sticky service or use the consistent-hash load balancer:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: TraefikService
metadata:
  name: bamboohr-mcp-affinity
spec:
  weighted:
    services:
      - name: bamboohr-oauth-mcp
        port: 3000
    sticky:
      cookie:
        name: lb
```

(Traefik also supports hashing by header via `IPWhiteList` middleware variants, but a cookie-based stickiness is the easiest portable path.)

**Envoy / Istio** — `DestinationRule` with `consistentHash` on `httpHeaderName: Authorization`.

With ingress affinity, concurrent refreshes for the same bearer always hit the same pod and collapse to a single BambooHR `token.php` call. Without it, the worst case is N concurrent refreshes across N pods — bounded but not zero.

## Caveats (read before deploying)

- **BambooHR OAuth requires marketplace approval.** Apply for it before you need this in production; the process takes calendar time.
- **No per-user revocation.** Bearer TTL bounds replay. Lower `WRAPPER_BEARER_TTL_SECONDS` if you need tighter recovery from credential leakage.
- **Authorization codes are not one-shot enforced.** RFC 6749 §4.1.2 says auth codes MUST be single-use. Enforcing that would require shared state (database/Redis). Instead, PKCE provides the security guarantee: an attacker who captures a redirect URL cannot exchange it without the `code_verifier`, which only the legitimate client holds. A legitimate client that retries `/token` within the 60s TTL gets the same wrapper bearer back (idempotent, not exploitable). This is a documented stateless trade-off.
- **In-flight OAuth state survives pod death but not key rotation.** The `state` param is itself an encrypted token. Rotating `WRAPPER_ENC_KEY_BASE64` mid-flow breaks any user who hasn't completed the callback yet.
