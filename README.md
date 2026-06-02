# BambooHR MCP OAuth Adapter

OAuth-aware wrapper around [`@twentytwokhz/bamboohr-mcp`](https://www.npmjs.com/package/@twentytwokhz/bamboohr-mcp).

**Why this exists.** The upstream MCP server reads `BAMBOOHR_API_KEY` once at boot and shares a single client across all HTTP requests — fine for stdio or single-user HTTP, but it cannot do per-user OAuth. This adapter terminates the BambooHR OAuth flow, mints a stateless encrypted bearer for each user, and runs the upstream MCP server with a per-request bearer-authenticated client. **All 79 upstream tools work unchanged** — no fork, no copy-paste.

## How it works

1. **One BambooHR OAuth app** (registered in the BambooHR Developer Portal).
2. **One adapter deployment** scoped to **one BambooHR tenant** (set via `BAMBOOHR_COMPANY_DOMAIN`).
3. User browses to `/connect/start`, gets redirected to BambooHR, authorizes, and BambooHR redirects back to `/connect/callback`.
4. Adapter exchanges the auth code for `{access_token, refresh_token}`, encrypts those into a self-contained wrapper bearer (AES-256-GCM, 32-byte key), and returns it to the user.
5. User calls `POST /mcp` with `Authorization: Bearer <wrapper-bearer>`.
6. Adapter decrypts, refreshes the upstream BambooHR token if it expires within `WRAPPER_REFRESH_SKEW_SECONDS`, constructs a fresh `BambooHRClient` configured with the user's access token, runs the MCP request inside an `AsyncLocalStorage` scope. If the wrapper bearer was re-minted due to refresh, it's returned in the `X-Wrapper-Token` response header.

No database. No session state. Adapter pods are horizontally scalable: both the wrapper bearer and the OAuth `state` parameter are AES-256-GCM-encrypted self-contained tokens, so any replica can handle any request. The only shared dependency is the encryption key.

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
| `PORT`                            | no       | `3000`        | HTTP listen port |
| `BAMBOOHR_OAUTH_SCOPES`           | no       | `offline_access` | Space- or plus-separated scope list. `offline_access` is always appended if absent. |
| `WRAPPER_BEARER_TTL_SECONDS`      | no       | `3600`        | Wrapper bearer lifetime |
| `WRAPPER_REFRESH_SKEW_SECONDS`    | no       | `60`          | Refresh upstream token if it expires within this many seconds |

Register your redirect URI in the BambooHR Developer Portal as exactly: `<PUBLIC_BASE_URL>/connect/callback`.

## Endpoints

| Method | Path                                          | Description |
|--------|-----------------------------------------------|-------------|
| GET    | `/healthz`                                    | Liveness/info |
| GET    | `/connect/start`                              | Begin OAuth — 302 to BambooHR `authorize.php` |
| GET    | `/connect/callback`                           | OAuth callback; returns `{access_token, expires_in, scope}` (access_token is the wrapper bearer) |
| POST   | `/mcp`                                        | MCP Streamable HTTP. Requires `Authorization: Bearer <wrapper-bearer>`. May return `X-Wrapper-Token` if upstream was refreshed. |
| POST   | `/disconnect`                                 | No-op (stateless); discard the bearer client-side |
| GET    | `/.well-known/oauth-authorization-server`    | OAuth AS metadata |
| GET    | `/.well-known/oauth-protected-resource`      | OAuth resource metadata |
| POST   | `/register`                                   | Dynamic Client Registration stub |

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
docker build -t bamboohr-mcp-oauth-adapter:latest .
docker run --rm -p 3000:3000 \
  -e BAMBOOHR_COMPANY_DOMAIN=mycompany \
  -e BAMBOOHR_OAUTH_CLIENT_ID=... \
  -e BAMBOOHR_OAUTH_CLIENT_SECRET=... \
  -e WRAPPER_ENC_KEY_BASE64="$(openssl rand -base64 32)" \
  -e PUBLIC_BASE_URL=https://bamboo-mcp.example.com \
  bamboohr-mcp-oauth-adapter:latest
```

## Kubernetes notes

- Put `BAMBOOHR_OAUTH_CLIENT_SECRET` and `WRAPPER_ENC_KEY_BASE64` in a `Secret` (never a `ConfigMap`).
- Probes:
  - liveness: `GET /healthz`
  - readiness: `GET /healthz`
- Rotation: changing `WRAPPER_ENC_KEY_BASE64` invalidates all outstanding bearers AND any in-flight OAuth state (users must restart any auth dance and re-auth). This is the documented revocation mechanism for a stateless deployment.
- Multi-replica: no sticky routing required. Bearer and OAuth state are both self-contained encrypted tokens; any pod can serve any request.
- The upstream client's 5-min response cache is effectively disabled (fresh per-request client). For high-traffic deployments where this matters, add a wrapper-layer cache keyed by `(userSubject, endpoint)`.

## Caveats (read before deploying)

- **BambooHR OAuth requires marketplace approval.** Apply for it before you need this in production; the process takes calendar time.
- **No per-user revocation.** Bearer TTL bounds replay. Lower `WRAPPER_BEARER_TTL_SECONDS` if you need tighter recovery from credential leakage.
- **Concurrent refresh.** Two simultaneous in-flight requests on the same bearer can both trigger refresh. If BambooHR rotates refresh tokens (single-use), one request will fail with `upstream_refresh_failed` and the affected client will need to re-auth. Mitigation requires either ingress-level sticky routing of bearers + a per-pod single-flight lock, or a distributed lock (Redis). Neither is in v0.1.
- **In-flight OAuth state survives pod death but not key rotation.** The `state` param is itself an encrypted token containing only timestamp + nonce. Rotating `WRAPPER_ENC_KEY_BASE64` mid-flow breaks any user who hasn't completed the callback yet.
