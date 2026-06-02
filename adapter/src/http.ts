// HTTP surface: full OAuth 2.0 Authorization Server in front of BambooHR.
//
// Endpoints:
//   GET  /healthz                                      — liveness
//   GET  /authorize                                    — client-facing AS endpoint
//                                                        (validates client params, redirects user to BambooHR)
//   GET  /connect/callback                             — BambooHR returns here;
//                                                        we mint a one-time auth code
//                                                        and 302 to the client's redirect_uri
//   POST /token                                        — client exchanges auth code + PKCE verifier
//                                                        for the wrapper bearer
//   POST /mcp                                          — MCP Streamable HTTP (requires bearer)
//   POST /disconnect                                   — informational only (stateless = nothing to delete)
//   GET  /.well-known/oauth-authorization-server
//   GET  /.well-known/oauth-protected-resource
//   POST /register                                     — dynamic client registration
//
// Flow:
//   1. MCP client (Cursor, etc.) reads /.well-known and POSTs /register.
//   2. Client browser-redirects user to /authorize?client_id&redirect_uri&state&
//      response_type=code&code_challenge&code_challenge_method=S256&scope=...
//   3. /authorize validates client params, encrypts them into an AuthRequest,
//      302s the user to BambooHR's authorize.php with our AuthRequest as state.
//   4. BambooHR redirects back to /connect/callback?code&state.
//   5. /connect/callback decrypts our AuthRequest (recovering the client's
//      redirect_uri/state/code_challenge), exchanges BambooHR's code for tokens,
//      mints a wrapper bearer, wraps that bearer in an encrypted AuthCode
//      containing the PKCE challenge + redirect_uri, then 302s to
//      <client_redirect_uri>?code=<our_auth_code>&state=<client_state>.
//   6. Client POSTs /token with grant_type=authorization_code, code, redirect_uri,
//      code_verifier. We decrypt the code, verify PKCE (sha256(verifier) == cc),
//      verify redirect_uri match, return the wrapper bearer.
//   7. Client calls /mcp with Authorization: Bearer <wrapper_bearer>.
//
// PKCE S256 is mandatory at /authorize. Redirect URIs must be in the env
// allowlist. No server-side session state for OAuth.

import express, { type Request, type Response, type NextFunction } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import type { Config } from './config.js';
import {
  decryptBearer,
  encryptBearer,
  BearerError,
  type BearerPayload,
  encryptAuthRequest,
  decryptAuthRequest,
  AuthRequestError,
  encryptAuthCode,
  decryptAuthCode,
  AuthCodeError,
} from './crypto.js';
import {
  buildAuthorizeUrl,
  exchangeCodeForToken,
  refreshAccessToken,
  redirectUri,
  OAuthError,
} from './oauth-client.js';
import { makeOAuthClient } from './oauth-bamboohr-client.js';
import { requestCtx } from './als.js';
import { buildServer } from './server.js';
import { bearerKey, singleFlight } from './refresh.js';

// Lifetime of the encrypted AuthRequest (state for the BambooHR round-trip).
// The user has this many seconds to log in at BambooHR and consent.
const AUTH_REQUEST_TTL_SECONDS = 10 * 60;

// Static client_id used in DCR responses and tolerated at /authorize.
// Multi-client AS is out of scope for v0.1; we accept any client_id but
// canonicalize to this one for our own bookkeeping.
const ADAPTER_CLIENT_ID = 'bamboohr-oauth-mcp';

// ----- helpers -----

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function extractBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (!h || typeof h !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

function constantTimeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function verifyPkceS256(verifier: string, expectedChallenge: string): boolean {
  // RFC 7636: challenge = BASE64URL-ENCODE(SHA256(verifier))
  const computed = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  return constantTimeEqualStr(computed, expectedChallenge);
}

function mintBearer(cfg: Config, token: {
  access_token: string;
  refresh_token: string | null;
  expires_in: number;
  scope: string;
}): string {
  const iat = nowSec();
  const payload: BearerPayload = {
    v: 1,
    iat,
    exp: iat + cfg.bearerTtlSeconds,
    at: token.access_token,
    rt: token.refresh_token,
    ate: iat + token.expires_in,
    d: cfg.companyDomain,
    s: token.scope,
  };
  return encryptBearer(payload, cfg.encKey);
}

async function ensureFreshUpstream(
  cfg: Config,
  rawBearer: string,
  payload: BearerPayload,
): Promise<{ payload: BearerPayload; rotated: boolean }> {
  if (payload.ate - nowSec() > cfg.refreshSkewSeconds) {
    return { payload, rotated: false };
  }
  if (!payload.rt) {
    throw new OAuthError(
      'upstream access_token is expired or about to expire and no refresh_token is available',
      401,
    );
  }
  // Coalesce concurrent refreshes for the same bearer to one upstream call.
  // The captured rt is the one from the bearer the FIRST caller decrypted;
  // racing callers may carry the same rt or a stale rt — either way, the
  // post-refresh payload returned here is the authoritative result and is
  // re-encrypted into a fresh wrapper bearer by /mcp.
  const fresh = await singleFlight(`rt:${bearerKey(rawBearer)}`, () =>
    refreshAccessToken(cfg, payload.rt as string),
  );
  const newPayload: BearerPayload = {
    ...payload,
    at: fresh.access_token,
    rt: fresh.refresh_token ?? payload.rt,
    ate: nowSec() + fresh.expires_in,
    s: fresh.scope ?? payload.s,
  };
  return { payload: newPayload, rotated: true };
}

// Append query params without reflowing the URL; preserves fragments/etc.
function appendQuery(url: string, params: Record<string, string>): string {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return u.toString();
}

// ----- app factory -----

export function buildApp(cfg: Config): express.Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '4mb' }));
  app.use(express.urlencoded({ extended: false }));

  const server = buildServer();

  // --- Health ---
  app.get('/healthz', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'bamboohr-oauth-mcp',
      version: '0.1.0',
      companyDomain: cfg.companyDomain,
    });
  });

  // --- OAuth AS: /authorize ---------------------------------------------
  app.get('/authorize', (req, res) => {
    const q = (k: string): string | null => {
      const v = req.query[k];
      return typeof v === 'string' && v.length > 0 ? v : null;
    };

    const responseType = q('response_type');
    const clientId = q('client_id');
    const redirectUriRaw = q('redirect_uri');
    const clientState = q('state') ?? '';
    const codeChallenge = q('code_challenge');
    const codeChallengeMethod = q('code_challenge_method');
    const scope = q('scope') ?? '';

    if (responseType !== 'code') {
      res.status(400).json({ error: 'unsupported_response_type', detail: 'only response_type=code is supported' });
      return;
    }
    if (!clientId) {
      res.status(400).json({ error: 'invalid_request', detail: 'client_id is required' });
      return;
    }
    if (!redirectUriRaw) {
      res.status(400).json({ error: 'invalid_request', detail: 'redirect_uri is required' });
      return;
    }
    if (!cfg.allowedRedirectUris.includes(redirectUriRaw)) {
      // Do NOT redirect on an invalid redirect_uri (open redirect avoidance).
      // Render a plain error so the user/admin can see the mismatch.
      res.status(400).json({
        error: 'invalid_redirect_uri',
        detail: `redirect_uri "${redirectUriRaw}" is not in OAUTH_ALLOWED_REDIRECT_URIS`,
      });
      return;
    }
    if (!codeChallenge || codeChallengeMethod !== 'S256') {
      res.status(400).json({
        error: 'invalid_request',
        detail: 'PKCE is required: supply code_challenge and code_challenge_method=S256',
      });
      return;
    }

    const iat = nowSec();
    const stateToken = encryptAuthRequest(
      {
        v: 1,
        iat,
        exp: iat + AUTH_REQUEST_TTL_SECONDS,
        ci: clientId,
        ru: redirectUriRaw,
        cs: clientState,
        cc: codeChallenge,
        sc: scope,
      },
      cfg.encKey,
    );

    res.redirect(302, buildAuthorizeUrl(cfg, stateToken));
  });

  // --- BambooHR callback ------------------------------------------------
  app.get('/connect/callback', async (req, res) => {
    const code = typeof req.query.code === 'string' ? req.query.code : null;
    const stateRaw = typeof req.query.state === 'string' ? req.query.state : null;
    const errParam = typeof req.query.error === 'string' ? req.query.error : null;

    if (errParam) {
      res.status(400).json({ error: 'oauth_provider_error', detail: errParam });
      return;
    }
    if (!code || !stateRaw) {
      res.status(400).json({ error: 'missing code or state' });
      return;
    }

    let authReq;
    try {
      authReq = decryptAuthRequest(stateRaw, cfg.encKey);
    } catch (e) {
      if (e instanceof AuthRequestError) {
        res.status(400).json({ error: 'invalid_state', detail: e.message });
        return;
      }
      throw e;
    }

    if (authReq.exp < nowSec()) {
      res.status(400).json({ error: 'state_expired' });
      return;
    }

    // Re-verify the redirect_uri is still in the allowlist. (Config could have
    // changed between /authorize and the callback; reject rather than honor a
    // stale URI.)
    if (!cfg.allowedRedirectUris.includes(authReq.ru)) {
      res.status(400).json({
        error: 'invalid_redirect_uri',
        detail: 'redirect_uri from original /authorize is no longer in the allowlist',
      });
      return;
    }

    let token;
    try {
      token = await exchangeCodeForToken(cfg, code);
    } catch (e) {
      if (e instanceof OAuthError) {
        // We cannot safely redirect to the client without the state context;
        // surface the error to the user/admin here.
        res.status(e.status ?? 502).json({ error: 'oauth_exchange_failed', detail: e.message });
        return;
      }
      throw e;
    }

    if (token.companyDomain && token.companyDomain !== cfg.companyDomain) {
      res.status(400).json({
        error: 'tenant_mismatch',
        detail: `token issued for "${token.companyDomain}", adapter is configured for "${cfg.companyDomain}"`,
      });
      return;
    }

    const bearer = mintBearer(cfg, {
      access_token: token.access_token,
      refresh_token: token.refresh_token ?? null,
      expires_in: token.expires_in,
      scope: token.scope,
    });

    const iat = nowSec();
    const authCode = encryptAuthCode(
      {
        v: 1,
        iat,
        exp: iat + cfg.authCodeTtlSeconds,
        b: bearer,
        ru: authReq.ru,
        cc: authReq.cc,
        eb: iat + cfg.bearerTtlSeconds,
        sc: token.scope,
      },
      cfg.encKey,
    );

    const redirect = appendQuery(authReq.ru, {
      code: authCode,
      state: authReq.cs,
    });
    res.redirect(302, redirect);
  });

  // --- OAuth AS: /token --------------------------------------------------
  app.post('/token', (req, res) => {
    // Accept both x-www-form-urlencoded (per RFC 6749) and JSON for convenience.
    const body = (req.body ?? {}) as Record<string, unknown>;
    const grantType = typeof body.grant_type === 'string' ? body.grant_type : null;
    const code = typeof body.code === 'string' ? body.code : null;
    const redirectUriIn = typeof body.redirect_uri === 'string' ? body.redirect_uri : null;
    const codeVerifier = typeof body.code_verifier === 'string' ? body.code_verifier : null;

    if (grantType !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }
    if (!code || !redirectUriIn || !codeVerifier) {
      res
        .status(400)
        .json({ error: 'invalid_request', detail: 'code, redirect_uri, and code_verifier are required' });
      return;
    }

    let authCode;
    try {
      authCode = decryptAuthCode(code, cfg.encKey);
    } catch (e) {
      if (e instanceof AuthCodeError) {
        res.status(400).json({ error: 'invalid_grant', detail: e.message });
        return;
      }
      throw e;
    }

    if (authCode.exp < nowSec()) {
      res.status(400).json({ error: 'invalid_grant', detail: 'authorization code expired' });
      return;
    }
    if (!constantTimeEqualStr(authCode.ru, redirectUriIn)) {
      res.status(400).json({ error: 'invalid_grant', detail: 'redirect_uri mismatch' });
      return;
    }
    if (!verifyPkceS256(codeVerifier, authCode.cc)) {
      res.status(400).json({ error: 'invalid_grant', detail: 'PKCE verification failed' });
      return;
    }

    const expiresIn = Math.max(0, authCode.eb - nowSec());
    res.json({
      access_token: authCode.b,
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope: authCode.sc,
    });
  });

  // --- Disconnect (stateless) ---
  app.post('/disconnect', (_req, res) => {
    res.json({ status: 'ok', note: 'stateless adapter: discard the bearer client-side' });
  });

  // --- MCP endpoint ---
  //
  // The WWW-Authenticate header on every 401 MUST include a `resource_metadata`
  // pointer per the MCP spec (which inherits from RFC 9728, OAuth 2.0 Protected
  // Resource Metadata). Without it MCP clients (Cursor, Claude Desktop, ...)
  // cannot discover the authorization server and fail with a generic empty-message
  // "Transient error connecting to streamableHttp server" instead of starting
  // the OAuth flow. The `error=` token is RFC 6750 §3.1.
  const resourceMetadataUrl = `${cfg.publicBaseUrl}/.well-known/oauth-protected-resource`;
  const wwwAuth = (errCode: string, description?: string): string => {
    const parts = [`Bearer realm="bamboohr-mcp"`, `resource_metadata="${resourceMetadataUrl}"`, `error="${errCode}"`];
    if (description) parts.push(`error_description="${description.replace(/"/g, "'")}"`);
    return parts.join(', ');
  };

  app.post('/mcp', async (req: Request, res: Response, next: NextFunction) => {
    const raw = extractBearer(req);
    if (!raw) {
      res
        .status(401)
        .set('WWW-Authenticate', wwwAuth('invalid_token', 'missing bearer'))
        .json({ error: 'missing_bearer' });
      return;
    }

    let payload: BearerPayload;
    try {
      payload = decryptBearer(raw, cfg.encKey);
    } catch (e) {
      if (e instanceof BearerError) {
        res
          .status(401)
          .set('WWW-Authenticate', wwwAuth('invalid_token', e.message))
          .json({ error: 'invalid_bearer', detail: e.message });
        return;
      }
      next(e);
      return;
    }

    if (payload.exp < nowSec()) {
      res
        .status(401)
        .set('WWW-Authenticate', wwwAuth('invalid_token', 'bearer expired'))
        .json({ error: 'bearer_expired' });
      return;
    }

    let rotated = false;
    try {
      const r = await ensureFreshUpstream(cfg, raw, payload);
      payload = r.payload;
      rotated = r.rotated;
    } catch (e) {
      if (e instanceof OAuthError) {
        res.status(e.status ?? 401).json({ error: 'upstream_refresh_failed', detail: e.message });
        return;
      }
      next(e);
      return;
    }

    if (rotated) {
      const newBearer = mintBearer(cfg, {
        access_token: payload.at,
        refresh_token: payload.rt,
        expires_in: payload.ate - nowSec(),
        scope: payload.s,
      });
      res.setHeader('X-Wrapper-Token', newBearer);
    }

    const client = makeOAuthClient({
      accessToken: payload.at,
      companyDomain: cfg.companyDomain,
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on('close', () => transport.close());

    try {
      await requestCtx.run({ client }, async () => {
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      });
    } catch (e) {
      next(e);
    }
  });

  // --- .well-known discovery ---
  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: cfg.publicBaseUrl,
      authorization_endpoint: `${cfg.publicBaseUrl}/authorize`,
      token_endpoint: `${cfg.publicBaseUrl}/token`,
      registration_endpoint: `${cfg.publicBaseUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: cfg.oauthScopes.split('+'),
    });
  });

  app.get('/.well-known/oauth-protected-resource', (_req, res) => {
    res.json({
      resource: `${cfg.publicBaseUrl}/mcp`,
      authorization_servers: [cfg.publicBaseUrl],
      bearer_methods_supported: ['header'],
    });
  });

  // --- Dynamic Client Registration (RFC 7591) ---
  // Accept the client's requested redirect_uris, validate each against the
  // env allowlist, and echo back. We do not persist anything; client_id is
  // a static label.
  app.post('/register', (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const requested = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
    const uris: string[] = [];
    for (const u of requested) {
      if (typeof u !== 'string') {
        res.status(400).json({ error: 'invalid_redirect_uri', detail: 'redirect_uris must be strings' });
        return;
      }
      if (!cfg.allowedRedirectUris.includes(u)) {
        res.status(400).json({
          error: 'invalid_redirect_uri',
          detail: `redirect_uri "${u}" is not in OAUTH_ALLOWED_REDIRECT_URIS`,
        });
        return;
      }
      uris.push(u);
    }
    // If the client sent no redirect_uris, echo the entire allowlist so
    // discovery-only clients can pick one.
    if (uris.length === 0) uris.push(...cfg.allowedRedirectUris);

    res.status(201).json({
      client_id: ADAPTER_CLIENT_ID,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      redirect_uris: uris,
    });
  });

  // Keep the upstream redirectUri helper alive (used elsewhere); silence unused.
  void redirectUri;

  // --- Error handler ---
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    // eslint-disable-next-line no-console
    console.error('[adapter] unhandled error:', err);
    if (res.headersSent) return;
    res.status(500).json({ error: 'internal_error', detail: err.message });
  });

  return app;
}
