// HTTP surface: OAuth init/callback, MCP endpoint, health, discovery.
//
// Endpoints (all returned by /.well-known where applicable):
//   GET  /healthz                              — liveness
//   GET  /connect/start                        — begin BambooHR OAuth (redirects to BambooHR)
//   GET  /connect/callback                     — OAuth callback; mints encrypted wrapper bearer
//   POST /mcp                                  — MCP Streamable HTTP (requires bearer)
//   POST /disconnect                           — informational only (stateless = nothing to delete)
//   GET  /.well-known/oauth-authorization-server
//   GET  /.well-known/oauth-protected-resource
//   POST /register                             — dynamic client registration (stub: returns adapter as the client)

import express, { type Request, type Response, type NextFunction } from 'express';
import { randomBytes } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

import type { Config } from './config.js';
import {
  decryptBearer,
  encryptBearer,
  BearerError,
  type BearerPayload,
  encryptState,
  decryptState,
  StateError,
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

// OAuth `state` is a self-contained AES-GCM token (see crypto.ts). No per-pod
// state store. State lifetime bounds how long a user has to complete the flow.
const STATE_TTL_SECONDS = 10 * 60;

// ----- bearer helpers -----

function extractBearer(req: Request): string | null {
  const h = req.headers.authorization;
  if (!h || typeof h !== 'string') return null;
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
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

// Refresh upstream access_token if it expires within refreshSkewSeconds.
// Returns the (possibly new) payload and a flag indicating whether a new
// wrapper bearer should be issued to the caller via X-Wrapper-Token.
async function ensureFreshUpstream(
  cfg: Config,
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
  const fresh = await refreshAccessToken(cfg, payload.rt);
  const newPayload: BearerPayload = {
    ...payload,
    at: fresh.access_token,
    rt: fresh.refresh_token ?? payload.rt,
    ate: nowSec() + fresh.expires_in,
    s: fresh.scope ?? payload.s,
  };
  return { payload: newPayload, rotated: true };
}

// ----- app factory -----

export function buildApp(cfg: Config): express.Express {
  const app = express();
  app.disable('x-powered-by');
  // Body parsing: MCP requests are JSON. Token endpoint isn't used by clients here
  // (we expose .well-known but the actual token mint happens via the callback
  // redirect, not a separate /token POST). Keep the limit generous for tool args.
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

  // --- OAuth: start ---
  app.get('/connect/start', (_req, res) => {
    const iat = nowSec();
    const state = encryptState(
      { v: 1, iat, exp: iat + STATE_TTL_SECONDS, n: randomBytes(16).toString('base64url') },
      cfg.encKey,
    );
    const url = buildAuthorizeUrl(cfg, state);
    res.redirect(302, url);
  });

  // --- OAuth: callback ---
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

    try {
      const state = decryptState(stateRaw, cfg.encKey);
      if (state.exp < nowSec()) {
        res.status(400).json({ error: 'state_expired' });
        return;
      }
    } catch (e) {
      if (e instanceof StateError) {
        res.status(400).json({ error: 'invalid_state', detail: e.message });
        return;
      }
      throw e;
    }

    try {
      const token = await exchangeCodeForToken(cfg, code);

      // If BambooHR returns a companyDomain on the token, ensure it matches our
      // configured single-tenant. Don't reject silently — return a clear error.
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

      // Render bearer plainly. Wrapping this in a nicer HTML page is a UX
      // improvement, not a correctness one. The MCP client typically scrapes
      // this from the redirect chain or from an in-process flow.
      res.json({
        token_type: 'Bearer',
        access_token: bearer,
        expires_in: cfg.bearerTtlSeconds,
        scope: token.scope,
      });
    } catch (e) {
      if (e instanceof OAuthError) {
        res.status(e.status ?? 502).json({ error: 'oauth_exchange_failed', detail: e.message });
      } else {
        res.status(500).json({ error: 'internal_error', detail: (e as Error).message });
      }
    }
  });

  // --- Disconnect (stateless) ---
  app.post('/disconnect', (_req, res) => {
    // No server-side session to delete. Client should drop its bearer.
    // BambooHR's OAuth does not (publicly) document a revoke endpoint; if/when
    // one is exposed, call it here using the refresh_token.
    res.json({ status: 'ok', note: 'stateless adapter: discard the bearer client-side' });
  });

  // --- MCP endpoint ---
  app.post('/mcp', async (req: Request, res: Response, next: NextFunction) => {
    const raw = extractBearer(req);
    if (!raw) {
      res.status(401).set('WWW-Authenticate', 'Bearer realm="bamboohr-mcp"').json({
        error: 'missing_bearer',
      });
      return;
    }

    let payload: BearerPayload;
    try {
      payload = decryptBearer(raw, cfg.encKey);
    } catch (e) {
      if (e instanceof BearerError) {
        res.status(401).json({ error: 'invalid_bearer', detail: e.message });
        return;
      }
      next(e);
      return;
    }

    if (payload.exp < nowSec()) {
      res.status(401).json({ error: 'bearer_expired' });
      return;
    }

    let rotated = false;
    try {
      const r = await ensureFreshUpstream(cfg, payload);
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
        // Keep wrapper TTL fresh on refresh too; upstream just rotated, so it's safe.
        expires_in: payload.ate - nowSec(),
        scope: payload.s,
      });
      res.setHeader('X-Wrapper-Token', newBearer);
    }

    const client = makeOAuthClient({
      accessToken: payload.at,
      companyDomain: cfg.companyDomain,
    });

    // Stateless transport per request (matches upstream behavior in dist/index.js).
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

  // --- .well-known discovery (best-effort MCP client compatibility) ---
  // These are intentionally minimal: the adapter is itself the AS for wrapper
  // bearers, and the BambooHR-side OAuth is opaque to MCP clients.
  app.get('/.well-known/oauth-authorization-server', (_req, res) => {
    res.json({
      issuer: cfg.publicBaseUrl,
      authorization_endpoint: `${cfg.publicBaseUrl}/connect/start`,
      // No separate token endpoint: callback returns the bearer directly.
      token_endpoint: `${cfg.publicBaseUrl}/connect/callback`,
      registration_endpoint: `${cfg.publicBaseUrl}/register`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      token_endpoint_auth_methods_supported: ['none'],
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

  app.post('/register', (_req, res) => {
    // Dynamic client registration stub: this adapter is single-tenant and has
    // a fixed BambooHR client. Return a static client_id so MCP clients that
    // require DCR can proceed.
    res.json({
      client_id: 'bamboohr-oauth-mcp',
      token_endpoint_auth_method: 'none',
      redirect_uris: [redirectUri(cfg)],
    });
  });

  // --- Error handler ---
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    // eslint-disable-next-line no-console
    console.error('[adapter] unhandled error:', err);
    if (res.headersSent) return;
    res.status(500).json({ error: 'internal_error', detail: err.message });
  });

  return app;
}
