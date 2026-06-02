import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import { randomBytes } from 'node:crypto';
import { buildApp } from '../src/http.js';
import type { Config } from '../src/config.js';
import {
  encryptBearer,
  encryptState,
  type BearerPayload,
  type StatePayload,
} from '../src/crypto.js';

const KEY = randomBytes(32);

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    publicBaseUrl: 'https://adapter.example.com',
    companyDomain: 'acme',
    bambooBaseUrl: 'https://acme.bamboohr.com',
    oauthClientId: 'cid',
    oauthClientSecret: 'csec',
    oauthScopes: 'offline_access',
    encKey: KEY,
    bearerTtlSeconds: 3600,
    refreshSkewSeconds: 60,
    ...overrides,
  };
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function mintBearerToken(payload: Partial<BearerPayload> = {}): string {
  const base: BearerPayload = {
    v: 1,
    iat: nowSec(),
    exp: nowSec() + 3600,
    at: 'upstream-at',
    rt: 'upstream-rt',
    ate: nowSec() + 3000,
    d: 'acme',
    s: 'offline_access',
    ...payload,
  };
  return encryptBearer(base, KEY);
}

function mintStateToken(payload: Partial<StatePayload> = {}): string {
  const base: StatePayload = {
    v: 1,
    iat: nowSec(),
    exp: nowSec() + 600,
    n: 'nonce',
    ...payload,
  };
  return encryptState(base, KEY);
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
  vi.restoreAllMocks();
});

// Build the app once per suite (it's idempotent and registers tools at boot).
// Each test still gets a fresh supertest instance via request(app).
const app = buildApp(cfg());

describe('http / healthz', () => {
  it('GET /healthz returns service info', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      status: 'ok',
      service: 'bamboohr-oauth-mcp',
      companyDomain: 'acme',
    });
  });
});

describe('http / .well-known', () => {
  it('serves authorization-server metadata', async () => {
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe('https://adapter.example.com');
    expect(res.body.authorization_endpoint).toBe('https://adapter.example.com/connect/start');
    expect(res.body.scopes_supported).toContain('offline_access');
  });

  it('serves protected-resource metadata', async () => {
    const res = await request(app).get('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe('https://adapter.example.com/mcp');
    expect(res.body.bearer_methods_supported).toContain('header');
  });
});

describe('http / /connect/start', () => {
  it('302-redirects to BambooHR authorize.php with an encrypted state', async () => {
    const res = await request(app).get('/connect/start');
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe('acme.bamboohr.com');
    expect(loc.pathname).toBe('/authorize.php');
    const state = loc.searchParams.get('state');
    expect(state).toBeTruthy();
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('http / /connect/callback', () => {
  it('rejects when code is missing', async () => {
    const state = mintStateToken();
    const res = await request(app).get(`/connect/callback?state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing code or state');
  });

  it('rejects when state is missing', async () => {
    const res = await request(app).get('/connect/callback?code=abc');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('missing code or state');
  });

  it('rejects an oauth-provider error', async () => {
    const res = await request(app).get('/connect/callback?error=access_denied');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('oauth_provider_error');
  });

  it('rejects malformed state', async () => {
    const res = await request(app).get('/connect/callback?code=c&state=garbage');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_state');
  });

  it('rejects expired state', async () => {
    const expired = mintStateToken({ exp: nowSec() - 1 });
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(expired)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('state_expired');
  });

  it('exchanges code for token and mints a wrapper bearer', async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'fresh-at',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'offline_access',
          refresh_token: 'fresh-rt',
          companyDomain: 'acme',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    global.fetch = fakeFetch as unknown as typeof fetch;

    const state = mintStateToken();
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.access_token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(res.body.expires_in).toBe(3600);
    expect(fakeFetch).toHaveBeenCalledTimes(1);
    const [calledUrl] = fakeFetch.mock.calls[0];
    expect(String(calledUrl)).toBe('https://acme.bamboohr.com/token.php?request=token');
  });

  it('rejects token issued for a different tenant', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'at',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'offline_access',
          companyDomain: 'someoneelse',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;
    const state = mintStateToken();
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('tenant_mismatch');
  });

  it('surfaces an OAuth provider HTTP error', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response('bad code', { status: 400 })) as unknown as typeof fetch;
    const state = mintStateToken();
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('oauth_exchange_failed');
  });
});

describe('http / /disconnect', () => {
  it('returns stateless ack', async () => {
    const res = await request(app).post('/disconnect');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('http / /mcp auth gating', () => {
  it('rejects requests with no Authorization', async () => {
    const res = await request(app).post('/mcp').set('content-type', 'application/json').send({});
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('missing_bearer');
    expect(res.headers['www-authenticate']).toMatch(/Bearer/);
  });

  it('rejects a malformed bearer', async () => {
    const res = await request(app)
      .post('/mcp')
      .set('authorization', 'Bearer garbage-token')
      .set('content-type', 'application/json')
      .send({});
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('invalid_bearer');
  });

  it('rejects an expired wrapper bearer', async () => {
    const token = mintBearerToken({ exp: nowSec() - 60 });
    const res = await request(app)
      .post('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('content-type', 'application/json')
      .send({});
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('bearer_expired');
  });

  it('rejects when upstream is expired and no refresh token is available', async () => {
    const token = mintBearerToken({ ate: nowSec() - 1, rt: null });
    const res = await request(app)
      .post('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('content-type', 'application/json')
      .send({});
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('upstream_refresh_failed');
  });

  it('refreshes upstream and returns a rotated X-Wrapper-Token when token is near expiry', async () => {
    // Token endpoint is hit (refresh). MCP endpoint then attempts an MCP
    // protocol message which will fail at the JSON-RPC layer because we sent
    // an empty body — that's fine; we only assert the refresh side-effect.
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'rotated-at',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'offline_access',
          refresh_token: 'rotated-rt',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    global.fetch = fakeFetch as unknown as typeof fetch;

    const token = mintBearerToken({ ate: nowSec() + 1, rt: 'old-rt' });
    const res = await request(app)
      .post('/mcp')
      .set('authorization', `Bearer ${token}`)
      .set('content-type', 'application/json')
      .send({});

    expect(res.headers['x-wrapper-token']).toBeTruthy();
    expect(res.headers['x-wrapper-token']).not.toBe(token);
    expect(fakeFetch).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fakeFetch.mock.calls[0];
    expect(String(calledUrl)).toBe('https://acme.bamboohr.com/token.php?request=token');
    const body = JSON.parse(String((init as RequestInit).body));
    expect(body.grant_type).toBe('refresh_token');
    expect(body.refresh_token).toBe('old-rt');
  });
});
