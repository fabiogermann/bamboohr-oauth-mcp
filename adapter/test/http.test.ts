import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import { createHash, randomBytes } from 'node:crypto';
import { buildApp } from '../src/http.js';
import type { Config } from '../src/config.js';
import {
  encryptBearer,
  encryptAuthRequest,
  encryptAuthCode,
  type BearerPayload,
  type AuthRequestPayload,
  type AuthCodePayload,
} from '../src/crypto.js';

const KEY = randomBytes(32);
const REDIRECT_URI = 'http://127.0.0.1:39000/callback';

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
    authCodeTtlSeconds: 60,
    allowedRedirectUris: [REDIRECT_URI],
    ...overrides,
  };
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url');
  return { verifier, challenge };
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

function mintAuthRequest(payload: Partial<AuthRequestPayload> = {}): string {
  const base: AuthRequestPayload = {
    v: 1,
    iat: nowSec(),
    exp: nowSec() + 600,
    ci: 'bamboohr-oauth-mcp',
    ru: REDIRECT_URI,
    cs: 'client-state',
    cc: pkcePair().challenge,
    sc: 'mcp',
    ...payload,
  };
  return encryptAuthRequest(base, KEY);
}

function mintAuthCode(payload: Partial<AuthCodePayload> = {}): string {
  const base: AuthCodePayload = {
    v: 1,
    iat: nowSec(),
    exp: nowSec() + 60,
    b: 'wrapped-bearer-placeholder',
    ru: REDIRECT_URI,
    cc: pkcePair().challenge,
    eb: nowSec() + 3600,
    sc: 'mcp',
    ...payload,
  };
  return encryptAuthCode(base, KEY);
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
  vi.restoreAllMocks();
});

const app = buildApp(cfg());

// ----- /healthz -----
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

// ----- /.well-known -----
describe('http / .well-known', () => {
  it('serves authorization-server metadata with /authorize + /token', async () => {
    const res = await request(app).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe('https://adapter.example.com');
    expect(res.body.authorization_endpoint).toBe('https://adapter.example.com/authorize');
    expect(res.body.token_endpoint).toBe('https://adapter.example.com/token');
    expect(res.body.code_challenge_methods_supported).toContain('S256');
    expect(res.body.scopes_supported).toContain('offline_access');
  });

  it('serves protected-resource metadata', async () => {
    const res = await request(app).get('/.well-known/oauth-protected-resource');
    expect(res.status).toBe(200);
    expect(res.body.resource).toBe('https://adapter.example.com/mcp');
    expect(res.body.bearer_methods_supported).toContain('header');
  });
});

// ----- /authorize -----
describe('http / /authorize', () => {
  it('rejects missing response_type', async () => {
    const res = await request(app).get('/authorize');
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_response_type');
  });

  it('rejects missing client_id', async () => {
    const res = await request(app).get('/authorize').query({ response_type: 'code' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('rejects redirect_uri not in allowlist', async () => {
    const { challenge } = pkcePair();
    const res = await request(app).get('/authorize').query({
      response_type: 'code',
      client_id: 'cid',
      redirect_uri: 'http://evil.example.com/steal',
      state: 'abc',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
  });

  it('rejects missing PKCE', async () => {
    const res = await request(app).get('/authorize').query({
      response_type: 'code',
      client_id: 'cid',
      redirect_uri: REDIRECT_URI,
      state: 'abc',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
    expect(res.body.detail).toMatch(/PKCE/);
  });

  it('rejects code_challenge_method other than S256', async () => {
    const res = await request(app).get('/authorize').query({
      response_type: 'code',
      client_id: 'cid',
      redirect_uri: REDIRECT_URI,
      state: 'abc',
      code_challenge: 'whatever',
      code_challenge_method: 'plain',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('302-redirects to BambooHR with encrypted AuthRequest as state', async () => {
    const { challenge } = pkcePair();
    const res = await request(app).get('/authorize').query({
      response_type: 'code',
      client_id: 'cid',
      redirect_uri: REDIRECT_URI,
      state: 'client-state-x',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      scope: 'mcp time_off',
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(loc.host).toBe('acme.bamboohr.com');
    expect(loc.pathname).toBe('/authorize.php');
    const state = loc.searchParams.get('state');
    expect(state).toBeTruthy();
    expect(state).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

// ----- /connect/callback -----
describe('http / /connect/callback', () => {
  it('rejects when code is missing', async () => {
    const state = mintAuthRequest();
    const res = await request(app).get(`/connect/callback?state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
  });

  it('rejects when state is missing', async () => {
    const res = await request(app).get('/connect/callback?code=abc');
    expect(res.status).toBe(400);
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

  it('rejects expired AuthRequest state', async () => {
    const expired = mintAuthRequest({ exp: nowSec() - 1 });
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(expired)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('state_expired');
  });

  it('rejects callback whose embedded redirect_uri is no longer in the allowlist', async () => {
    const state = mintAuthRequest({ ru: 'http://stale.example.com/cb' });
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
  });

  it('exchanges code, mints an auth code, and 302s to the client redirect_uri with code+state', async () => {
    const fakeFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'fresh-at',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'mcp',
          refresh_token: 'fresh-rt',
          companyDomain: 'acme',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    );
    global.fetch = fakeFetch as unknown as typeof fetch;

    const state = mintAuthRequest({ cs: 'client-state-xyz' });
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.location);
    expect(`${loc.protocol}//${loc.host}${loc.pathname}`).toBe(REDIRECT_URI);
    expect(loc.searchParams.get('state')).toBe('client-state-xyz');
    const code = loc.searchParams.get('code');
    expect(code).toBeTruthy();
    expect(code).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('rejects token issued for a different tenant', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          access_token: 'at',
          expires_in: 3600,
          token_type: 'Bearer',
          scope: 'mcp',
          companyDomain: 'someoneelse',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      ),
    ) as unknown as typeof fetch;
    const state = mintAuthRequest();
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('tenant_mismatch');
  });

  it('surfaces an OAuth provider HTTP error', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response('bad code', { status: 400 })) as unknown as typeof fetch;
    const state = mintAuthRequest();
    const res = await request(app).get(`/connect/callback?code=c&state=${encodeURIComponent(state)}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('oauth_exchange_failed');
  });
});

// ----- /token -----
describe('http / /token', () => {
  it('rejects unsupported grant_type', async () => {
    const res = await request(app).post('/token').type('form').send({ grant_type: 'password' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unsupported_grant_type');
  });

  it('rejects missing fields', async () => {
    const res = await request(app).post('/token').type('form').send({ grant_type: 'authorization_code' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  it('rejects malformed auth code', async () => {
    const res = await request(app).post('/token').type('form').send({
      grant_type: 'authorization_code',
      code: 'garbage',
      redirect_uri: REDIRECT_URI,
      code_verifier: 'whatever',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects expired auth code', async () => {
    const { verifier, challenge } = pkcePair();
    const code = mintAuthCode({ exp: nowSec() - 1, cc: challenge });
    const res = await request(app).post('/token').type('form').send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
    expect(res.body.detail).toMatch(/expired/);
  });

  it('rejects redirect_uri mismatch', async () => {
    const { verifier, challenge } = pkcePair();
    const code = mintAuthCode({ ru: REDIRECT_URI, cc: challenge });
    const res = await request(app).post('/token').type('form').send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'http://other.example.com/cb',
      code_verifier: verifier,
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
    expect(res.body.detail).toMatch(/redirect_uri mismatch/);
  });

  it('rejects PKCE failure', async () => {
    const { challenge } = pkcePair();
    const code = mintAuthCode({ cc: challenge });
    const res = await request(app).post('/token').type('form').send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: 'this-is-not-the-right-verifier',
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
    expect(res.body.detail).toMatch(/PKCE/);
  });

  it('returns the wrapped bearer on valid PKCE + redirect_uri match', async () => {
    const { verifier, challenge } = pkcePair();
    const bearerToken = mintBearerToken();
    const code = mintAuthCode({ b: bearerToken, cc: challenge, eb: nowSec() + 1800, sc: 'mcp' });
    const res = await request(app).post('/token').type('form').send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    });
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.access_token).toBe(bearerToken);
    expect(res.body.scope).toBe('mcp');
    expect(res.body.expires_in).toBeGreaterThan(0);
    expect(res.body.expires_in).toBeLessThanOrEqual(1800);
  });

  it('accepts JSON body in addition to form-urlencoded', async () => {
    const { verifier, challenge } = pkcePair();
    const code = mintAuthCode({ cc: challenge });
    const res = await request(app)
      .post('/token')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      });
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
  });
});

// ----- /register -----
describe('http / /register', () => {
  it('echoes allowed redirect_uris and returns adapter client_id', async () => {
    const res = await request(app).post('/register').send({ redirect_uris: [REDIRECT_URI] });
    expect(res.status).toBe(201);
    expect(res.body.client_id).toBe('bamboohr-oauth-mcp');
    expect(res.body.redirect_uris).toEqual([REDIRECT_URI]);
    expect(res.body.token_endpoint_auth_method).toBe('none');
  });

  it('rejects unknown redirect_uris', async () => {
    const res = await request(app).post('/register').send({ redirect_uris: ['http://evil/cb'] });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
  });

  it('returns the entire allowlist when client sent none', async () => {
    const res = await request(app).post('/register').send({});
    expect(res.status).toBe(201);
    expect(res.body.redirect_uris).toEqual([REDIRECT_URI]);
  });
});

// ----- /disconnect -----
describe('http / /disconnect', () => {
  it('returns stateless ack', async () => {
    const res = await request(app).post('/disconnect');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

// ----- /mcp auth gating (unchanged) -----
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

  it('coalesces concurrent refreshes on the same bearer to a single upstream call', async () => {
    let resolveTokenCall: (resp: Response) => void = () => {};
    const tokenPromise = new Promise<Response>((res) => {
      resolveTokenCall = res;
    });
    const fakeFetch = vi.fn().mockImplementation(() => tokenPromise);
    global.fetch = fakeFetch as unknown as typeof fetch;

    const token = mintBearerToken({ ate: nowSec() + 1, rt: 'old-rt' });
    // supertest's Test doesn't dispatch until `.then` is called. Chain a no-op
    // `.then` on each to force the HTTP request to be sent now; the resulting
    // promises are awaited later via Promise.all.
    const send = () =>
      request(app)
        .post('/mcp')
        .set('authorization', `Bearer ${token}`)
        .set('content-type', 'application/json')
        .send({})
        .then((r) => r);
    const inflight = [send(), send(), send()];

    // Yield enough microtasks for all three /mcp handlers to reach the
    // singleFlight call. setTimeout(0) flushes pending I/O; one tick is enough
    // in practice but we use a small delay for safety.
    await new Promise((r) => setTimeout(r, 30));

    resolveTokenCall(
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

    const results = await Promise.all(inflight);
    expect(results[0].headers['x-wrapper-token']).toBeTruthy();
    expect(results[1].headers['x-wrapper-token']).toBeTruthy();
    expect(results[2].headers['x-wrapper-token']).toBeTruthy();
    expect(fakeFetch).toHaveBeenCalledTimes(1);
  });
});
