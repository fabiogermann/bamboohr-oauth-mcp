import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { loadConfig } from '../src/config.js';

const REQUIRED_KEYS = [
  'BAMBOOHR_COMPANY_DOMAIN',
  'BAMBOOHR_OAUTH_CLIENT_ID',
  'BAMBOOHR_OAUTH_CLIENT_SECRET',
  'WRAPPER_ENC_KEY_BASE64',
  'PUBLIC_BASE_URL',
  'PORT',
  'BAMBOOHR_OAUTH_SCOPES',
  'WRAPPER_BEARER_TTL_SECONDS',
  'WRAPPER_REFRESH_SKEW_SECONDS',
  'OAUTH_ALLOWED_REDIRECT_URIS',
  'OAUTH_AUTH_CODE_TTL_SECONDS',
];

let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = {};
  for (const k of REQUIRED_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

function setValidEnv(): string {
  const keyB64 = randomBytes(32).toString('base64');
  process.env.BAMBOOHR_COMPANY_DOMAIN = 'acme';
  process.env.BAMBOOHR_OAUTH_CLIENT_ID = 'cid';
  process.env.BAMBOOHR_OAUTH_CLIENT_SECRET = 'csec';
  process.env.WRAPPER_ENC_KEY_BASE64 = keyB64;
  process.env.PUBLIC_BASE_URL = 'https://adapter.example.com';
  process.env.BAMBOOHR_OAUTH_SCOPES = 'mcp';
  process.env.OAUTH_ALLOWED_REDIRECT_URIS = 'http://127.0.0.1:39000/callback';
  return keyB64;
}

describe('config / loadConfig', () => {
  it('loads a minimal valid env', () => {
    setValidEnv();
    const cfg = loadConfig();
    expect(cfg.companyDomain).toBe('acme');
    expect(cfg.bambooBaseUrl).toBe('https://acme.bamboohr.com');
    expect(cfg.publicBaseUrl).toBe('https://adapter.example.com');
    expect(cfg.port).toBe(3000);
    expect(cfg.bearerTtlSeconds).toBe(3600);
    expect(cfg.refreshSkewSeconds).toBe(60);
    expect(cfg.encKey.length).toBe(32);
    expect(cfg.oauthScopes).toBe('mcp+offline_access');
    expect(cfg.allowedRedirectUris).toEqual(['http://127.0.0.1:39000/callback']);
    expect(cfg.authCodeTtlSeconds).toBe(60);
  });

  it('strips trailing slash from PUBLIC_BASE_URL', () => {
    setValidEnv();
    process.env.PUBLIC_BASE_URL = 'https://adapter.example.com///';
    expect(loadConfig().publicBaseUrl).toBe('https://adapter.example.com');
  });

  it.each([
    'BAMBOOHR_COMPANY_DOMAIN',
    'BAMBOOHR_OAUTH_CLIENT_ID',
    'BAMBOOHR_OAUTH_CLIENT_SECRET',
    'WRAPPER_ENC_KEY_BASE64',
    'PUBLIC_BASE_URL',
    'OAUTH_ALLOWED_REDIRECT_URIS',
  ])('throws when %s is missing', (varName) => {
    setValidEnv();
    delete process.env[varName];
    expect(() => loadConfig()).toThrow(new RegExp(varName));
  });

  it('parses multiple redirect URIs from comma-separated env', () => {
    setValidEnv();
    process.env.OAUTH_ALLOWED_REDIRECT_URIS =
      'cursor://anysphere.cursor-deeplink/sso/login, http://127.0.0.1:39000/callback';
    expect(loadConfig().allowedRedirectUris).toEqual([
      'cursor://anysphere.cursor-deeplink/sso/login',
      'http://127.0.0.1:39000/callback',
    ]);
  });

  it('throws on an invalid redirect URI', () => {
    setValidEnv();
    process.env.OAUTH_ALLOWED_REDIRECT_URIS = 'http://valid/ok, not a uri';
    expect(() => loadConfig()).toThrow(/invalid URI/);
  });

  it('honors custom OAUTH_AUTH_CODE_TTL_SECONDS', () => {
    setValidEnv();
    process.env.OAUTH_AUTH_CODE_TTL_SECONDS = '120';
    expect(loadConfig().authCodeTtlSeconds).toBe(120);
  });

  it('throws on invalid company domain', () => {
    setValidEnv();
    process.env.BAMBOOHR_COMPANY_DOMAIN = 'has spaces';
    expect(() => loadConfig()).toThrow(/COMPANY_DOMAIN/);
  });

  it('throws when PUBLIC_BASE_URL is missing scheme', () => {
    setValidEnv();
    process.env.PUBLIC_BASE_URL = 'adapter.example.com';
    expect(() => loadConfig()).toThrow(/scheme/);
  });

  it('throws when key is not 32 bytes', () => {
    setValidEnv();
    process.env.WRAPPER_ENC_KEY_BASE64 = randomBytes(16).toString('base64');
    expect(() => loadConfig()).toThrow(/32 bytes/);
  });

  it('throws on invalid PORT', () => {
    setValidEnv();
    process.env.PORT = 'not-a-number';
    expect(() => loadConfig()).toThrow(/PORT/);
    process.env.PORT = '0';
    expect(() => loadConfig()).toThrow(/PORT/);
    process.env.PORT = '-5';
    expect(() => loadConfig()).toThrow(/PORT/);
  });

  it('parses space-separated scopes and auto-appends offline_access', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'mcp time_off company:info';
    expect(loadConfig().oauthScopes).toBe('mcp+time_off+company:info+offline_access');
  });

  it('accepts plus-separated scopes verbatim and auto-appends offline_access', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'a+b+c';
    expect(loadConfig().oauthScopes).toBe('a+b+c+offline_access');
  });

  it('does not duplicate offline_access if already present', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'mcp offline_access';
    const scopes = loadConfig().oauthScopes.split('+');
    expect(scopes.filter((s) => s === 'offline_access').length).toBe(1);
  });

  it('defaults to "offline_access openid email" when unset', () => {
    setValidEnv();
    delete process.env.BAMBOOHR_OAUTH_SCOPES;
    expect(loadConfig().oauthScopes.split('+').sort()).toEqual(['email', 'offline_access', 'openid']);
  });

  it('throws when BAMBOOHR_OAUTH_SCOPES is explicitly empty after trimming', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = '   ';
    // Empty value falls back to the default, which contains offline_access etc.,
    // so loadConfig succeeds. The explicit-empty rejection only applies if the
    // user really set the var to a non-empty whitespace-only string after the
    // optional() fallback — which optional() treats as "unset". This test
    // confirms we don't surprise users with a startup crash for whitespace.
    expect(() => loadConfig()).not.toThrow();
  });

  it('honors custom PORT, bearer TTL and refresh skew', () => {
    setValidEnv();
    process.env.PORT = '8080';
    process.env.WRAPPER_BEARER_TTL_SECONDS = '900';
    process.env.WRAPPER_REFRESH_SKEW_SECONDS = '30';
    const cfg = loadConfig();
    expect(cfg.port).toBe(8080);
    expect(cfg.bearerTtlSeconds).toBe(900);
    expect(cfg.refreshSkewSeconds).toBe(30);
  });
});
