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
    expect(cfg.oauthScopes).toBe('mcp');
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
    'BAMBOOHR_OAUTH_SCOPES',
  ])('throws when %s is missing', (varName) => {
    setValidEnv();
    delete process.env[varName];
    expect(() => loadConfig()).toThrow(new RegExp(varName));
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

  it('parses space-separated scopes verbatim (no auto-append)', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'mcp time_off company:info';
    expect(loadConfig().oauthScopes).toBe('mcp+time_off+company:info');
  });

  it('accepts plus-separated scopes verbatim', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'a+b+c';
    expect(loadConfig().oauthScopes).toBe('a+b+c');
  });

  it('does not inject offline_access', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = 'mcp';
    expect(loadConfig().oauthScopes.split('+')).not.toContain('offline_access');
  });

  it('throws when BAMBOOHR_OAUTH_SCOPES is empty after trimming', () => {
    setValidEnv();
    process.env.BAMBOOHR_OAUTH_SCOPES = '   ';
    expect(() => loadConfig()).toThrow(/BAMBOOHR_OAUTH_SCOPES/);
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
