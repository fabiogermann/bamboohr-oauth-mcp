import { describe, it, expect } from 'vitest';
import { buildAuthorizeUrl, redirectUri } from '../src/oauth-client.js';
import type { Config } from '../src/config.js';

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    port: 3000,
    publicBaseUrl: 'https://adapter.example.com',
    companyDomain: 'acme',
    bambooBaseUrl: 'https://acme.bamboohr.com',
    oauthClientId: 'client_id_42',
    oauthClientSecret: 'secret',
    oauthScopes: 'read.employees+offline_access',
    encKey: Buffer.alloc(32),
    bearerTtlSeconds: 3600,
    refreshSkewSeconds: 60,
    ...overrides,
  };
}

describe('oauth-client / redirectUri', () => {
  it('uses publicBaseUrl + /connect/callback', () => {
    expect(redirectUri(cfg())).toBe('https://adapter.example.com/connect/callback');
  });
});

describe('oauth-client / buildAuthorizeUrl', () => {
  it('targets the tenant-specific authorize.php', () => {
    const u = new URL(buildAuthorizeUrl(cfg(), 'STATE-VAL'));
    expect(u.host).toBe('acme.bamboohr.com');
    expect(u.pathname).toBe('/authorize.php');
  });

  it('includes required OAuth params', () => {
    const u = new URL(buildAuthorizeUrl(cfg(), 'STATE-VAL'));
    expect(u.searchParams.get('request')).toBe('authorize');
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('state')).toBe('STATE-VAL');
    expect(u.searchParams.get('client_id')).toBe('client_id_42');
    expect(u.searchParams.get('redirect_uri')).toBe('https://adapter.example.com/connect/callback');
  });

  it('preserves + separators in scope (does not url-encode)', () => {
    const url = buildAuthorizeUrl(cfg({ oauthScopes: 'a+b+c' }), 'st');
    // Raw URL string must contain `&scope=a+b+c`, not `&scope=a%2Bb%2Bc`
    expect(url).toContain('&scope=a+b+c');
    expect(url).not.toContain('a%2Bb');
  });

  it('does not double-add scope when other params are present', () => {
    const url = buildAuthorizeUrl(cfg(), 'st');
    const matches = url.match(/[?&]scope=/g) || [];
    expect(matches.length).toBe(1);
  });
});
