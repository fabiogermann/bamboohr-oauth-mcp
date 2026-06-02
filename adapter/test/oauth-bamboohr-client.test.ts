import { describe, it, expect } from 'vitest';
import { BambooHRClient } from '@twentytwokhz/bamboohr-mcp/dist/services/bamboohr-client.js';
import { makeOAuthClient } from '../src/oauth-bamboohr-client.js';

// Importing the module above patches BambooHRClient.prototype.getAuthHeader.
// These tests verify the patch is correct AND that the original Basic auth
// fallback still works for instances that don't carry a bearer.

interface ProtoExposed {
  getAuthHeader: () => string;
}

function protoCall(instance: BambooHRClient): string {
  return (BambooHRClient.prototype as unknown as ProtoExposed).getAuthHeader.call(instance);
}

describe('oauth-bamboohr-client / patched getAuthHeader', () => {
  it('returns Bearer header for an OAuth-constructed client', () => {
    const c = makeOAuthClient({ accessToken: 'abc.def.ghi', companyDomain: 'acme' });
    expect(protoCall(c)).toBe('Bearer abc.def.ghi');
  });

  it('falls back to original Basic auth when no bearer is set', () => {
    const c = new BambooHRClient({ apiKey: 'apikey123', companyDomain: 'acme' });
    const header = protoCall(c);
    expect(header.startsWith('Basic ')).toBe(true);
    const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
    expect(decoded).toBe('apikey123:x');
  });

  it('sets baseUrl from companyDomain (untouched by patch)', () => {
    const c = makeOAuthClient({ accessToken: 't', companyDomain: 'tenant-x' });
    // baseUrl is private in d.ts but present at runtime.
    const url = (c as unknown as { baseUrl: string }).baseUrl;
    expect(url).toContain('https://tenant-x.bamboohr.com/api/');
  });

  it('is idempotent under re-import (does not double-wrap)', async () => {
    // Re-import (cached) and confirm bearer behavior still works exactly once.
    await import('../src/oauth-bamboohr-client.js');
    await import('../src/oauth-bamboohr-client.js');
    const c = makeOAuthClient({ accessToken: 'token', companyDomain: 'acme' });
    expect(protoCall(c)).toBe('Bearer token');
  });

  it('different instances carry independent bearers', () => {
    const a = makeOAuthClient({ accessToken: 'A', companyDomain: 'acme' });
    const b = makeOAuthClient({ accessToken: 'B', companyDomain: 'acme' });
    expect(protoCall(a)).toBe('Bearer A');
    expect(protoCall(b)).toBe('Bearer B');
  });
});
