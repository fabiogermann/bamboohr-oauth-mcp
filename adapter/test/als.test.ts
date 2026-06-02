import { describe, it, expect } from 'vitest';
import { requestCtx, createProxyClient } from '../src/als.js';
import type { BambooHRClient } from '@twentytwokhz/bamboohr-mcp/dist/services/bamboohr-client.js';

describe('als / proxy client', () => {
  it('throws when accessed outside a request context', () => {
    const p = createProxyClient();
    expect(() => (p as unknown as { get: unknown }).get).toThrow(/outside of a request context/);
  });

  it('delegates property reads to the ALS-stored client', async () => {
    const fake = {
      tag: 'real-one',
      get(endpoint: string) {
        return Promise.resolve({ endpoint, fromInstance: (this as { tag: string }).tag });
      },
    };
    const p = createProxyClient();
    await requestCtx.run({ client: fake as unknown as BambooHRClient }, async () => {
      // function call is bound to the real instance so `this` is preserved.
      const r = await (p as unknown as { get(e: string): Promise<{ endpoint: string; fromInstance: string }> }).get('/x');
      expect(r).toEqual({ endpoint: '/x', fromInstance: 'real-one' });
    });
  });

  it('resolves to the current store, not a captured one (per-request isolation)', async () => {
    const a = {
      whoami() {
        return 'A';
      },
    };
    const b = {
      whoami() {
        return 'B';
      },
    };
    const p = createProxyClient() as unknown as { whoami(): string };
    await requestCtx.run({ client: a as unknown as BambooHRClient }, async () => {
      expect(p.whoami()).toBe('A');
      await requestCtx.run({ client: b as unknown as BambooHRClient }, async () => {
        expect(p.whoami()).toBe('B');
      });
      expect(p.whoami()).toBe('A');
    });
  });

  it('returns non-function properties verbatim', async () => {
    const fake = { someField: 42 };
    const p = createProxyClient() as unknown as { someField: number };
    await requestCtx.run({ client: fake as unknown as BambooHRClient }, async () => {
      expect(p.someField).toBe(42);
    });
  });
});
