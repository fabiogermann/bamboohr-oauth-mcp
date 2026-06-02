import { describe, it, expect, vi } from 'vitest';
import { bearerKey, singleFlight, _inflightSize } from '../src/refresh.js';

describe('refresh / bearerKey', () => {
  it('is deterministic for the same input', () => {
    expect(bearerKey('abc')).toBe(bearerKey('abc'));
  });

  it('differs for different inputs', () => {
    expect(bearerKey('abc')).not.toBe(bearerKey('xyz'));
  });

  it('is 64 hex chars (sha256)', () => {
    expect(bearerKey('anything')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('refresh / singleFlight', () => {
  it('runs fn once for concurrent calls with the same key and returns the same value', async () => {
    const fn = vi.fn().mockImplementation(
      () => new Promise<string>((res) => setTimeout(() => res('result'), 20)),
    );
    const [a, b, c] = await Promise.all([
      singleFlight('k1', fn),
      singleFlight('k1', fn),
      singleFlight('k1', fn),
    ]);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(a).toBe('result');
    expect(b).toBe('result');
    expect(c).toBe('result');
  });

  it('runs fn per distinct key', async () => {
    const fn = vi.fn().mockImplementation(async (k: string) => `for-${k}`);
    const [a, b] = await Promise.all([
      singleFlight('keyA', () => fn('A')),
      singleFlight('keyB', () => fn('B')),
    ]);
    expect(fn).toHaveBeenCalledTimes(2);
    expect(a).toBe('for-A');
    expect(b).toBe('for-B');
  });

  it('clears the in-flight entry after success so a later call re-invokes fn', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    await singleFlight('reuseKey-1', fn);
    await singleFlight('reuseKey-1', fn);
    expect(fn).toHaveBeenCalledTimes(2);
    expect(_inflightSize()).toBe(0);
  });

  it('clears the in-flight entry after failure and propagates to all awaiters', async () => {
    const fn = vi.fn().mockImplementation(
      () => new Promise<string>((_res, rej) => setTimeout(() => rej(new Error('boom')), 10)),
    );
    const calls = [
      singleFlight('failKey', fn).catch((e) => e.message),
      singleFlight('failKey', fn).catch((e) => e.message),
    ];
    const results = await Promise.all(calls);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(results).toEqual(['boom', 'boom']);
    // Map should be cleared so a fresh call invokes fn again.
    const fn2 = vi.fn().mockResolvedValue('ok');
    await singleFlight('failKey', fn2);
    expect(fn2).toHaveBeenCalledTimes(1);
  });
});
