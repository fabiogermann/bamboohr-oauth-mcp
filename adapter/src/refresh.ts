// Per-process single-flight refresh.
//
// Problem: under concurrent /mcp load, two requests carrying the same wrapper
// bearer can both observe upstream access_token expiry and both call BambooHR's
// refresh endpoint. If BambooHR rotates refresh tokens (single-use), the
// second call invalidates the first's RT and the affected request fails.
//
// Solution: dedupe in-flight refreshes by a stable per-bearer key. The first
// caller starts the refresh; concurrent callers await the same promise. When
// the promise resolves (or rejects), the entry is removed so the next batch
// of requests can refresh again the next time the access_token nears expiry.
//
// Storage: a plain Map in this process. No Redis, no cache, no persistence.
// Survives only for the lifetime of in-flight requests.
//
// Multi-replica behavior:
//   - Single replica: races are fully eliminated.
//   - N replicas with random routing: races reduced by N but still possible
//     when two requests on the same bearer happen to land on different pods.
//     The recommended fix is ingress-level affinity by Authorization header
//     hash (see README). The adapter remains stateless; coordination lives
//     in the load balancer that already exists.

import { createHash } from 'node:crypto';

/**
 * Key derived from the raw wrapper bearer. We hash to keep the key short
 * and to avoid keeping the bearer plaintext in the Map's keys (a minor
 * defense-in-depth concern, since the bearer also lives in the call stack
 * during the request lifetime).
 */
export function bearerKey(rawBearer: string): string {
  return createHash('sha256').update(rawBearer, 'utf8').digest('hex');
}

const inflight = new Map<string, Promise<unknown>>();

/**
 * Coalesce concurrent calls keyed by `key` to a single invocation of `fn`.
 * Subsequent callers await the same promise. The entry is removed in a
 * `finally` so the next refresh cycle starts fresh.
 *
 * The returned promise is type-narrowed to T per invocation, even though
 * the underlying Map stores Promise<unknown> to support different result
 * types on different keys.
 */
export async function singleFlight<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const existing = inflight.get(key);
  if (existing) {
    return existing as Promise<T>;
  }
  const p = (async () => fn())().finally(() => {
    // Only delete if we're still the in-flight entry (paranoia against a
    // theoretical race where the entry was already replaced — shouldn't
    // happen with current code paths but harmless either way).
    if (inflight.get(key) === p) inflight.delete(key);
  });
  inflight.set(key, p);
  return p;
}

/** Test/diagnostic helper. */
export function _inflightSize(): number {
  return inflight.size;
}
