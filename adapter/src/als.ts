// AsyncLocalStorage context: carries the per-request BambooHRClient through
// the entire async call chain of every tool handler invocation.
//
// The MCP server is built ONCE at boot. All tool handlers close over a single
// proxy object that, on every property access, looks up the live client from ALS.
// Each HTTP request opens an ALS scope, constructs a fresh OAuthBambooHRClient
// from that user's decrypted bearer, and runs the MCP transport inside it.

import { AsyncLocalStorage } from 'node:async_hooks';
import type { BambooHRClient } from '@twentytwokhz/bamboohr-mcp/dist/services/bamboohr-client.js';

interface RequestContext {
  client: BambooHRClient;
}

export const requestCtx = new AsyncLocalStorage<RequestContext>();

/**
 * Build a proxy that looks like a BambooHRClient but delegates every property
 * access to the client stored in the current ALS context.
 *
 * The upstream tool registration functions (registerEmployeeTools etc.) accept
 * a `client: BambooHRClient` and store it in handler closures. The handlers
 * call methods on that closure ref (e.g. `client.get(...)`). By passing this
 * proxy as the closure ref, every method invocation transparently resolves to
 * the real per-request client at call time.
 *
 * Property access returns a bound function so `this` inside the upstream method
 * is the real client (preserving access to internal fields like this.baseUrl,
 * this.cache, this.getHeaders, etc.).
 */
export function createProxyClient(): BambooHRClient {
  const handler: ProxyHandler<object> = {
    get(_target, prop, _receiver) {
      const ctx = requestCtx.getStore();
      if (!ctx) {
        throw new Error(
          `BambooHR client accessed outside of a request context (no ALS store). ` +
            `This is a bug in the adapter: tool handler ran outside requestCtx.run().`,
        );
      }
      const real = ctx.client as unknown as Record<string | symbol, unknown>;
      const value = real[prop];
      if (typeof value === 'function') {
        return (value as (...args: unknown[]) => unknown).bind(real);
      }
      return value;
    },
  };
  return new Proxy({}, handler) as unknown as BambooHRClient;
}
