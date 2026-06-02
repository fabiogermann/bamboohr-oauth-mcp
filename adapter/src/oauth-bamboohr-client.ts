// Per-request BambooHR client with bearer auth.
//
// Why prototype-patch rather than subclass:
//   Upstream's .d.ts declares getAuthHeader() as `private`. TypeScript blocks
//   override-by-subclass. At runtime, `private` is erased — getAuthHeader is
//   just a normal prototype method. We patch BambooHRClient.prototype.getAuthHeader
//   ONCE at module load, making it bearer-aware: when an instance has
//   __bearerToken set, it returns "Bearer <token>"; otherwise it falls back to
//   the original Basic auth implementation (so the upstream class remains
//   usable in its original form should anything else construct it).
//
// We then expose `makeOAuthClient(...)` which constructs an instance whose
// `apiKey` is a sentinel (never read because our patched getAuthHeader returns
// early) and whose `companyDomain` is the real value (used to build baseUrl).

import { BambooHRClient } from '@twentytwokhz/bamboohr-mcp/dist/services/bamboohr-client.js';

const APIKEY_SENTINEL = '__oauth_adapter_unused__';
const BEARER_FIELD = '__bearerToken' as const;

interface BearerAware {
  [BEARER_FIELD]?: string;
}

// Capture the original to use as fallback (and to avoid double-patching).
const protoAny = BambooHRClient.prototype as unknown as {
  getAuthHeader: (this: unknown) => string;
  __oauthPatched?: boolean;
};

if (!protoAny.__oauthPatched) {
  const originalGetAuthHeader = protoAny.getAuthHeader;
  protoAny.getAuthHeader = function (this: unknown): string {
    const self = this as BearerAware;
    const t = self[BEARER_FIELD];
    if (typeof t === 'string' && t.length > 0) {
      return `Bearer ${t}`;
    }
    return originalGetAuthHeader.call(this);
  };
  protoAny.__oauthPatched = true;
}

/**
 * Build a BambooHRClient instance configured to use the supplied OAuth access
 * token for every request. The instance's apiKey field is never read by the
 * patched getAuthHeader and is set to a sentinel for clarity in any debugger.
 */
export function makeOAuthClient(opts: {
  accessToken: string;
  companyDomain: string;
}): BambooHRClient {
  const client = new BambooHRClient({
    apiKey: APIKEY_SENTINEL,
    companyDomain: opts.companyDomain,
  });
  (client as unknown as BearerAware)[BEARER_FIELD] = opts.accessToken;
  return client;
}
