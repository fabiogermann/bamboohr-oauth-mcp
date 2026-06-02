// Centralized configuration: read & validate env once at boot.
// Fails fast with a clear message if anything required is missing.

export interface Config {
  // HTTP server
  port: number;
  publicBaseUrl: string; // external URL used in OAuth redirect_uri and .well-known docs

  // BambooHR tenant (single-tenant deployment)
  companyDomain: string;
  bambooBaseUrl: string; // https://{companyDomain}.bamboohr.com

  // BambooHR OAuth app
  oauthClientId: string;
  oauthClientSecret: string;
  oauthScopes: string; // plus-separated, exactly what BambooHR receives

  // Bearer encryption
  encKey: Buffer; // 32 bytes, AES-256-GCM

  // Tunables
  bearerTtlSeconds: number; // wrapper bearer lifetime (independent of upstream access_token expiry)
  refreshSkewSeconds: number; // refresh upstream token if it expires within this many seconds
}

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return v.trim();
}

function optional(name: string, fallback: string): string {
  const v = process.env[name];
  return v && v.trim() !== '' ? v.trim() : fallback;
}

function parseIntEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = parseInt(v, 10);
  if (Number.isNaN(n) || n <= 0) {
    throw new Error(`Invalid integer for ${name}: ${v}`);
  }
  return n;
}

function parseScopes(raw: string): string {
  // BambooHR's authorize.php uses '+' as separator. Accept ' ' too and normalize.
  // We do NOT auto-inject any scope: BambooHR rejects unknown scopes with
  // invalid_scope, including (in some app configurations) `offline_access`.
  // Callers must supply exactly the scopes their BambooHR OAuth app is allowed
  // to request.
  const tokens = raw
    .split(/[\s+]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (tokens.length === 0) {
    throw new Error(
      'BAMBOOHR_OAUTH_SCOPES must contain at least one scope. ' +
        'Set it to the space- or plus-separated list your BambooHR OAuth app supports.',
    );
  }
  return tokens.join('+');
}

function parseKey(b64: string): Buffer {
  let buf: Buffer;
  try {
    buf = Buffer.from(b64, 'base64');
  } catch (e) {
    throw new Error('WRAPPER_ENC_KEY_BASE64 is not valid base64');
  }
  if (buf.length !== 32) {
    throw new Error(
      `WRAPPER_ENC_KEY_BASE64 must decode to exactly 32 bytes (got ${buf.length}). ` +
        `Generate with: openssl rand -base64 32`,
    );
  }
  return buf;
}

export function loadConfig(): Config {
  const companyDomain = required('BAMBOOHR_COMPANY_DOMAIN');
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(companyDomain)) {
    throw new Error(`BAMBOOHR_COMPANY_DOMAIN must be a subdomain label (got: ${companyDomain})`);
  }

  const publicBaseUrl = required('PUBLIC_BASE_URL').replace(/\/+$/, '');
  if (!/^https?:\/\//.test(publicBaseUrl)) {
    throw new Error(`PUBLIC_BASE_URL must include scheme (got: ${publicBaseUrl})`);
  }

  return {
    port: parseIntEnv('PORT', 3000),
    publicBaseUrl,
    companyDomain,
    bambooBaseUrl: `https://${companyDomain}.bamboohr.com`,
    oauthClientId: required('BAMBOOHR_OAUTH_CLIENT_ID'),
    oauthClientSecret: required('BAMBOOHR_OAUTH_CLIENT_SECRET'),
    oauthScopes: parseScopes(required('BAMBOOHR_OAUTH_SCOPES')),
    encKey: parseKey(required('WRAPPER_ENC_KEY_BASE64')),
    bearerTtlSeconds: parseIntEnv('WRAPPER_BEARER_TTL_SECONDS', 3600),
    refreshSkewSeconds: parseIntEnv('WRAPPER_REFRESH_SKEW_SECONDS', 60),
  };
}
