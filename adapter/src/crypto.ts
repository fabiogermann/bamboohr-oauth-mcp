// AES-256-GCM self-contained tokens. Used for four distinct payload kinds:
//   1) Bearer        — wrapper access token returned to MCP clients
//   2) State         — opaque-to-BambooHR `state` round-trip on the OAuth dance
//                      we initiate from /authorize
//   3) AuthRequest   — carries the MCP client's authorize params (redirect_uri,
//                      state, PKCE challenge, requested scopes, client_id)
//                      across the BambooHR round-trip. We send this as the
//                      `state` query parameter to BambooHR's authorize endpoint
//                      and decrypt on /connect/callback. It REPLACES the older
//                      plain `State` token now that /authorize is the entrypoint.
//   4) AuthCode      — one-time authorization code returned to the MCP client's
//                      redirect_uri. Carries the wrapper bearer plus PKCE
//                      challenge so /token can verify the code_verifier.
//
// Wire format for every kind (base64url of binary):
//   version(1) | iv(12) | ciphertext | tag(16)
//
// Each kind has its own version byte so type confusion is rejected on parse
// (in addition to JSON shape validation). Bearer and the older State both used
// version 1 historically; new payload types use distinct version bytes.
//
// Wrong-kind tokens never decrypt because the version byte is checked BEFORE
// AES-GCM is applied; if an attacker bypasses that check they're still
// authenticated by the GCM tag and finally rejected by shape validation.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const IV_LEN = 12;
const TAG_LEN = 16;

const KIND_BEARER = 1;
const KIND_STATE = 1; // historical; kept at 1 for backward compat with in-flight states
const KIND_AUTH_REQUEST = 3;
const KIND_AUTH_CODE = 4;

// --- Generic AEAD primitives (internal) -----------------------------------

function aeadEncrypt(kind: number, plaintext: Buffer, key: Buffer): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from([kind]), iv, ciphertext, tag]).toString('base64url');
}

function aeadDecrypt(
  expectedKind: number,
  token: string,
  key: Buffer,
  wrap: (msg: string) => Error,
): Buffer {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  let buf: Buffer;
  try {
    buf = Buffer.from(token, 'base64url');
  } catch {
    throw wrap('malformed token (not base64url)');
  }
  if (buf.length < 1 + IV_LEN + TAG_LEN + 1) {
    throw wrap('malformed token (too short)');
  }
  if (buf[0] !== expectedKind) {
    throw wrap(`unsupported token version: ${buf[0]}`);
  }
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ciphertext = buf.subarray(1 + IV_LEN, buf.length - TAG_LEN);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw wrap('authentication failed (wrong key or tampered token)');
  }
}

function decodeJson<T>(plaintext: Buffer, guard: (x: unknown) => x is T, wrap: (msg: string) => Error): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw wrap('plaintext is not valid JSON');
  }
  if (!guard(parsed)) {
    throw wrap('plaintext has invalid shape');
  }
  return parsed;
}

// --- Bearer ---------------------------------------------------------------

export interface BearerPayload {
  v: 1;
  iat: number;
  exp: number;
  at: string;
  rt: string | null;
  ate: number;
  d: string;
  s: string;
}

export class BearerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BearerError';
  }
}

export function encryptBearer(payload: BearerPayload, key: Buffer): string {
  return aeadEncrypt(KIND_BEARER, Buffer.from(JSON.stringify(payload), 'utf8'), key);
}

export function decryptBearer(token: string, key: Buffer): BearerPayload {
  const wrap = (m: string) => new BearerError(`bearer ${m}`);
  const plaintext = aeadDecrypt(KIND_BEARER, token, key, wrap);
  return decodeJson<BearerPayload>(plaintext, isBearerPayload, wrap);
}

function isBearerPayload(x: unknown): x is BearerPayload {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    o.v === 1 &&
    typeof o.iat === 'number' &&
    typeof o.exp === 'number' &&
    typeof o.at === 'string' &&
    (o.rt === null || typeof o.rt === 'string') &&
    typeof o.ate === 'number' &&
    typeof o.d === 'string' &&
    typeof o.s === 'string'
  );
}

// --- State (legacy: kept for callers that still need a plain nonce token) --

export interface StatePayload {
  v: 1;
  iat: number;
  exp: number;
  n: string;
}

export class StateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StateError';
  }
}

export function encryptState(payload: StatePayload, key: Buffer): string {
  return aeadEncrypt(KIND_STATE, Buffer.from(JSON.stringify(payload), 'utf8'), key);
}

export function decryptState(token: string, key: Buffer): StatePayload {
  const wrap = (m: string) => new StateError(`state ${m}`);
  const plaintext = aeadDecrypt(KIND_STATE, token, key, wrap);
  return decodeJson<StatePayload>(plaintext, isStatePayload, wrap);
}

function isStatePayload(x: unknown): x is StatePayload {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return o.v === 1 && typeof o.iat === 'number' && typeof o.exp === 'number' && typeof o.n === 'string';
}

// --- AuthRequest -----------------------------------------------------------
// Sent as the `state` query param to BambooHR's /authorize.php. We use
// AES-GCM (not just an opaque random string) so /connect/callback can recover
// the MCP client's redirect_uri, state, PKCE challenge, and requested scopes
// without server-side storage.

export interface AuthRequestPayload {
  v: 1;
  iat: number;
  exp: number;
  ci: string; // client_id (informational; not validated downstream)
  ru: string; // client's redirect_uri (validated against allowlist at /authorize time)
  cs: string; // client's state value, opaque
  cc: string; // PKCE code_challenge (S256, base64url)
  sc: string; // scopes the client asked for (space-separated; informational)
}

export class AuthRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthRequestError';
  }
}

export function encryptAuthRequest(payload: AuthRequestPayload, key: Buffer): string {
  return aeadEncrypt(KIND_AUTH_REQUEST, Buffer.from(JSON.stringify(payload), 'utf8'), key);
}

export function decryptAuthRequest(token: string, key: Buffer): AuthRequestPayload {
  const wrap = (m: string) => new AuthRequestError(`auth_request ${m}`);
  const plaintext = aeadDecrypt(KIND_AUTH_REQUEST, token, key, wrap);
  return decodeJson<AuthRequestPayload>(plaintext, isAuthRequestPayload, wrap);
}

function isAuthRequestPayload(x: unknown): x is AuthRequestPayload {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    o.v === 1 &&
    typeof o.iat === 'number' &&
    typeof o.exp === 'number' &&
    typeof o.ci === 'string' &&
    typeof o.ru === 'string' &&
    typeof o.cs === 'string' &&
    typeof o.cc === 'string' &&
    typeof o.sc === 'string'
  );
}

// --- AuthCode --------------------------------------------------------------
// Returned to the MCP client's redirect_uri as the `code` query parameter.
// /token exchanges it (with PKCE proof + matching redirect_uri) for the
// wrapper bearer. Short-lived: a few seconds is fine; one minute is generous.
//
// We do NOT enforce one-shot use (would require shared storage). PKCE prevents
// any third party who captures the redirect URL from exchanging it, since they
// won't have the code_verifier.

export interface AuthCodePayload {
  v: 1;
  iat: number;
  exp: number;
  b: string; // wrapper bearer (already-encrypted bearer token)
  ru: string; // client redirect_uri (must match the one supplied to /token)
  cc: string; // PKCE code_challenge (S256, base64url)
  eb: number; // bearer expiry (unix seconds), used for /token's expires_in
  sc: string; // scopes (returned in /token response)
}

export class AuthCodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthCodeError';
  }
}

export function encryptAuthCode(payload: AuthCodePayload, key: Buffer): string {
  return aeadEncrypt(KIND_AUTH_CODE, Buffer.from(JSON.stringify(payload), 'utf8'), key);
}

export function decryptAuthCode(token: string, key: Buffer): AuthCodePayload {
  const wrap = (m: string) => new AuthCodeError(`auth_code ${m}`);
  const plaintext = aeadDecrypt(KIND_AUTH_CODE, token, key, wrap);
  return decodeJson<AuthCodePayload>(plaintext, isAuthCodePayload, wrap);
}

function isAuthCodePayload(x: unknown): x is AuthCodePayload {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    o.v === 1 &&
    typeof o.iat === 'number' &&
    typeof o.exp === 'number' &&
    typeof o.b === 'string' &&
    typeof o.ru === 'string' &&
    typeof o.cc === 'string' &&
    typeof o.eb === 'number' &&
    typeof o.sc === 'string'
  );
}
