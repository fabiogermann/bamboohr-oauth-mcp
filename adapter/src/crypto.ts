// AES-256-GCM bearer token: self-contained, stateless.
// Wire format (base64url of binary): version(1) | iv(12) | ciphertext | tag(16)
//
// Payload (plaintext, before encryption) is a JSON object:
//   {
//     v: 1,
//     iat: number,           // issued-at, unix seconds
//     exp: number,           // wrapper bearer expiry, unix seconds
//     at: string,            // upstream BambooHR access_token
//     rt: string | null,     // upstream BambooHR refresh_token (may be absent if offline_access not granted)
//     ate: number,           // upstream access_token expiry, unix seconds
//     d: string,             // companyDomain (informational; single-tenant deployments validate against config)
//     s: string              // granted scopes (space-separated)
//   }

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;

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

export function encryptBearer(payload: BearerPayload, key: Buffer): string {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = Buffer.concat([Buffer.from([VERSION]), iv, ciphertext, tag]);
  return out.toString('base64url');
}

export class BearerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BearerError';
  }
}

export function decryptBearer(token: string, key: Buffer): BearerPayload {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  let buf: Buffer;
  try {
    buf = Buffer.from(token, 'base64url');
  } catch {
    throw new BearerError('malformed bearer (not base64url)');
  }
  if (buf.length < 1 + IV_LEN + TAG_LEN + 1) {
    throw new BearerError('malformed bearer (too short)');
  }
  if (buf[0] !== VERSION) {
    throw new BearerError(`unsupported bearer version: ${buf[0]}`);
  }
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ciphertext = buf.subarray(1 + IV_LEN, buf.length - TAG_LEN);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new BearerError('bearer authentication failed (wrong key or tampered token)');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new BearerError('bearer plaintext is not valid JSON');
  }
  if (!isBearerPayload(parsed)) {
    throw new BearerError('bearer plaintext has invalid shape');
  }
  return parsed;
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

// ---------------------------------------------------------------------------
// OAuth `state` parameter (stateless).
//
// We encrypt our own JSON payload into the state value with the same AES-256-GCM
// key used for bearers, then base64url-encode it. BambooHR echoes `state` back
// unchanged on the callback. On callback we decrypt and verify the timestamp.
//
// Wire format is identical to the bearer (version | iv | ciphertext | tag), but
// versioned separately so we can evolve them independently.
//
// What this gives us:
//   - No per-pod Map of pending states. Any replica can handle the callback.
//
// What we deliberately do NOT do:
//   - Enforce one-shot use of a given `state`. BambooHR's `code` is single-use
//     at their end, which already prevents replay of the full callback URL.
//     Single-use enforcement on `state` would re-introduce shared state.
//
// Payload:
//   { v: 1, iat: number, exp: number, n: string }   // n = random nonce, base64url

const STATE_VERSION = 1;

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
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const out = Buffer.concat([Buffer.from([STATE_VERSION]), iv, ciphertext, tag]);
  return out.toString('base64url');
}

export function decryptState(token: string, key: Buffer): StatePayload {
  if (key.length !== 32) throw new Error('encryption key must be 32 bytes');
  let buf: Buffer;
  try {
    buf = Buffer.from(token, 'base64url');
  } catch {
    throw new StateError('malformed state (not base64url)');
  }
  if (buf.length < 1 + IV_LEN + TAG_LEN + 1) {
    throw new StateError('malformed state (too short)');
  }
  if (buf[0] !== STATE_VERSION) {
    throw new StateError(`unsupported state version: ${buf[0]}`);
  }
  const iv = buf.subarray(1, 1 + IV_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  const ciphertext = buf.subarray(1 + IV_LEN, buf.length - TAG_LEN);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new StateError('state authentication failed (wrong key or tampered token)');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString('utf8'));
  } catch {
    throw new StateError('state plaintext is not valid JSON');
  }
  if (!isStatePayload(parsed)) {
    throw new StateError('state plaintext has invalid shape');
  }
  return parsed;
}

function isStatePayload(x: unknown): x is StatePayload {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return o.v === 1 && typeof o.iat === 'number' && typeof o.exp === 'number' && typeof o.n === 'string';
}
