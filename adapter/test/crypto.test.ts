import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  encryptBearer,
  decryptBearer,
  BearerError,
  encryptState,
  decryptState,
  StateError,
  encryptAuthRequest,
  decryptAuthRequest,
  AuthRequestError,
  encryptAuthCode,
  decryptAuthCode,
  AuthCodeError,
  type BearerPayload,
  type StatePayload,
  type AuthRequestPayload,
  type AuthCodePayload,
} from '../src/crypto.js';

const KEY = randomBytes(32);
const OTHER_KEY = randomBytes(32);

function makeBearer(): BearerPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    iat: now,
    exp: now + 3600,
    at: 'upstream-access-token',
    rt: 'upstream-refresh-token',
    ate: now + 3500,
    d: 'acme',
    s: 'offline_access read.employees',
  };
}

function makeState(): StatePayload {
  const now = Math.floor(Date.now() / 1000);
  return { v: 1, iat: now, exp: now + 600, n: 'random-nonce-base64url' };
}

describe('crypto / bearer', () => {
  it('roundtrips a payload', () => {
    const p = makeBearer();
    const t = encryptBearer(p, KEY);
    const back = decryptBearer(t, KEY);
    expect(back).toEqual(p);
  });

  it('roundtrips with null refresh token', () => {
    const p = { ...makeBearer(), rt: null };
    expect(decryptBearer(encryptBearer(p, KEY), KEY)).toEqual(p);
  });

  it('produces base64url output (no +/= chars)', () => {
    const t = encryptBearer(makeBearer(), KEY);
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('rejects token encrypted with a different key', () => {
    const t = encryptBearer(makeBearer(), KEY);
    expect(() => decryptBearer(t, OTHER_KEY)).toThrow(BearerError);
  });

  it('rejects a tampered ciphertext byte', () => {
    const t = encryptBearer(makeBearer(), KEY);
    const buf = Buffer.from(t, 'base64url');
    // Flip a byte in the ciphertext region (after version+iv, before tag).
    buf[20] ^= 0x01;
    const tampered = buf.toString('base64url');
    expect(() => decryptBearer(tampered, KEY)).toThrow(BearerError);
  });

  it('rejects a tampered auth tag', () => {
    const t = encryptBearer(makeBearer(), KEY);
    const buf = Buffer.from(t, 'base64url');
    buf[buf.length - 1] ^= 0x01;
    expect(() => decryptBearer(buf.toString('base64url'), KEY)).toThrow(BearerError);
  });

  it('rejects truncated input', () => {
    const t = encryptBearer(makeBearer(), KEY);
    const truncated = Buffer.from(t, 'base64url').subarray(0, 10).toString('base64url');
    expect(() => decryptBearer(truncated, KEY)).toThrow(BearerError);
  });

  it('rejects an unknown version byte', () => {
    const t = encryptBearer(makeBearer(), KEY);
    const buf = Buffer.from(t, 'base64url');
    buf[0] = 99;
    expect(() => decryptBearer(buf.toString('base64url'), KEY)).toThrow(/unsupported token version/);
  });

  it('rejects total garbage', () => {
    expect(() => decryptBearer('this-is-not-a-token', KEY)).toThrow(BearerError);
  });

  it('throws on key with wrong length', () => {
    expect(() => encryptBearer(makeBearer(), Buffer.alloc(16))).toThrow(/32 bytes/);
    expect(() => decryptBearer(encryptBearer(makeBearer(), KEY), Buffer.alloc(31))).toThrow(/32 bytes/);
  });

  it('two encryptions of the same payload produce different ciphertexts (IV randomness)', () => {
    const p = makeBearer();
    const a = encryptBearer(p, KEY);
    const b = encryptBearer(p, KEY);
    expect(a).not.toEqual(b);
    expect(decryptBearer(a, KEY)).toEqual(decryptBearer(b, KEY));
  });
});

describe('crypto / state', () => {
  it('roundtrips a state payload', () => {
    const p = makeState();
    expect(decryptState(encryptState(p, KEY), KEY)).toEqual(p);
  });

  it('rejects state encrypted with another key', () => {
    const t = encryptState(makeState(), KEY);
    expect(() => decryptState(t, OTHER_KEY)).toThrow(StateError);
  });

  it('rejects tampering', () => {
    const t = encryptState(makeState(), KEY);
    const buf = Buffer.from(t, 'base64url');
    buf[buf.length - 1] ^= 0x80;
    expect(() => decryptState(buf.toString('base64url'), KEY)).toThrow(StateError);
  });
});

describe('crypto / bearer vs state separation', () => {
  it('rejects a bearer when decoded as state and vice versa (different version bytes)', () => {
    // Both happen to be version=1 currently, but ciphertext shape (JSON keys)
    // differs, so cross-decode must fail JSON-shape validation.
    const b = encryptBearer(makeBearer(), KEY);
    const s = encryptState(makeState(), KEY);
    expect(() => decryptState(b, KEY)).toThrow(StateError);
    expect(() => decryptBearer(s, KEY)).toThrow(BearerError);
  });
});

function makeAuthRequest(): AuthRequestPayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    iat: now,
    exp: now + 600,
    ci: 'bamboohr-oauth-mcp',
    ru: 'http://127.0.0.1:39000/callback',
    cs: 'client-state',
    cc: 'challenge-b64url',
    sc: 'mcp time_off',
  };
}

describe('crypto / auth request', () => {
  it('roundtrips', () => {
    const r = makeAuthRequest();
    const t = encryptAuthRequest(r, KEY);
    expect(decryptAuthRequest(t, KEY)).toEqual(r);
  });

  it('rejects another key', () => {
    const t = encryptAuthRequest(makeAuthRequest(), KEY);
    expect(() => decryptAuthRequest(t, OTHER_KEY)).toThrow(AuthRequestError);
  });

  it('is distinguishable from bearer/state by version byte', () => {
    const b = encryptBearer(makeBearer(), KEY);
    const s = encryptState(makeState(), KEY);
    expect(() => decryptAuthRequest(b, KEY)).toThrow(AuthRequestError);
    expect(() => decryptAuthRequest(s, KEY)).toThrow(AuthRequestError);
  });
});

function makeAuthCode(): AuthCodePayload {
  const now = Math.floor(Date.now() / 1000);
  return {
    v: 1,
    iat: now,
    exp: now + 60,
    b: 'wrapped-bearer-string',
    ru: 'http://127.0.0.1:39000/callback',
    cc: 'challenge-b64url',
    eb: now + 3600,
    sc: 'mcp',
  };
}

describe('crypto / auth code', () => {
  it('roundtrips', () => {
    const c = makeAuthCode();
    const t = encryptAuthCode(c, KEY);
    expect(decryptAuthCode(t, KEY)).toEqual(c);
  });

  it('rejects another key', () => {
    const t = encryptAuthCode(makeAuthCode(), KEY);
    expect(() => decryptAuthCode(t, OTHER_KEY)).toThrow(AuthCodeError);
  });

  it('is distinguishable from auth request by version byte', () => {
    const r = encryptAuthRequest(makeAuthRequest(), KEY);
    expect(() => decryptAuthCode(r, KEY)).toThrow(AuthCodeError);
  });
});
