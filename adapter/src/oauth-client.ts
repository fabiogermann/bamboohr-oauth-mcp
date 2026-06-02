// BambooHR OAuth client.
// Endpoints (per https://documentation.bamboohr.com/docs/getting-started):
//   Authorize:  https://{companyDomain}.bamboohr.com/authorize.php
//   Token:      https://{companyDomain}.bamboohr.com/token.php?request=token
//
// authorize.php uses query params. token.php expects a JSON body.

import type { Config } from './config.js';

export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  scope: string;
  refresh_token?: string;
  id_token?: string;
  companyDomain?: string;
}

export class OAuthError extends Error {
  constructor(message: string, public status?: number) {
    super(message);
    this.name = 'OAuthError';
  }
}

export function buildAuthorizeUrl(cfg: Config, state: string): string {
  const params = new URLSearchParams({
    request: 'authorize',
    response_type: 'code',
    state,
    client_id: cfg.oauthClientId,
    redirect_uri: redirectUri(cfg),
  });
  // BambooHR expects scopes joined by '+' in the URL. URLSearchParams would
  // encode '+' as '%2B', so build the scope segment manually.
  // Also, BambooHR's example uses scope=a+b+c, where the literal '+' acts as separator.
  const base = `${cfg.bambooBaseUrl}/authorize.php?${params.toString()}`;
  return `${base}&scope=${cfg.oauthScopes}`;
}

export function redirectUri(cfg: Config): string {
  return `${cfg.publicBaseUrl}/connect/callback`;
}

export async function exchangeCodeForToken(cfg: Config, code: string): Promise<TokenResponse> {
  const body = {
    client_id: cfg.oauthClientId,
    client_secret: cfg.oauthClientSecret,
    code,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri(cfg),
  };
  return postToken(cfg, body);
}

export async function refreshAccessToken(cfg: Config, refreshToken: string): Promise<TokenResponse> {
  const body = {
    client_id: cfg.oauthClientId,
    client_secret: cfg.oauthClientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
    redirect_uri: redirectUri(cfg),
  };
  return postToken(cfg, body);
}

async function postToken(cfg: Config, body: Record<string, string>): Promise<TokenResponse> {
  const url = `${cfg.bambooBaseUrl}/token.php?request=token`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(body),
  });

  const text = await res.text();
  if (!res.ok) {
    throw new OAuthError(
      `BambooHR token endpoint returned ${res.status}: ${text.slice(0, 500)}`,
      res.status,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new OAuthError(`BambooHR token response was not JSON: ${text.slice(0, 200)}`);
  }
  if (!isTokenResponse(parsed)) {
    throw new OAuthError(`BambooHR token response shape unexpected: ${text.slice(0, 200)}`);
  }
  return parsed;
}

function isTokenResponse(x: unknown): x is TokenResponse {
  if (!x || typeof x !== 'object') return false;
  const o = x as Record<string, unknown>;
  return (
    typeof o.access_token === 'string' &&
    typeof o.expires_in === 'number' &&
    typeof o.token_type === 'string' &&
    typeof o.scope === 'string' &&
    (o.refresh_token === undefined || typeof o.refresh_token === 'string') &&
    (o.id_token === undefined || typeof o.id_token === 'string') &&
    (o.companyDomain === undefined || typeof o.companyDomain === 'string')
  );
}
