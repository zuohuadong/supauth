/**
 * Supabase OAuth 2.1 black-box compatibility tests (P0-9)
 *
 * These tests verify Supabase Auth's public OAuth/OIDC behavior without
 * depending on Supabase internal test helpers. Live checks are opt-in because
 * they require a real Supabase runtime and registered OAuth client.
 *
 * Run smoke contract:
 *   bun test tests/integration/supabase-compat/oauth21.test.ts
 *
 * Run live checks:
 *   RUN_SUPABASE_OAUTH21_COMPAT=1 \
 *   OAUTH_RUNTIME_URL=http://localhost:9999 \
 *   OAUTH21_CLIENT_ID=<registered-client-id> \
 *   OAUTH21_REDIRECT_URI=http://localhost:3000/oauth/callback \
 *   OAUTH21_ACCESS_TOKEN=<oauth-access-token> \
 *   OAUTH21_REFRESH_TOKEN=<oauth-refresh-token> \
 *   bun test tests/integration/supabase-compat/oauth21.test.ts
 *
 * Strict CI checks:
 *   REQUIRE_SUPABASE_AUTH_COMPAT=1 runs the live public OAuth/OIDC checks and
 *   fails fast when any required live Auth secret is missing. The strict CI
 *   workflow also fails if the suite reports skipped tests.
 *
 * Optional live token checks outside strict mode:
 *   OAUTH21_ACCESS_TOKEN=<oauth-access-token>
 *   OAUTH21_REFRESH_TOKEN=<oauth-refresh-token>
 *   OAUTH21_TOKEN_AUTH_METHOD=none|client_secret_basic|client_secret_post
 *   OAUTH21_CLIENT_SECRET=<client-secret>
 *   SUPABASE_AUTH_COMPAT_VERSION=v2.192.0|v2.196.0
 */

import { describe, expect, it } from 'bun:test';
import {
  SUPABASE_METADATA_CLAIMS,
  SUPABASE_OAUTH_ACCESS_TOKEN_CLAIMS,
  SUPABASE_OAUTH_STANDARD_SCOPES,
  SUPABASE_REQUIRED_CLAIMS,
  SUPABASE_RUNTIME_ROLES,
  SUPAOAUTH_CLAIM_KEYS,
} from '../../../packages/shared/src/index.js';

const STRICT_COMPAT = process.env.REQUIRE_SUPABASE_AUTH_COMPAT === '1';
const RUN_LIVE = STRICT_COMPAT || process.env.RUN_SUPABASE_OAUTH21_COMPAT === '1';
const RUNTIME_URL = trimTrailingSlash(process.env.OAUTH_RUNTIME_URL || 'http://localhost:9999');
const CLIENT_ID = process.env.OAUTH21_CLIENT_ID || '';
const REDIRECT_URI = process.env.OAUTH21_REDIRECT_URI || 'http://localhost:3000/oauth/callback';
const ACCESS_TOKEN = process.env.OAUTH21_ACCESS_TOKEN || '';
const REFRESH_TOKEN = process.env.OAUTH21_REFRESH_TOKEN || '';
const CLIENT_SECRET = process.env.OAUTH21_CLIENT_SECRET || '';
const TOKEN_AUTH_METHOD = process.env.OAUTH21_TOKEN_AUTH_METHOD || 'none';
const LIVE_TIMEOUT_MS = parseInt(process.env.OAUTH21_TEST_TIMEOUT_MS || '30000', 10);
const CURRENT_COMPAT_VERSION = 'v2.196.0';
const SUPPORTED_COMPAT_VERSIONS = new Set(['v2.192.0', CURRENT_COMPAT_VERSION]);
const EXPECTED_COMPAT_VERSION = process.env.SUPABASE_AUTH_COMPAT_VERSION || CURRENT_COMPAT_VERSION;

if (STRICT_COMPAT) {
  assertRequiredEnv([
    'OAUTH_RUNTIME_URL',
    'OAUTH21_CLIENT_ID',
    'OAUTH21_REDIRECT_URI',
    'OAUTH21_ACCESS_TOKEN',
    'OAUTH21_REFRESH_TOKEN',
  ]);
  if (TOKEN_AUTH_METHOD === 'client_secret_basic' || TOKEN_AUTH_METHOD === 'client_secret_post') {
    assertRequiredEnv(['OAUTH21_CLIENT_SECRET']);
  }
}

type LiveTestHandler = () => void | Promise<unknown>;

function liveIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE) it(name, fn, LIVE_TIMEOUT_MS);
}

function clientLiveIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE && CLIENT_ID) it(name, fn, LIVE_TIMEOUT_MS);
}

function accessTokenLiveIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE && ACCESS_TOKEN) it(name, fn, LIVE_TIMEOUT_MS);
}

function refreshTokenLiveIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE && REFRESH_TOKEN) it(name, fn, LIVE_TIMEOUT_MS);
}

function assertRequiredEnv(names: string[]) {
  const missing = names.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required Supabase Auth compatibility env: ${missing.join(', ')}`);
  }
}

type JsonObject = Record<string, unknown>;

interface OAuthMetadata extends JsonObject {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
  response_types_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
}

describe('Supabase OAuth 2.1 compatibility fixture', () => {
  it('rejects a declared matrix version that differs from runtime health', () => {
    expect(() => assertExpectedRuntimeVersion('v2.196.0', 'v2.192.0'))
      .toThrow('Expected GoTrue v2.192.0 but runtime health reports v2.196.0');
    expect(() => assertExpectedRuntimeVersion('v2.195.0', 'v2.195.0'))
      .toThrow('Unsupported GoTrue compatibility matrix version: v2.195.0');
  });

  it('rejects missing or invalid runtime health versions', () => {
    expect(() => runtimeVersionFromHealth({})).toThrow('GoTrue health response has no valid version');
    expect(() => runtimeVersionFromHealth({ version: 'development' }))
      .toThrow('GoTrue health response has no valid version');
    expect(runtimeVersionFromHealth({ version: 'v2.196.0' })).toBe('v2.196.0');
  });

  it('fails the live version boundary on health errors and mismatches', async () => {
    const unavailableHealth = (() => Promise.resolve(new Response(null, { status: 503 }))) as unknown as typeof fetch;
    const floorHealth = (() => Promise.resolve(Response.json({ version: 'v2.192.0' }))) as unknown as typeof fetch;

    await expect(verifiedRuntimeVersion(unavailableHealth))
      .rejects.toThrow('GoTrue health check failed with status 503');
    await expect(verifiedRuntimeVersion(floorHealth))
      .rejects.toThrow('Expected GoTrue v2.196.0 but runtime health reports v2.192.0');
  });

  it('declares the live OAuth 2.1 compatibility environment contract', () => {
    expect([
      'RUN_SUPABASE_OAUTH21_COMPAT',
      'OAUTH_RUNTIME_URL',
      'OAUTH21_CLIENT_ID',
      'OAUTH21_REDIRECT_URI',
      'OAUTH21_ACCESS_TOKEN',
      'OAUTH21_REFRESH_TOKEN',
      'OAUTH21_TOKEN_AUTH_METHOD',
      'OAUTH21_CLIENT_SECRET',
      'SUPABASE_AUTH_COMPAT_VERSION',
    ]).toContain('OAUTH21_CLIENT_ID');
  });

  liveIt('exposes OAuth 2.1 authorization-server metadata', async () => {
    const runtimeVersion = await verifiedRuntimeVersion();
    const metadata = await getOAuthMetadata();

    expect(metadata.issuer).toBeDefined();
    expectEndpointPath(metadata.authorization_endpoint, '/auth/v1/oauth/authorize');
    expectEndpointPath(metadata.token_endpoint, '/auth/v1/oauth/token');
    expectEndpointPath(metadata.jwks_uri, '/auth/v1/.well-known/jwks.json');

    if (metadata.userinfo_endpoint) {
      expectEndpointPath(metadata.userinfo_endpoint, '/auth/v1/oauth/userinfo');
    }

    expect(metadata.response_types_supported || []).toContain('code');
    expect(metadata.grant_types_supported || []).toContain('authorization_code');
    expect(metadata.grant_types_supported || []).toContain('refresh_token');
    expect(metadata.grant_types_supported || []).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(metadata.code_challenge_methods_supported || []).toContain('S256');
    if (runtimeVersion === CURRENT_COMPAT_VERSION) {
      expect(metadata.scopes_supported || []).toContain('offline_access');
    }
  });

  liveIt('keeps OIDC discovery aligned with OAuth metadata', async () => {
    const [oauthMetadata, oidcMetadata] = await Promise.all([
      getOAuthMetadata(),
      getJson<OAuthMetadata>('/auth/v1/.well-known/openid-configuration'),
    ]);

    expect(oidcMetadata.issuer).toBe(oauthMetadata.issuer);
    expect(oidcMetadata.authorization_endpoint).toBe(oauthMetadata.authorization_endpoint);
    expect(oidcMetadata.token_endpoint).toBe(oauthMetadata.token_endpoint);
    expect(oidcMetadata.jwks_uri).toBe(oauthMetadata.jwks_uri);
  });

  liveIt('rejects the client_credentials grant', async () => {
    const metadata = await getOAuthMetadata();
    const response = await postForm(metadata.token_endpoint, { grant_type: 'client_credentials' });

    expect([400, 401, 405]).toContain(response.status);
    expect(response.ok).toBe(false);
  });

  clientLiveIt('rejects RFC 8693 token exchange with stock GoTrue semantics', async () => {
    const metadata = await getOAuthMetadata();
    const response = await postForm(metadata.token_endpoint, {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      client_id: CLIENT_ID,
      client_secret: TOKEN_AUTH_METHOD === 'client_secret_post' ? CLIENT_SECRET : undefined,
      subject_token: 'stock-gotrue-token-exchange-probe',
    }, tokenAuthHeaders());

    expect(response.status).toBe(400);
    expect(response.ok).toBe(false);
    const body = await response.json() as JsonObject;
    expect(body.error).toBe('unsupported_grant_type');
  });

  liveIt('does not expose UserInfo without a bearer token', async () => {
    const metadata = await getOAuthMetadata();
    const endpoint = metadata.userinfo_endpoint || `${RUNTIME_URL}/auth/v1/oauth/userinfo`;
    const res = await fetch(endpoint, { headers: { accept: 'application/json' } });

    expect([401, 403]).toContain(res.status);
    expect(res.ok).toBe(false);
  });

  clientLiveIt('requires PKCE parameters for authorization-code requests', async () => {
    const metadata = await getOAuthMetadata();
    const authorizeUrl = new URL(metadata.authorization_endpoint);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('client_id', CLIENT_ID);
    authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authorizeUrl.searchParams.set('scope', 'openid email');
    authorizeUrl.searchParams.set('state', 'supaoauth-pkce-negative-test');

    const res = await fetch(authorizeUrl, { redirect: 'manual' });

    expect(res.status).not.toBe(200);
    expect([302, 303, 400, 401]).toContain(res.status);
  });

  accessTokenLiveIt('OAuth access tokens include Supabase and OAuth client claims', async () => {
    const { header, payload } = decodeJwt(ACCESS_TOKEN);
    const metadata = await getOAuthMetadata();
    const jwks = await fetch(metadata.jwks_uri).then((res) => res.json()) as { keys?: JsonObject[] };

    expectSupabaseOAuthAccessTokenPayload(payload, metadata.issuer);

    if (header.kid && Array.isArray(jwks.keys)) {
      expect(jwks.keys.some((key) => key.kid === header.kid)).toBe(true);
    }
  });

  accessTokenLiveIt('UserInfo accepts OAuth bearer tokens', async () => {
    const metadata = await getOAuthMetadata();
    const endpoint = metadata.userinfo_endpoint || `${RUNTIME_URL}/auth/v1/oauth/userinfo`;
    const res = await fetch(endpoint, {
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${ACCESS_TOKEN}`,
      },
    });

    expect(res.ok).toBe(true);
    const body = await res.json() as JsonObject;
    expect(body.sub).toBeDefined();
  });

  refreshTokenLiveIt('refresh-token flow returns a bearer access token', async () => {
    const metadata = await getOAuthMetadata();
    const res = await postForm(metadata.token_endpoint, {
      grant_type: 'refresh_token',
      refresh_token: REFRESH_TOKEN,
      client_id: CLIENT_ID || undefined,
      client_secret: TOKEN_AUTH_METHOD === 'client_secret_post' ? CLIENT_SECRET : undefined,
    }, tokenAuthHeaders());

    expect(res.ok).toBe(true);
    const body = await res.json() as JsonObject;
    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe('bearer');
    expect(body.expires_in).toBeDefined();
    if (body.scope !== undefined) expectGrantedOAuthScope(body);

    const { payload } = decodeJwt(String(body.access_token));
    expectSupabaseOAuthAccessTokenPayload(payload, metadata.issuer);
  });
});

async function getOAuthMetadata(): Promise<OAuthMetadata> {
  return getJson<OAuthMetadata>('/auth/v1/.well-known/oauth-authorization-server');
}

async function verifiedRuntimeVersion(fetchImpl: typeof fetch = fetch): Promise<string> {
  const response = await fetchImpl(`${RUNTIME_URL}/auth/v1/health`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`GoTrue health check failed with status ${response.status}`);
  const runtimeVersion = runtimeVersionFromHealth(await response.json());
  assertExpectedRuntimeVersion(runtimeVersion, EXPECTED_COMPAT_VERSION);
  return runtimeVersion;
}

function runtimeVersionFromHealth(healthPayload: unknown): string {
  if (!healthPayload || typeof healthPayload !== 'object' || Array.isArray(healthPayload)) {
    throw new Error('GoTrue health response has no valid version');
  }
  const runtimeVersion = (healthPayload as Record<string, unknown>).version;
  if (typeof runtimeVersion !== 'string' || !/^v\d+\.\d+\.\d+$/.test(runtimeVersion)) {
    throw new Error('GoTrue health response has no valid version');
  }
  return runtimeVersion;
}

function assertExpectedRuntimeVersion(runtimeVersion: string, expectedVersion: string): void {
  if (!SUPPORTED_COMPAT_VERSIONS.has(expectedVersion)) {
    throw new Error(`Unsupported GoTrue compatibility matrix version: ${expectedVersion}`);
  }
  if (runtimeVersion !== expectedVersion) {
    throw new Error(`Expected GoTrue ${expectedVersion} but runtime health reports ${runtimeVersion}`);
  }
}

async function getJson<T extends JsonObject>(path: string): Promise<T> {
  const res = await fetch(`${RUNTIME_URL}${path}`, {
    headers: { accept: 'application/json' },
  });

  expect(res.ok).toBe(true);
  return await res.json() as T;
}

async function postForm(
  endpoint: string,
  fields: Record<string, string | undefined>,
  headers: HeadersInit = {},
): Promise<Response> {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(fields)) {
    if (value) body.set(key, value);
  }

  return fetch(endpoint, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/x-www-form-urlencoded',
      ...headers,
    },
    body,
  });
}

function tokenAuthHeaders(): HeadersInit {
  if (TOKEN_AUTH_METHOD !== 'client_secret_basic') return {};
  if (!CLIENT_ID || !CLIENT_SECRET) return {};

  return {
    authorization: `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`,
  };
}

function expectSupabaseOAuthAccessTokenPayload(payload: JsonObject, issuer: string): void {
  expect(payload.sub).toBeDefined();
  expect(SUPABASE_RUNTIME_ROLES).toContain(payload.role as (typeof SUPABASE_RUNTIME_ROLES)[number]);
  expect(payload.exp).toBeDefined();
  expect(payload.iss).toBe(issuer);
  for (const claim of SUPABASE_REQUIRED_CLAIMS) {
    expect(payload).toHaveProperty(claim);
  }
  for (const claim of SUPABASE_METADATA_CLAIMS) {
    if (claim in payload) expect(payload[claim]).toBeDefined();
  }
  for (const claim of SUPABASE_OAUTH_ACCESS_TOKEN_CLAIMS) {
    expect(payload).toHaveProperty(claim);
  }
  for (const claim of SUPAOAUTH_CLAIM_KEYS) {
    expect(payload).not.toHaveProperty(claim);
  }

  if (CLIENT_ID) {
    expect(payload.client_id).toBe(CLIENT_ID);
  }

  expectGrantedOAuthScope(payload);
}

function expectGrantedOAuthScope(body: JsonObject): void {
  expect(typeof body.scope).toBe('string');
  const grantedScopes = String(body.scope).split(/\s+/).filter(Boolean);
  expect(grantedScopes.length).toBeGreaterThan(0);
  for (const scope of grantedScopes) {
    expect(SUPABASE_OAUTH_STANDARD_SCOPES).toContain(scope as (typeof SUPABASE_OAUTH_STANDARD_SCOPES)[number]);
  }
}

function decodeJwt(token: string): { header: JsonObject; payload: JsonObject } {
  const [encodedHeader, encodedPayload] = token.split('.');
  expect(encodedHeader).toBeDefined();
  expect(encodedPayload).toBeDefined();

  return {
    header: decodeJwtPart(encodedHeader),
    payload: decodeJwtPart(encodedPayload),
  };
}

function decodeJwtPart(value: string): JsonObject {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as JsonObject;
}

function expectEndpointPath(endpoint: string, expectedPath: string): void {
  const url = new URL(endpoint);
  expect(url.pathname).toBe(expectedPath);
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}
