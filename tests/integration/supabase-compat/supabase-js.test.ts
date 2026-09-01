/**
 * Supabase Auth compatibility fixture (P0-16).
 *
 * The smoke contract runs without live env. Live mode verifies that SupaOAuth
 * keeps the GoTrue Auth runtime intact and that supabase-js can complete the
 * auth/session/token lifecycle against a real tenant.
 *
 * Live env:
 *   REQUIRE_SUPABASE_AUTH_COMPAT=1
 *   RUN_SUPABASE_RUNTIME_COMPAT=1
 *   OAUTH_RUNTIME_URL=https://api.example.com
 *   MANAGEMENT_URL=https://auth.example.com/api
 *   SUPABASE_PUBLISHABLE_KEY=<sb_publishable-key> (or legacy SUPABASE_ANON_KEY)
 *   SUPABASE_SECRET_KEY=<sb_secret-key> (or legacy SUPABASE_SERVICE_ROLE_KEY)
 *   SUPABASE_TEST_EMAIL=<test-user@example.com>
 *   SUPABASE_TEST_PASSWORD=<password>
 */

import { describe, it, expect } from 'bun:test';
import { createClient } from '@supabase/supabase-js';
import { resolveSupabaseAdminKey, resolveSupabasePublicKey } from '../../../scripts/supabase-compat-env.js';
import {
  SUPABASE_METADATA_CLAIMS,
  SUPABASE_REQUIRED_CLAIMS,
  SUPABASE_RUNTIME_ROLES,
  SUPAOAUTH_CLAIM_KEYS,
} from '../../../packages/shared/src/index.js';

const RUNTIME_URL = trimTrailingSlash(process.env.OAUTH_RUNTIME_URL || 'http://localhost:9999');
const MANAGEMENT_PORT = parseInt(process.env.PORT || '4010', 10);
const MANAGEMENT_URL = trimTrailingSlash(process.env.MANAGEMENT_URL || `http://localhost:${MANAGEMENT_PORT}`);
const STRICT_COMPAT = process.env.REQUIRE_SUPABASE_AUTH_COMPAT === '1';
const RUN_LIVE = STRICT_COMPAT || process.env.RUN_SUPABASE_RUNTIME_COMPAT === '1' || process.env.RUN_SUPABASE_OAUTH21_COMPAT === '1';
const SUPABASE_PUBLIC_KEY = resolveSupabasePublicKey();
const SUPABASE_ADMIN_KEY = resolveSupabaseAdminKey();
const TEST_EMAIL = process.env.SUPABASE_TEST_EMAIL || '';
const TEST_PASSWORD = process.env.SUPABASE_TEST_PASSWORD || '';

type LiveTestHandler = () => void | Promise<unknown>;

function liveIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE) it(name, fn);
}

function supabaseJsIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE && SUPABASE_PUBLIC_KEY) it(name, fn);
}

function authIt(name: string, fn: LiveTestHandler) {
  if (RUN_LIVE && SUPABASE_PUBLIC_KEY && TEST_EMAIL && TEST_PASSWORD) it(name, fn);
}

if (STRICT_COMPAT) {
  assertRequiredEnv(['OAUTH_RUNTIME_URL', 'MANAGEMENT_URL', 'SUPABASE_TEST_EMAIL', 'SUPABASE_TEST_PASSWORD']);
  assertRequiredValues({
    SUPABASE_PUBLIC_KEY,
    SUPABASE_ADMIN_KEY,
  });
}

function supabaseClient() {
  return createClient(RUNTIME_URL, SUPABASE_PUBLIC_KEY, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

describe('Supabase runtime compatibility', () => {
  liveIt('/auth/v1/.well-known/openid-configuration returns GoTrue discovery', async () => {
    const res = await fetch(`${RUNTIME_URL}/auth/v1/.well-known/openid-configuration`);
    expect(res.ok).toBe(true);

    const body = await res.json();
    expect(body.issuer).toBeDefined();
    expect(body.authorization_endpoint).toBeDefined();
    expect(body.token_endpoint).toBeDefined();
    expect(body.runtime_mode).toBeUndefined();
  });

  liveIt('/auth/v1/.well-known/jwks.json returns JWKS', async () => {
    const res = await fetch(`${RUNTIME_URL}/auth/v1/.well-known/jwks.json`);
    expect(res.ok).toBe(true);

    const body = await res.json();
    expect(Array.isArray(body.keys)).toBe(true);
  });

  liveIt('Management API health returns SupaOAuth response', async () => {
    const res = await fetch(`${MANAGEMENT_URL}/v1/health`);
    expect(res.ok).toBe(true);

    const body = await res.json();
    expect(body.runtime_mode).toBe('gotrue');
  });

  supabaseJsIt('supabase-js can initialize and read current session', async () => {
    const client = supabaseClient();
    const { data, error } = await client.auth.getSession();
    expect(error).toBeNull();
    expect(data).toHaveProperty('session');
  });

  authIt('supabase-js signUp/signIn/getSession/refresh/signOut path works', async () => {
    const client = supabaseClient();
    await client.auth.signUp({ email: TEST_EMAIL, password: TEST_PASSWORD });

    const signIn = await client.auth.signInWithPassword({
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    });
    expect(signIn.error).toBeNull();
    expect(signIn.data.session?.access_token).toBeDefined();
    expect(signIn.data.session?.refresh_token).toBeDefined();

    const session = await client.auth.getSession();
    expect(session.error).toBeNull();
    expect(session.data.session?.access_token).toBeDefined();

    const refreshed = await client.auth.refreshSession();
    expect(refreshed.error).toBeNull();
    expect(refreshed.data.session?.access_token).toBeDefined();

    const signOut = await client.auth.signOut();
    expect(signOut.error).toBeNull();
  });

  authIt('supabase-js user and JWT/JWKS path works with authenticated token', async () => {
    const client = supabaseClient();
    const signIn = await client.auth.signInWithPassword({ email: TEST_EMAIL, password: TEST_PASSWORD });
    expect(signIn.error).toBeNull();

    const user = await client.auth.getUser();
    expect(user.error).toBeNull();
    expect(user.data.user?.id).toBeDefined();

    const token = signIn.data.session?.access_token || '';
    const payload = decodeJwtPayload(token);
    expect(payload.sub).toBe(user.data.user?.id);
    expect(SUPABASE_RUNTIME_ROLES).toContain(payload.role as (typeof SUPABASE_RUNTIME_ROLES)[number]);
    for (const claim of SUPABASE_REQUIRED_CLAIMS) {
      expect(payload).toHaveProperty(claim);
    }
    for (const claim of SUPABASE_METADATA_CLAIMS) {
      expect(payload).toHaveProperty(claim);
    }
    expect(payload.supaoauth).toBeUndefined();
    for (const claim of SUPAOAUTH_CLAIM_KEYS) {
      expect(payload).not.toHaveProperty(claim);
    }
  });

  authIt('supabase-js completes TOTP and verifies the v2.193+ admin factor downgrade', async () => {
    const client = supabaseClient();
    const gotrueVersion = await readGotrueVersion();
    const signIn = await client.auth.signInWithPassword({ email: TEST_EMAIL, password: TEST_PASSWORD });
    expect(signIn.error).toBeNull();
    expect(signIn.data.session?.access_token).toBeDefined();
    expect(signIn.data.user?.id).toBeDefined();

    let factorId: string | null = null;
    let factorRemoved = false;
    try {
      const enrollment = await client.auth.mfa.enroll({
        factorType: 'totp',
        friendlyName: `supaoauth-compat-${Date.now()}`,
        issuer: 'SupaOAuth compatibility',
      });
      expect(enrollment.error).toBeNull();
      expect(enrollment.data?.type).toBe('totp');
      factorId = enrollment.data?.id || null;
      const secret = enrollment.data?.totp.secret;
      expect(factorId).toBeTruthy();
      expect(secret).toBeTruthy();

      const challenge = await client.auth.mfa.challenge({ factorId: factorId as string });
      expect(challenge.error).toBeNull();
      expect(challenge.data?.id).toBeTruthy();

      const verification = await client.auth.mfa.verify({
        factorId: factorId as string,
        challengeId: challenge.data?.id as string,
        code: await generateTotpCode(secret as string),
      });
      expect(verification.error).toBeNull();
      expect(verification.data?.access_token).toBeDefined();
      const verifiedPayload = decodeJwtPayload(verification.data?.access_token || '');
      expect(verifiedPayload.aal).toBe('aal2');
      expect(amrMethods(verifiedPayload)).toContain('totp');
      expect(amrEntries(verifiedPayload).every((entry) => !('factor_type' in entry))).toBe(true);

      const assurance = await client.auth.mfa.getAuthenticatorAssuranceLevel();
      expect(assurance.error).toBeNull();
      expect(assurance.data?.currentLevel).toBe('aal2');

      if (versionAtLeast(gotrueVersion, [2, 193, 0])) {
        const adminClient = createClient(RUNTIME_URL, SUPABASE_ADMIN_KEY, {
          auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
        });
        const deletion = await adminClient.auth.admin.mfa.deleteFactor({
          userId: signIn.data.user?.id as string,
          id: factorId as string,
        });
        expect(deletion.error).toBeNull();
        factorRemoved = true;

        const downgraded = await client.auth.refreshSession();
        expect(downgraded.error).toBeNull();
        const downgradedPayload = decodeJwtPayload(downgraded.data.session?.access_token || '');
        expect(downgradedPayload.aal).toBe('aal1');
        expect(amrMethods(downgradedPayload)).not.toContain('totp');
        expect(amrEntries(downgradedPayload).every((entry) => !('factor_type' in entry))).toBe(true);
      } else {
        const unenroll = await client.auth.mfa.unenroll({ factorId: factorId as string });
        expect(unenroll.error).toBeNull();
        factorRemoved = true;
      }
    } finally {
      if (factorId && !factorRemoved) {
        const cleanup = await client.auth.mfa.unenroll({ factorId });
        expect(cleanup.error).toBeNull();
      }
      const signOut = await client.auth.signOut({ scope: 'local' });
      expect(signOut.error).toBeNull();
    }
  });

  it('GoTrue JWT required claims are defined in compatibility spec', () => {
    const expectedClaims = [
      'iss',
      'aud',
      'exp',
      'iat',
      'sub',
      'role',
      'aal',
      'session_id',
      'email',
      'phone',
      'is_anonymous',
    ];
    for (const claim of SUPABASE_REQUIRED_CLAIMS) {
      expect(expectedClaims).toContain(claim);
    }
    expect(SUPABASE_METADATA_CLAIMS).toEqual(['app_metadata', 'user_metadata']);
    expect(SUPABASE_RUNTIME_ROLES).toEqual(['anon', 'authenticated', 'service_role']);
  });

  it('generates RFC 6238 TOTP at the exact injected client-time boundary', async () => {
    const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

    expect(await generateTotpCode(rfcSecret, 29_999)).toBe('755224');
    expect(await generateTotpCode(rfcSecret, 30_000)).toBe('287082');
    expect(await generateTotpCode(rfcSecret, 59_000)).toBe('287082');
  });
});

function decodeJwtPayload(token: string): Record<string, unknown> {
  const [, payload] = token.split('.');
  expect(payload).toBeDefined();
  const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

function amrEntries(payload: Record<string, unknown>): Array<Record<string, unknown>> {
  if (!Array.isArray(payload.amr)) return [];
  return payload.amr.filter((entry): entry is Record<string, unknown> => (
    typeof entry === 'object' && entry !== null
  ));
}

function amrMethods(payload: Record<string, unknown>): string[] {
  return amrEntries(payload)
    .map((entry) => entry.method)
    .filter((method): method is string => typeof method === 'string');
}

async function readGotrueVersion(): Promise<string> {
  const response = await fetch(`${RUNTIME_URL}/auth/v1/health`);
  if (!response.ok) throw new Error(`Unable to read GoTrue version: HTTP ${response.status}`);
  const body = await response.json() as { version?: unknown };
  if (typeof body.version !== 'string') throw new Error('GoTrue health response is missing version');
  return body.version;
}

function versionAtLeast(version: string, minimum: readonly [number, number, number]): boolean {
  const match = version.match(/^v?(\d+)\.(\d+)\.(\d+)/);
  if (!match) throw new Error(`Invalid GoTrue version: ${version}`);
  const actual = match.slice(1, 4).map(Number);
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual[index] !== minimum[index]) return actual[index] > minimum[index];
  }
  return true;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

function assertRequiredEnv(names: string[]) {
  const missing = names.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required Supabase Auth compatibility env: ${missing.join(', ')}`);
  }
}

function assertRequiredValues(values: Record<string, string>) {
  const missing = Object.entries(values).filter(([, value]) => !value).map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`Missing required Supabase Auth compatibility env: ${missing.join(', ')}`);
  }
}

async function generateTotpCode(secret: string, now = Date.now()): Promise<string> {
  const counter = Math.floor(now / 30_000);
  const counterBytes = new ArrayBuffer(8);
  new DataView(counterBytes).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey(
    'raw',
    decodeBase32(secret),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = digest[digest.length - 1] & 0x0f;
  const binaryCode = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  return String(binaryCode % 1_000_000).padStart(6, '0');
}

function decodeBase32(value: string): Uint8Array<ArrayBuffer> {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = value.toUpperCase().replaceAll('=', '').replaceAll(/\s+/g, '');
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of normalized) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) throw new Error('GoTrue returned an invalid TOTP secret');
    buffer = (buffer << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}
