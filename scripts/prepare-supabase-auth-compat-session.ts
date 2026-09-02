#!/usr/bin/env bun

import { appendFileSync } from 'node:fs';
import { createSupaCloudOAuthFetch } from '@supacloud/js';
import { createClient } from '@supabase/supabase-js';
import {
  resolveSupabaseAdminKey,
  resolveSupabasePublicKey,
  requiredSupabaseAdminKey,
  requiredSupabasePublicKey,
} from './supabase-compat-env.js';

const runtimeUrl = requiredEnv('OAUTH_RUNTIME_URL').replace(/\/auth\/v1\/?$/, '').replace(/\/+$/, '');
const clientId = requiredEnv('OAUTH21_CLIENT_ID');
const redirectUri = requiredEnv('OAUTH21_REDIRECT_URI');
const publicKey = resolveSupabasePublicKey(process.env, { fullStack: true }) || requiredSupabasePublicKey();
const adminKey = resolveSupabaseAdminKey(process.env, { fullStack: true }) || requiredSupabaseAdminKey();
const credentials = ephemeralCredentials(requiredEnv('SUPABASE_TEST_EMAIL'));
const githubEnv = requiredEnv('GITHUB_ENV');
const currentCompatVersion = 'v2.196.0';
const supportedCompatVersions = new Set(['v2.192.0', currentCompatVersion]);
const expectedCompatVersion = process.env.SUPABASE_AUTH_COMPAT_VERSION?.trim() || currentCompatVersion;
const runtimeVersion = await verifiedRuntimeVersion(runtimeUrl, expectedCompatVersion);
const expectedScopes = runtimeVersion === currentCompatVersion
  ? ['openid', 'email', 'profile', 'offline_access']
  : ['openid', 'email', 'profile'];

const codeVerifier = randomBase64Url(48);
const codeChallenge = base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))));
const state = crypto.randomUUID();
const authorizeUrl = new URL(`${runtimeUrl}/auth/v1/oauth/authorize`);
authorizeUrl.searchParams.set('response_type', 'code');
authorizeUrl.searchParams.set('client_id', clientId);
authorizeUrl.searchParams.set('redirect_uri', redirectUri);
authorizeUrl.searchParams.set('scope', expectedScopes.join(' '));
authorizeUrl.searchParams.set('state', state);
authorizeUrl.searchParams.set('code_challenge', codeChallenge);
authorizeUrl.searchParams.set('code_challenge_method', 'S256');

const authorizationResponse = await fetch(authorizeUrl, { redirect: 'manual' });
const authorizationLocation = authorizationResponse.headers.get('location');
if (![302, 303].includes(authorizationResponse.status) || !authorizationLocation) {
  throw new Error(`OAuth authorization initialization failed with status ${authorizationResponse.status}`);
}

const authorizationPageUrl = new URL(authorizationLocation, runtimeUrl);
const authorizationId = authorizationPageUrl.searchParams.get('authorization_id');
if (!authorizationId) throw new Error('OAuth authorization redirect did not include authorization_id');

const supabase = createClient(runtimeUrl, publicKey, {
  auth: {
    autoRefreshToken: false,
    persistSession: false,
    detectSessionInUrl: false,
  },
});

await createCompatibilityUser(runtimeUrl, adminKey, credentials, githubEnv);
const signIn = await supabase.auth.signInWithPassword(credentials);
if (signIn.error || !signIn.data.session) {
  throw new Error(`Supabase Auth compatibility sign-in failed: ${signIn.error?.message || 'missing session'}`);
}

const consentUrl = `${authorizationPageUrl.origin}/v1/public/oauth/authorizations/${encodeURIComponent(authorizationId)}`;
const userAuthorization = { authorization: `Bearer ${signIn.data.session.access_token}` };
const detailsResponse = await fetch(consentUrl, { headers: userAuthorization });
const details = await detailsResponse.json().catch(() => null) as OAuthErrorPayload | null;
if (!detailsResponse.ok) {
  throw new Error(`OAuth authorization details failed with status ${detailsResponse.status}: ${oauthError(details, 'invalid response')}`);
}
const approvalResponse = details?.redirect_url
  ? detailsResponse
  : await fetch(`${consentUrl}/consent`, {
    method: 'POST',
    headers: { ...userAuthorization, 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'approve' }),
  });
const approval = details?.redirect_url
  ? details
  : await approvalResponse.json().catch(() => null) as OAuthErrorPayload | null;
if (!approvalResponse.ok || !approval?.redirect_url) {
  throw new Error(`OAuth authorization approval failed with status ${approvalResponse.status}: ${oauthError(approval, 'missing redirect URL')}`);
}

const callbackUrl = new URL(approval.redirect_url);
if (callbackUrl.searchParams.get('state') !== state) throw new Error('OAuth authorization state mismatch');
const authorizationCode = callbackUrl.searchParams.get('code');
if (!authorizationCode) throw new Error('OAuth authorization approval did not return a code');

const tokenResponse = await fetch(`${runtimeUrl}/auth/v1/oauth/token`, {
  method: 'POST',
  headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: authorizationCode,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  }),
});
const tokens = await tokenResponse.json().catch(() => null) as { access_token?: string; refresh_token?: string; error?: string } | null;
if (!tokenResponse.ok || !tokens?.access_token || !tokens.refresh_token) {
  throw new Error(`OAuth authorization-code exchange failed with status ${tokenResponse.status}: ${tokens?.error || 'missing tokens'}`);
}

console.log(`::add-mask::${tokens.access_token}`);
console.log(`::add-mask::${tokens.refresh_token}`);
const oauthClient = createClient(runtimeUrl, publicKey, {
  global: {
    fetch: createSupaCloudOAuthFetch({
      clientId,
      tokenEndpoint: `${runtimeUrl}/auth/v1/oauth/token`,
    }),
  },
  auth: {
    autoRefreshToken: false,
    persistSession: false,
    detectSessionInUrl: false,
  },
});
const refreshed = await oauthClient.auth.refreshSession({ refresh_token: tokens.refresh_token });
if (refreshed.error || !refreshed.data.session) {
  throw new Error(`SupAuth OAuth compatibility refresh failed: ${refreshed.error?.message || 'missing session'}`);
}

const accessToken = refreshed.data.session.access_token;
const refreshToken = refreshed.data.session.refresh_token;
const payload = decodeJwtPayload(accessToken);
const grantedScopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/).filter(Boolean) : [];
if (
  payload.client_id !== clientId
  || typeof payload.sub !== 'string'
  || expectedScopes.some((scope) => !grantedScopes.includes(scope))
) {
  throw new Error([
    'SupAuth OAuth compatibility exchange returned an unexpected token shape',
    `client_id_present=${typeof payload.client_id === 'string'}`,
    `client_id_matches=${payload.client_id === clientId}`,
    `sub_present=${typeof payload.sub === 'string'}`,
    `scope_present=${typeof payload.scope === 'string'}`,
    `scope_values=${grantedScopes.join(',') || '<empty>'}`,
  ].join('; '));
}

console.log(`::add-mask::${accessToken}`);
console.log(`::add-mask::${refreshToken}`);
appendFileSync(githubEnv, `OAUTH21_ACCESS_TOKEN=${accessToken}\nOAUTH21_REFRESH_TOKEN=${refreshToken}\n`);
console.log('Prepared ephemeral OAuth compatibility session for this CI job.');

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

interface OAuthErrorPayload {
  redirect_url?: string;
  error?: string;
  error_description?: string;
  message?: string;
}

function oauthError(payload: OAuthErrorPayload | null, fallback: string): string {
  return payload?.error_description || payload?.message || payload?.error || fallback;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const payload = token.split('.')[1];
  if (!payload) throw new Error('OAuth access token is not a JWT');
  const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return JSON.parse(atob(padded)) as Record<string, unknown>;
}

function randomBase64Url(bytes: number): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return base64Url(value);
}

function base64Url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

interface CompatibilityCredentials {
  email: string;
  password: string;
}

function ephemeralCredentials(baseEmail: string): CompatibilityCredentials {
  const separator = baseEmail.lastIndexOf('@');
  if (separator < 1) throw new Error('SUPABASE_TEST_EMAIL must be an email address');
  const runId = crypto.randomUUID();
  return {
    email: `${baseEmail.slice(0, separator)}+${runId}@${baseEmail.slice(separator + 1)}`,
    password: randomBase64Url(48),
  };
}

async function createCompatibilityUser(
  runtimeUrl: string,
  adminKey: string,
  credentials: CompatibilityCredentials,
  githubEnv: string,
): Promise<void> {
  const admin = createClient(runtimeUrl, adminKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const created = await admin.auth.admin.createUser({ ...credentials, email_confirm: true });
  if (created.error || !created.data.user) {
    throw new Error(`Unable to create compatibility user: ${created.error?.message || 'missing user'}`);
  }
  console.log(`::add-mask::${credentials.email}`);
  console.log(`::add-mask::${credentials.password}`);
  appendFileSync(githubEnv, [
    `SUPABASE_TEST_EMAIL=${credentials.email}`,
    `SUPABASE_TEST_PASSWORD=${credentials.password}`,
    `SUPABASE_COMPAT_USER_ID=${created.data.user.id}`,
    '',
  ].join('\n'));
}

async function verifiedRuntimeVersion(runtimeBaseUrl: string, expectedVersion: string): Promise<string> {
  const response = await fetch(`${runtimeBaseUrl}/auth/v1/health`, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`GoTrue health check failed with status ${response.status}`);
  const runtimeVersion = runtimeVersionFromHealth(await response.json());
  assertExpectedRuntimeVersion(runtimeVersion, expectedVersion);
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
  if (!supportedCompatVersions.has(expectedVersion)) {
    throw new Error(`Unsupported GoTrue compatibility matrix version: ${expectedVersion}`);
  }
  if (runtimeVersion !== expectedVersion) {
    throw new Error(`Expected GoTrue ${expectedVersion} but runtime health reports ${runtimeVersion}`);
  }
}
