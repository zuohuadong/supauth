#!/usr/bin/env bun

import {
  resolveSupabaseAdminKey,
  resolveManagementApiBases,
  resolveSupabaseManagementAdminKey,
  requiredSupabaseAdminKey,
} from './supabase-compat-env.js';

const runtimeUrl = requiredEnv('OAUTH_RUNTIME_URL').replace(/\/auth\/v1\/?$/, '').replace(/\/+$/, '');
const managementApiUrl = process.env.MANAGEMENT_URL?.trim().replace(/\/+$/, '')
  || process.env.SUPABASE_URL?.trim().replace(/\/+$/, '')
  || process.env.SUPABASE_FULLSTACK_URL?.trim().replace(/\/+$/, '')
  || runtimeUrl;
const managementApiBases = resolveManagementApiBases(managementApiUrl);
const tenantRef = requiredEnv('SUPACLOUD_AUTH_AUTHORITY_REF');
const adminKey = resolveSupabaseManagementAdminKey(process.env)
  || resolveSupabaseAdminKey(process.env, { fullStack: true })
  || requiredSupabaseAdminKey();
const userId = process.env.SUPABASE_COMPAT_USER_ID?.trim();

if (userId) {
  let deleted: Response | null = null;
  for (const managementApiBase of managementApiBases) {
    deleted = await fetch(`${managementApiBase}/v1/projects/${encodeURIComponent(tenantRef)}/auth/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        apikey: adminKey,
        authorization: `Bearer ${adminKey}`,
        'x-project-ref': tenantRef,
      },
    });
    if (deleted.status !== 404) break;
  }
  if (!deleted.ok) {
    const body = await deleted.json().catch(() => null) as { message?: string; error?: string } | null;
    throw new Error(`Unable to delete compatibility user: ${(body?.message || body?.error || `HTTP ${deleted.status}`)}`);
  }
  console.log('Deleted ephemeral Supabase Auth compatibility user.');
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}
