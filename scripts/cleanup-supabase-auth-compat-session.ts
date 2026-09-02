#!/usr/bin/env bun

import { createClient } from '@supabase/supabase-js';
import { resolveSupabaseAdminKey, requiredSupabaseAdminKey } from './supabase-compat-env.js';

const runtimeUrl = requiredEnv('OAUTH_RUNTIME_URL').replace(/\/auth\/v1\/?$/, '').replace(/\/+$/, '');
const adminKey = resolveSupabaseAdminKey(process.env, { fullStack: true }) || requiredSupabaseAdminKey();
const userId = process.env.SUPABASE_COMPAT_USER_ID?.trim();

if (userId) {
  const admin = createClient(runtimeUrl, adminKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  const deleted = await admin.auth.admin.deleteUser(userId);
  if (deleted.error) throw new Error(`Unable to delete compatibility user: ${deleted.error.message}`);
  console.log('Deleted ephemeral Supabase Auth compatibility user.');
}

function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}
