// Database connection — uses SupaCloud's Postgres instance
// SupaOAuth metadata lives in the `supaoauth` schema, separate from `auth` (GoTrue)

import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.js';
import { runtimeEnv } from '../config/platform-env.js';

export interface DbConfig {
  url: string;
}

function getConnectionConfig(): DbConfig {
  const url = runtimeEnv('SUPACLOUD_DATABASE_URL') || runtimeEnv('DATABASE_URL') || '';
  if (!url) {
    throw new Error('DATABASE_URL or SUPACLOUD_DATABASE_URL is required for SupaOAuth metadata DB');
  }
  return { url };
}

let _db: ReturnType<typeof drizzle> | null = null;
let _sql: ReturnType<typeof postgres> | null = null;

export function getDb() {
  if (_db) return _db;
  const { url } = getConnectionConfig();
  _sql = postgres(url, {
    max: 10,
    idle_timeout: 20,
    connect_timeout: 2,
  });
  _db = drizzle(_sql, { schema });
  return _db;
}

export async function closeDb() {
  if (_sql) {
    await _sql.end();
    _sql = null;
    _db = null;
  }
}

// Re-export schema for convenience
export { schema };
export type Database = ReturnType<typeof drizzle>;
