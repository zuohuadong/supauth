import { describe, expect, it } from 'bun:test';
import {
  requiredSupabaseAdminKey,
  requiredSupabasePublicKey,
  resolveSupabaseAdminKey,
  resolveSupabasePublicKey,
  resolveSupabaseManagementAdminKey,
} from '../scripts/supabase-compat-env.js';

describe('Supabase compatibility key selection', () => {
  it('prefers modern publishable and secret keys', () => {
    const env = {
      SUPABASE_PUBLISHABLE_KEY: 'modern-public',
      SUPABASE_ANON_KEY: 'legacy-public',
      SUPABASE_SECRET_KEY: 'modern-admin',
      SUPABASE_SERVICE_ROLE_KEY: 'legacy-admin',
    };

    expect(resolveSupabasePublicKey(env)).toBe('modern-public');
    expect(resolveSupabaseAdminKey(env)).toBe('modern-admin');
  });

  it('keeps legacy JWT keys as fallbacks', () => {
    const env = {
      SUPABASE_ANON_KEY: 'legacy-public',
      SUPABASE_SERVICE_ROLE_KEY: 'legacy-admin',
    };

    expect(requiredSupabasePublicKey(env)).toBe('legacy-public');
    expect(requiredSupabaseAdminKey(env)).toBe('legacy-admin');
  });

  it('falls back to service-role keys when modern secret aliases are empty', () => {
    const env = {
      SUPABASE_SECRET_KEY: '  ',
      SUPABASE_SERVICE_ROLE_KEY: 'legacy-admin',
      SUPABASE_FULLSTACK_SECRET_KEY: '',
      SUPABASE_FULLSTACK_SERVICE_ROLE_KEY: 'fixture-legacy-admin',
    };

    expect(resolveSupabaseAdminKey(env)).toBe('legacy-admin');
    expect(resolveSupabaseAdminKey(env, { fullStack: true })).toBe('fixture-legacy-admin');
  });

  it('prefers full-stack overrides before project-wide keys', () => {
    const env = {
      SUPABASE_FULLSTACK_PUBLISHABLE_KEY: 'fixture-public',
      SUPABASE_FULLSTACK_SECRET_KEY: 'fixture-admin',
      SUPABASE_PUBLISHABLE_KEY: 'project-public',
      SUPABASE_SECRET_KEY: 'project-admin',
    };

    expect(resolveSupabasePublicKey(env, { fullStack: true })).toBe('fixture-public');
    expect(resolveSupabaseAdminKey(env, { fullStack: true })).toBe('fixture-admin');
  });

  it('keeps fixture legacy keys ahead of project-wide modern keys', () => {
    const env = {
      SUPABASE_FULLSTACK_ANON_KEY: 'fixture-legacy-public',
      SUPABASE_FULLSTACK_SERVICE_ROLE_KEY: 'fixture-legacy-admin',
      SUPABASE_PUBLISHABLE_KEY: 'project-modern-public',
      SUPABASE_SECRET_KEY: 'project-modern-admin',
    };

    expect(resolveSupabasePublicKey(env, { fullStack: true })).toBe('fixture-legacy-public');
    expect(resolveSupabaseAdminKey(env, { fullStack: true })).toBe('fixture-legacy-admin');
  });

  it('prefers SupaCloud management tokens for management API calls', () => {
    const env = {
      SUPACLOUD_MASTER_TOKEN: 'master-token',
      SUPACLOUD_INTERNAL_TOKEN: 'internal-token',
      SUPACLOUD_SERVICE_TOKEN: 'service-token',
      SUPABASE_FULLSTACK_SECRET_KEY: 'fixture-modern-admin',
      SUPABASE_FULLSTACK_SERVICE_ROLE_KEY: 'fixture-legacy-admin',
      SUPABASE_SECRET_KEY: 'project-modern-admin',
      SUPABASE_SERVICE_ROLE_KEY: 'project-legacy-admin',
    };

    expect(resolveSupabaseManagementAdminKey(env)).toBe('master-token');
  });

  it('fails with both accepted variable names when no key is configured', () => {
    expect(() => requiredSupabasePublicKey({})).toThrow(
      'SUPABASE_PUBLISHABLE_KEY or SUPABASE_ANON_KEY',
    );
    expect(() => requiredSupabaseAdminKey({})).toThrow(
      'SUPABASE_SECRET_KEY or SUPABASE_SERVICE_ROLE_KEY',
    );
  });
});
