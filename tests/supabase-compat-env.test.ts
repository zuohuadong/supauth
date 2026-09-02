import { describe, expect, it } from 'bun:test';
import {
  requiredSupabaseAdminKey,
  requiredSupabasePublicKey,
  resolveSupabaseAdminKey,
  resolveSupabasePublicKey,
} from '../scripts/supabase-compat-env.js';

describe('Supabase compatibility key selection', () => {
  it('prefers modern publishable and service-role keys', () => {
    const env = {
      SUPABASE_PUBLISHABLE_KEY: 'modern-public',
      SUPABASE_ANON_KEY: 'legacy-public',
      SUPABASE_SERVICE_ROLE_KEY: 'modern-admin',
      SUPABASE_SECRET_KEY: 'legacy-admin',
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

  it('prefers full-stack overrides before project-wide keys', () => {
    const env = {
      SUPABASE_FULLSTACK_PUBLISHABLE_KEY: 'fixture-public',
      SUPABASE_FULLSTACK_SERVICE_ROLE_KEY: 'fixture-admin',
      SUPABASE_PUBLISHABLE_KEY: 'project-public',
      SUPABASE_SECRET_KEY: 'project-admin',
    };

    expect(resolveSupabasePublicKey(env, { fullStack: true })).toBe('fixture-public');
    expect(resolveSupabaseAdminKey(env, { fullStack: true })).toBe('fixture-admin');
  });

  it('keeps fixture legacy keys ahead of project-wide modern keys', () => {
    const env = {
      SUPABASE_FULLSTACK_ANON_KEY: 'fixture-legacy-public',
      SUPABASE_FULLSTACK_SECRET_KEY: 'fixture-legacy-admin',
      SUPABASE_PUBLISHABLE_KEY: 'project-modern-public',
      SUPABASE_SECRET_KEY: 'project-modern-admin',
    };

    expect(resolveSupabasePublicKey(env, { fullStack: true })).toBe('fixture-legacy-public');
    expect(resolveSupabaseAdminKey(env, { fullStack: true })).toBe('fixture-legacy-admin');
  });

  it('fails with both accepted variable names when no key is configured', () => {
    expect(() => requiredSupabasePublicKey({})).toThrow(
      'SUPABASE_PUBLISHABLE_KEY or SUPABASE_ANON_KEY',
    );
    expect(() => requiredSupabaseAdminKey({})).toThrow(
      'SUPABASE_SERVICE_ROLE_KEY or SUPABASE_SECRET_KEY',
    );
  });
});
