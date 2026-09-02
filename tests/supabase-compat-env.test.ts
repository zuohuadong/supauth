import { describe, expect, it } from 'bun:test';
import {
  requiredSupabaseAdminKey,
  requiredSupabasePublicKey,
  resolveManagementApiBaseCandidates,
  resolveManagementApiBases,
  resolveSupabaseAdminKey,
  resolveSupabaseManagementAdminKey,
  resolveSupabasePublicKey,
} from '../scripts/supabase-compat-env.js';
import { requestProjectAuthUser } from '../scripts/supabase-management-api.js';

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

  it('prefers full-stack management admin keys before project-wide admin keys', () => {
    const env = {
      SUPABASE_FULLSTACK_SERVICE_ROLE_KEY: 'fixture-management-admin',
      SUPABASE_FULLSTACK_SECRET_KEY: 'fixture-management-secret',
      SUPABASE_SECRET_KEY: 'project-admin',
      SUPABASE_SERVICE_ROLE_KEY: 'legacy-admin',
    };

    expect(resolveSupabaseManagementAdminKey(env)).toBe('fixture-management-admin');
  });

  it('normalizes management API bases and keeps the /api alternate available', () => {
    expect(resolveManagementApiBases('https://auth.example.com')).toEqual([
      'https://auth.example.com',
      'https://auth.example.com/api',
    ]);
    expect(resolveManagementApiBases('https://auth.example.com/api')).toEqual([
      'https://auth.example.com/api',
      'https://auth.example.com',
    ]);
    expect(resolveManagementApiBases('https://auth.example.com/')).toEqual([
      'https://auth.example.com',
      'https://auth.example.com/api',
    ]);
  });

  it('builds ordered management API candidates from management, full-stack, root, and runtime bases', () => {
    const env = {
      MANAGEMENT_URL: 'https://management.example.com',
      SUPABASE_FULLSTACK_URL: 'https://fullstack.example.com/api',
      SUPABASE_URL: 'https://root.example.com/',
    };

    expect(resolveManagementApiBaseCandidates(env, 'https://runtime.example.com')).toEqual([
      'https://management.example.com',
      'https://management.example.com/api',
      'https://fullstack.example.com/api',
      'https://fullstack.example.com',
      'https://root.example.com',
      'https://root.example.com/api',
      'https://runtime.example.com',
      'https://runtime.example.com/api',
    ]);
  });

  it('falls through 404s from MANAGEMENT_URL to the next candidate base', async () => {
    const calls: Array<{ url: string; method: string }> = [];
    const fetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      calls.push({ url, method: init?.method || 'GET' });
      if (url.startsWith('https://management.example.com') || url.startsWith('https://fullstack.example.com')) {
        return new Response('not found', { status: 404 });
      }
      return Response.json({ id: 'user-one', email: 'compat@example.test' });
    };

    const managementApiBases = resolveManagementApiBaseCandidates(
      {
        MANAGEMENT_URL: 'https://management.example.com',
        SUPABASE_FULLSTACK_URL: 'https://fullstack.example.com',
        SUPABASE_URL: 'https://root.example.com',
      },
      'https://runtime.example.com',
    );

    const response = await requestProjectAuthUser(
      managementApiBases,
      'test-project',
      'admin-key',
      'POST',
      { email: 'compat@example.test' },
      fetchImpl as typeof fetch,
    );

    expect(response.ok).toBe(true);
    expect(calls.map(({ url }) => url)).toEqual([
      'https://management.example.com/v1/projects/test-project/auth/users',
      'https://management.example.com/api/v1/projects/test-project/auth/users',
      'https://fullstack.example.com/v1/projects/test-project/auth/users',
      'https://fullstack.example.com/api/v1/projects/test-project/auth/users',
      'https://root.example.com/v1/projects/test-project/auth/users',
    ]);
    expect(calls.every(({ method }) => method === 'POST')).toBe(true);
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
