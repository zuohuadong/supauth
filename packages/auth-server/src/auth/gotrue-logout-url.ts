import { runtimeEnv } from '../config/platform-env.js';

type GoTrueEnvironment = Record<string, string | undefined>;

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

export function buildGoTrueLogoutUrl(baseUrl: string): string {
  const normalized = trimTrailingSlash(baseUrl.trim());
  if (!normalized) return '';
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return '';
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return '';
  parsed.search = '';
  parsed.hash = '';
  const pathname = trimTrailingSlash(parsed.pathname);
  parsed.pathname = pathname.endsWith('/auth/v1/logout') || pathname.endsWith('/logout')
    ? pathname
    : pathname.endsWith('/auth/v1') ? `${pathname}/logout` : `${pathname}/auth/v1/logout`;
  return parsed.toString();
}

export function resolveGoTrueLogoutUrl(env?: GoTrueEnvironment): string {
  const read = (name: string) => env ? env[name] : runtimeEnv(name);
  const baseUrl = read('GOTRUE_LOGOUT_URL')
    || read('OAUTH_RUNTIME_URL')
    || read('SUPACLOUD_RUNTIME_URL')
    || read('SUPABASE_URL')
    || '';
  return buildGoTrueLogoutUrl(baseUrl);
}
