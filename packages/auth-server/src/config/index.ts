// SupaOAuth server configuration — loaded from server-side env only (no VITE_)

import { firstRuntimeEnv, runtimeEnv } from './platform-env.js';

export interface ServerConfig {
  port: number;
  host: string;
  nodeEnv: string;
  supacloudApiUrl: string;
  supacloudMasterToken: string;
  supabaseServiceRoleKey: string;
  supaoauthBffSigningSecret: string;
  projectRef: string;
  oauthAuthorizationProjectRef: string;
  oauthRuntimeUrl: string;
  oauthRuntimeInternalUrl: string;
  publicBaseUrl: string;
  trustProxyHeaders: boolean;
  /** The only supported auth runtime. GoTrue owns users, sessions and tokens. */
  runtimeMode: 'gotrue';
  databaseUrl: string;
  corsOrigins: string[];
  logLevel: 'debug' | 'info' | 'warn' | 'error';
}

const MIN_BFF_SIGNING_SECRET_LENGTH = 32;

let _config: ServerConfig | null = null;

function env(...names: string[]): string {
  return firstRuntimeEnv(...names);
}

function booleanEnv(name: string, defaultValue = false) {
  const value = runtimeEnv(name);
  if (value === undefined || value === '') return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function isHttpUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export function loadConfig(): ServerConfig {
  const runtimeUrl = env('OAUTH_RUNTIME_URL', 'SUPACLOUD_RUNTIME_URL', 'SUPABASE_URL');

  const configuredRuntimeMode = runtimeEnv('RUNTIME_MODE')?.trim();
  if (configuredRuntimeMode && configuredRuntimeMode !== 'gotrue') {
    throw new Error('RUNTIME_MODE must be "gotrue"; external OIDC runtimes are not supported');
  }

  _config = {
    port: parseInt(runtimeEnv('PORT') || '4010', 10),
    host: runtimeEnv('HOST') || '0.0.0.0',
    nodeEnv: runtimeEnv('NODE_ENV') || 'development',
    supacloudApiUrl: env(
      'SUPACLOUD_API_URL',
      'SUPACLOUD_INTERNAL_API_URL',
      'SUPACLOUD_MANAGEMENT_API_URL',
      'SUPACLOUD_INTERNAL_SUPABASE_URL',
    ),
    supacloudMasterToken: env('SUPACLOUD_MASTER_TOKEN', 'SUPACLOUD_INTERNAL_TOKEN', 'SUPACLOUD_SERVICE_TOKEN'),
    supabaseServiceRoleKey: env('SUPABASE_SERVICE_ROLE_KEY'),
    supaoauthBffSigningSecret: env('SUPAOAUTH_BFF_SIGNING_SECRET'),
    projectRef: env('PROJECT_REF', 'SUPACLOUD_PROJECT_REF', 'SUPABASE_PROJECT_REF'),
    oauthAuthorizationProjectRef: env(
      'SUPACLOUD_AUTH_AUTHORITY_REF',
      'SUPAUTH_OAUTH_AUTHORIZATION_PROJECT_REF',
      'OAUTH_AUTHORIZATION_PROJECT_REF',
      'GOTRUE_AUTHORIZATION_PROJECT_REF',
    ),
    oauthRuntimeUrl: runtimeUrl,
    // OAuth 专用内部地址必须优先，避免遗留的 SupaCloud 地址把已更新的 GoTrue 运行地址覆盖。
    oauthRuntimeInternalUrl: env('OAUTH_RUNTIME_INTERNAL_URL', 'SUPACLOUD_RUNTIME_INTERNAL_URL', 'GOTRUE_INTERNAL_URL') || runtimeUrl,
    publicBaseUrl: env('SUPAUTH_PUBLIC_URL', 'AUTH_PUBLIC_URL', 'SUPAUTH_INSTALLED_BASE_URL', 'SUPAUTH_BASE_URL', 'OAUTH_PUBLIC_BASE_URL'),
    trustProxyHeaders: booleanEnv('TRUST_PROXY_HEADERS'),
    runtimeMode: 'gotrue',
    databaseUrl: env('SUPACLOUD_DATABASE_URL', 'SUPABASE_DB_URL', 'DATABASE_URL'),
    corsOrigins: (runtimeEnv('CORS_ORIGINS') || 'http://localhost:5173').split(','),
    logLevel: (runtimeEnv('LOG_LEVEL') as ServerConfig['logLevel']) || 'info',
  };
  return _config;
}

export function getConfig(): ServerConfig {
  return _config ?? loadConfig();
}

export function validateBffSigningSecret(config: Pick<ServerConfig, 'supaoauthBffSigningSecret' | 'supacloudMasterToken'>): string | undefined {
  const secret = config.supaoauthBffSigningSecret;
  if (!secret) return 'SUPAOAUTH_BFF_SIGNING_SECRET is required';
  if (secret.length < MIN_BFF_SIGNING_SECRET_LENGTH) {
    return 'SUPAOAUTH_BFF_SIGNING_SECRET must be at least 32 characters';
  }
  if (secret === config.supacloudMasterToken) {
    return 'SUPAOAUTH_BFF_SIGNING_SECRET must be independent from the SupaCloud token';
  }
  return undefined;
}

export function validateConfig(config: ServerConfig): string[] {
  const errors: string[] = [];
  if (!config.supacloudApiUrl) {
    errors.push('SUPACLOUD_API_URL, SUPACLOUD_INTERNAL_API_URL, or SUPACLOUD_INTERNAL_SUPABASE_URL is required');
  }
  if (!config.supacloudMasterToken) errors.push('SUPACLOUD_MASTER_TOKEN or SUPACLOUD_INTERNAL_TOKEN is required');
  if (!config.supabaseServiceRoleKey) errors.push('SUPABASE_SERVICE_ROLE_KEY is required');
  if (!config.projectRef) errors.push('PROJECT_REF or SUPACLOUD_PROJECT_REF is required');
  if (!config.oauthRuntimeUrl) errors.push('OAUTH_RUNTIME_URL, SUPACLOUD_RUNTIME_URL, or SUPABASE_URL is required');
  if (config.publicBaseUrl && !isHttpUrl(config.publicBaseUrl)) {
    errors.push('SUPAUTH_PUBLIC_URL or AUTH_PUBLIC_URL must be a valid http(s) URL');
  }
  if (config.nodeEnv === 'production' && !config.publicBaseUrl) {
    errors.push('SUPAUTH_PUBLIC_URL or AUTH_PUBLIC_URL is required when NODE_ENV=production');
  }
  if (!config.databaseUrl) errors.push('DATABASE_URL or SUPACLOUD_DATABASE_URL is required');
  const bffSigningSecretError = validateBffSigningSecret(config);
  if (bffSigningSecretError) errors.push(bffSigningSecretError);
  if (config.runtimeMode !== 'gotrue') {
    errors.push('RUNTIME_MODE must be "gotrue"; external OIDC runtimes are not supported');
  }
  return errors;
}

export function enforceStartupConfig(config: ServerConfig): void {
  const errors = validateConfig(config);
  if (errors.length === 0) return;

  const errorDetails = errors.join('; ');
  if (config.nodeEnv === 'production') {
    throw new Error(`SupaOAuth configuration is invalid: ${errorDetails}`);
  }

  console.warn('SupaOAuth config warnings:', errorDetails);
}
