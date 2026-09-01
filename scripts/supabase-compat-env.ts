type Environment = Record<string, string | undefined>;

const PUBLIC_KEY_NAMES = [
  'SUPABASE_PUBLISHABLE_KEY',
  'SUPABASE_ANON_KEY',
] as const;

const ADMIN_KEY_NAMES = [
  'SUPABASE_SECRET_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
] as const;

const FULL_STACK_PUBLIC_KEY_NAMES = [
  'SUPABASE_FULLSTACK_PUBLISHABLE_KEY',
  'SUPABASE_FULLSTACK_ANON_KEY',
  ...PUBLIC_KEY_NAMES,
] as const;

const FULL_STACK_ADMIN_KEY_NAMES = [
  'SUPABASE_FULLSTACK_SECRET_KEY',
  'SUPABASE_FULLSTACK_SERVICE_ROLE_KEY',
  ...ADMIN_KEY_NAMES,
] as const;

export function resolveSupabasePublicKey(
  env: Environment = process.env,
  options: { fullStack?: boolean } = {},
): string {
  return firstNonEmpty(env, options.fullStack ? FULL_STACK_PUBLIC_KEY_NAMES : PUBLIC_KEY_NAMES);
}

export function resolveSupabaseAdminKey(
  env: Environment = process.env,
  options: { fullStack?: boolean } = {},
): string {
  return firstNonEmpty(env, options.fullStack ? FULL_STACK_ADMIN_KEY_NAMES : ADMIN_KEY_NAMES);
}

export function requiredSupabasePublicKey(env: Environment = process.env): string {
  return requiredFirstNonEmpty(env, PUBLIC_KEY_NAMES);
}

export function requiredSupabaseAdminKey(env: Environment = process.env): string {
  return requiredFirstNonEmpty(env, ADMIN_KEY_NAMES);
}

function firstNonEmpty(env: Environment, names: readonly string[]): string {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return value;
  }
  return '';
}

function requiredFirstNonEmpty(env: Environment, names: readonly string[]): string {
  const value = firstNonEmpty(env, names);
  if (value) return value;
  throw new Error(`Missing required environment variable: ${names.join(' or ')}`);
}
