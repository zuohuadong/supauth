import { HOSTED_MIGRATIONS } from '../packages/auth-server/src/db/migrate.js';

export const SUPAUTH_CUSTOM_UI_FALLBACK_ROUTE = '/custom-ui/*';

/**
 * Persistent control-plane domains owned by the SupaCloud Management API.
 *
 * Authentication runtime state is deliberately absent from this list.  A
 * SupaCloud management facade may expose a read/action endpoint for a
 * GoTrue-owned resource, but that endpoint must not turn the facade into a
 * second source of truth.
 */
export const SUPACLOUD_OWNED_MANAGEMENT_DOMAINS = [
  'applications',
  'organizations',
  'organization_members',
  'organization_invitations',
  'organization_jit',
  'organization_applications',
  'rbac_roles',
  'rbac_permissions',
  'rbac_assignments',
  'audit',
  'webhooks',
  'webhook_delivery',
  'providers',
  'secret_manager',
  'tenant_collaborators',
  'tenant_collaborator_invitations',
] as const;

/**
 * GoTrue is the only authority for authentication runtime state.  These
 * identifiers are part of the install artifact so a platform can validate
 * that management facades are delegated rather than persisted locally.
 */
export const GOTRUE_OWNED_RUNTIME_DOMAINS = [
  'auth.users',
  'auth.identities',
  'auth.oauth_clients',
  'auth.oauth_grants',
  'auth.oauth_authorizations',
  'auth.sessions',
  'auth.refresh_tokens',
  'auth.mfa_factors',
  'oauth_oidc_protocol',
  'jwt_signing_and_jwks',
  '/auth/v1/*',
] as const;

/**
 * SupaCloud/SupaOAuth may expose these management facades, but every action
 * is delegated to GoTrue and read back from GoTrue.  No facade entry is a
 * local auth table or an alternate issuer.
 */
export const SUPACLOUD_MANAGEMENT_FACADES = [
  'oauth_clients',
  'users',
  'user_mfa',
] as const;

export const SUPAUTH_OVERLAY_DOMAINS = [
  'hosted_auth_pages',
  'account_center_pages',
  'account_claim_pages',
  'sign_in_experience_overrides',
  'connector_visibility_overrides',
  'oauth_consent_policy',
  'oauth_consent_decisions',
  'api_resources',
  'api_resource_bindings',
  'tenant_branding_assets',
  'tenant_phrases',
  'custom_profile_fields',
  'compatibility_helpers',
  'organization_templates',
  'enterprise_sso_mapping',
  'account_provisioning_records',
] as const;

export const SUPACLOUD_MANAGED_BACKGROUND_JOBS = [
  {
    name: 'webhook-delivery',
    owner: 'supacloud',
    trigger: 'POST /v1/projects/{projectRef}/webhooks/events',
    description: 'SupaCloud signs, retries, records diagnostics, and disables failing webhooks.',
  },
  {
    name: 'account-provisioning-import',
    owner: 'supacloud-function',
    trigger: 'POST /api/v1/account-provisioning/import',
    description: 'Runs inside the SupAuth Function handler; no standalone import service is required.',
  },
] as const;

export const FORBIDDEN_RUNTIME_FORMS = [
  'standalone-http-server',
  'systemd-service',
  'pm2-process',
  'webhook-worker-process',
  'cron-process-owned-by-supauth',
] as const;

export const SUPAOAUTH_TABLE_OWNERSHIP = {
  api_resources: { class: 'supauth-overlay', domain: 'api_resources' },
  scopes: { class: 'supauth-overlay', domain: 'api_resources' },
  organizations: { class: 'legacy-temporary', replacement: 'supacloud-management-api:organizations' },
  organization_members: { class: 'legacy-temporary', replacement: 'supacloud-management-api:organization_members' },
  roles: { class: 'legacy-temporary', replacement: 'supacloud-management-api:rbac_roles' },
  permissions: { class: 'legacy-temporary', replacement: 'supacloud-management-api:rbac_permissions' },
  sign_in_experience: { class: 'supauth-overlay', domain: 'sign_in_experience_overrides' },
  application_sign_in_experience: { class: 'supauth-overlay', domain: 'sign_in_experience_overrides' },
  audit_logs: { class: 'legacy-temporary', replacement: 'supacloud-management-api:audit' },
  connectors: { class: 'supauth-overlay', domain: 'connector_visibility_overrides' },
  application_bindings: { class: 'supauth-overlay', domain: 'api_resource_bindings' },
  role_assignments: { class: 'legacy-temporary', replacement: 'supacloud-management-api:rbac_assignments' },
  user_consents: { class: 'legacy-temporary', replacement: 'gotrue-oauth-grants' },
  oauth_consent_decisions: { class: 'supauth-overlay', domain: 'oauth_consent_decisions' },
  organization_templates: { class: 'supauth-overlay', domain: 'organization_templates' },
  organization_template_instantiations: { class: 'supauth-overlay', domain: 'organization_templates' },
  provisioning_records: { class: 'legacy-temporary', replacement: 'supacloud-app-install-state' },
  security_config: { class: 'supauth-overlay', domain: 'compatibility_helpers' },
  enterprise_sso_config: { class: 'supauth-overlay', domain: 'enterprise_sso_mapping' },
  api_version_log: { class: 'supauth-overlay', domain: 'compatibility_helpers' },
  application_secrets: { class: 'legacy-temporary', replacement: 'gotrue:oauth-client-secret-rotation' },
  application_consent_settings: { class: 'supauth-overlay', domain: 'oauth_consent_policy' },
  account_provisioning_records: { class: 'supauth-overlay', domain: 'account_provisioning_records' },
  organization_invitations: { class: 'legacy-temporary', replacement: 'supacloud-management-api:organization_invitations' },
  organization_jit_settings: { class: 'legacy-temporary', replacement: 'supacloud-management-api:organization_jit' },
  organization_applications: { class: 'legacy-temporary', replacement: 'supacloud-management-api:organization_applications' },
  connector_factories: { class: 'supauth-overlay', domain: 'connector_visibility_overrides' },
  tenant_configs: { class: 'supauth-overlay', domain: 'tenant_branding_assets' },
} as const;

export function createSupacloudAppManifest(input: {
  functionBundle: string;
  adminStaticDir: string;
  openapiPath: string;
}) {
  return {
    schema_version: 1,
    app_id: 'supauth',
    name: 'SupAuth',
    install_mode: 'supacloud-project-scoped',
    http_runtime: 'supacloud-functions-only',
    // Retained as the control-plane summary for schema-v1 consumers. Runtime
    // authority is normative in the explicit map and domain lists below.
    source_of_truth: 'supacloud-management-api',
    runtime_mode: 'gotrue',
    authority: {
      auth_runtime: 'gotrue',
      control_plane: 'supacloud-management-api',
      overlay: 'supaoauth-schema',
    },
    supacloud_owned_management_domains: SUPACLOUD_OWNED_MANAGEMENT_DOMAINS,
    gotrue_owned_runtime_domains: GOTRUE_OWNED_RUNTIME_DOMAINS,
    supacloud_management_facades: SUPACLOUD_MANAGEMENT_FACADES,
    supauth_overlay_domains: SUPAUTH_OVERLAY_DOMAINS,
    supacloud_managed_background_jobs: SUPACLOUD_MANAGED_BACKGROUND_JOBS,
    forbidden_runtime_forms: FORBIDDEN_RUNTIME_FORMS,
    supaoauth_table_ownership: SUPAOAUTH_TABLE_OWNERSHIP,
    created_at: new Date().toISOString(),
    artifacts: {
      function_bundle: input.functionBundle,
      admin_static_dir: input.adminStaticDir,
      openapi: input.openapiPath,
    },
    required_supacloud_env: [
      { name: 'SUPACLOUD_INTERNAL_API_URL', secret: false, description: 'Project-scoped SupaCloud Management API base URL.' },
      { name: 'SUPACLOUD_INTERNAL_TOKEN', secret: true, description: 'Project-scoped internal token for server-side SupaCloud API calls.' },
      { name: 'SUPABASE_SERVICE_ROLE_KEY', secret: true, description: 'Project-scoped service-role key for Supabase Storage data-plane calls.' },
      { name: 'SUPAOAUTH_BFF_SIGNING_SECRET', secret: true, description: 'Independent shared HMAC secret for SupAuth actor proof; server-side only.' },
      { name: 'SUPACLOUD_PROJECT_REF', secret: false, description: 'Current SupaCloud project ref.' },
      { name: 'SUPACLOUD_RUNTIME_URL', secret: false, description: 'Public Supabase-compatible runtime URL for the project.' },
      { name: 'SUPACLOUD_RUNTIME_INTERNAL_URL', secret: false, optional: true, description: 'Internal GoTrue/runtime URL when different from the public runtime URL.' },
      { name: 'SUPAUTH_OAUTH_AUTHORIZATION_PROJECT_REF', secret: false, optional: true, description: 'Center IdP project ref that owns GoTrue OAuth authorization rows when different from the business project.' },
      { name: 'SUPACLOUD_DATABASE_URL', secret: true, description: 'Project database URL for SupAuth overlay tables and migrations.' },
      { name: 'ADMIN_SSO_ISSUER', secret: false, description: 'Explicit public GoTrue/OIDC issuer used by the Admin Console.' },
      { name: 'ADMIN_SSO_CLIENT_ID', secret: false, description: 'Explicit public OAuth client id registered for the Admin Console.' },
      { name: 'ADMIN_SSO_JWKS_URI', secret: false, optional: true, description: 'Optional explicit issuer JWKS endpoint.' },
      { name: 'ADMIN_SSO_AUDIENCE', secret: false, optional: true, description: 'Optional explicit accepted access-token audience.' },
      { name: 'ADMIN_SSO_REDIRECT_URI', secret: false, optional: true, description: 'Optional explicit Admin OAuth redirect URI.' },
      { name: 'ADMIN_SSO_POST_LOGOUT_REDIRECT_URI', secret: false, optional: true, description: 'Optional explicit Admin post-logout redirect URI.' },
      { name: 'ADMIN_SSO_REQUIRE_AAL2', secret: false, optional: true, description: 'Server-only Admin MFA gate. Disabled unless set to true; never expose as VITE_*.' },
      { name: 'ADMIN_SSO_ALLOWED_EMAILS', secret: true, optional: true, description: 'Optional server-only email allowlist fallback when the database allowlist is empty.' },
      { name: 'ADMIN_SSO_ALLOWED_DOMAINS', secret: true, optional: true, description: 'Legacy compatibility field; domain entries never grant Admin access.' },
    ],
    admin_sso: {
      required_env: ['ADMIN_SSO_ISSUER', 'ADMIN_SSO_CLIENT_ID'],
      optional_env: [
        'ADMIN_SSO_JWKS_URI',
        'ADMIN_SSO_AUDIENCE',
        'ADMIN_SSO_REDIRECT_URI',
        'ADMIN_SSO_POST_LOGOUT_REDIRECT_URI',
        'ADMIN_SSO_REQUIRE_AAL2',
      ],
      allowlist: {
        database_table: 'supaoauth.security_config',
        database_fields: ['admin_allowed_emails', 'admin_allowed_domains'],
        optional_secret_env: ['ADMIN_SSO_ALLOWED_EMAILS', 'ADMIN_SSO_ALLOWED_DOMAINS'],
        install_rule: 'exact-email-count-positive-and-domain-count-zero',
      },
      client_contract: {
        verification: 'management-api-readback',
        client_type: 'public',
        token_endpoint_auth_method: 'none',
        redirect_uris: 'exact-single',
        grant_types: ['authorization_code', 'refresh_token'],
        pkce_code_challenge_method: 'S256',
        browser_client_secret: 'forbidden',
        required_aal: 'aal2-when-ADMIN_SSO_REQUIRE_AAL2=true',
      },
    },
    pages: [
      {
        name: 'supauth-admin',
        source_dir: input.adminStaticDir,
        routes: ['/admin', '/admin/*'],
        fallback: '/admin/index.html',
      },
    ],
    functions: [
      {
        name: 'supauth',
        runtime: 'bun',
        entrypoint: input.functionBundle,
        deployment_bundle: {
          entrypoint: 'index.ts',
          files: [
            { artifact: 'function_bundle', target: 'index.ts' },
            {
              artifact: 'admin_static_dir',
              target_prefix: 'admin-console/build',
              recursive: true,
              text_only: true,
            },
          ],
        },
        routes: [
          { path: '/api/*', strip_prefix: '/api' },
          { path: '/v1/*' },
          { path: '/v1/public/*' },
          { path: SUPAUTH_CUSTOM_UI_FALLBACK_ROUTE },
          { path: '/oauth/*' },
          { path: '/login' },
          { path: '/login.html' },
          { path: '/authorize.html' },
          { path: '/logout' },
          { path: '/logout.html' },
          { path: '/hosted-auth.js' },
          { path: '/account' },
          { path: '/account.html' },
          { path: '/account/*' },
          { path: '/change-password' },
          { path: '/change-password.html' },
          { path: '/claim' },
          { path: '/claim.html' },
          { path: '/favicon.ico' },
          { path: '/favicon.svg' },
          { path: '/admin/api/*', strip_prefix: '/admin/api' },
          { path: '/admin' },
          { path: '/' },
        ],
      },
    ],
    preserved_runtime_routes: [
      '/auth/v1/*',
      '/rest/v1/*',
      '/storage/v1/*',
      '/realtime/v1/*',
      '/functions/v1/*',
    ],
    migrations: HOSTED_MIGRATIONS.map((migration) => ({
      name: migration.name,
      command: 'SupaCloud Management API POST /v1/projects/{projectRef}/database/sql',
      database_env: 'SUPACLOUD_DATABASE_URL',
    })),
  };
}
