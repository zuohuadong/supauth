import { describe, expect, it } from 'bun:test';
import { existsSync, readFileSync } from 'node:fs';
import {
  createSupacloudAppManifest,
  GOTRUE_OWNED_RUNTIME_DOMAINS,
  SUPACLOUD_MANAGEMENT_FACADES,
  SUPACLOUD_OWNED_MANAGEMENT_DOMAINS,
  SUPAOAUTH_TABLE_OWNERSHIP,
} from '../scripts/supacloud-app-contract.js';
import {
  HOSTED_MIGRATIONS,
  MIGRATION_SQL,
  MIGRATION_V11_SQL,
} from '../packages/auth-server/src/db/migrate.js';

describe('SupAuth SupaCloud app contract', () => {
  it('declares SupaCloud Functions as the only HTTP runtime', () => {
    const manifest = createSupacloudAppManifest({
      functionBundle: 'packages/auth-server/dist/supacloud-function/supacloud-function.js',
      adminStaticDir: 'packages/admin-console/build',
      openapiPath: 'artifacts/supacloud-app/openapi.json',
    });

    expect(manifest.http_runtime).toBe('supacloud-functions-only');
    expect(manifest.source_of_truth).toBe('supacloud-management-api');
    expect(manifest.runtime_mode).toBe('gotrue');
    expect(manifest.authority).toEqual({
      auth_runtime: 'gotrue',
      control_plane: 'supacloud-management-api',
      overlay: 'supaoauth-schema',
    });
    expect(manifest.forbidden_runtime_forms).toEqual(expect.arrayContaining([
      'standalone-http-server',
      'systemd-service',
      'pm2-process',
      'webhook-worker-process',
      'cron-process-owned-by-supauth',
    ]));
    expect(manifest.functions).toHaveLength(1);
    expect(manifest.functions[0].entrypoint).toBe('packages/auth-server/dist/supacloud-function/supacloud-function.js');
    expect(manifest.required_supacloud_env).toContainEqual(expect.objectContaining({
      name: 'SUPAOAUTH_BFF_SIGNING_SECRET',
      secret: true,
    }));
    expect(manifest.required_supacloud_env).toContainEqual(expect.objectContaining({
      name: 'SUPABASE_SERVICE_ROLE_KEY',
      secret: true,
    }));
  });

  it('declares the Admin SSO install and multi-file Function bundle contract', () => {
    const manifest = createSupacloudAppManifest({
      functionBundle: 'function.js',
      adminStaticDir: 'admin',
      openapiPath: 'openapi.json',
    });
    const envByName = Object.fromEntries(manifest.required_supacloud_env.map((entry) => [entry.name, entry]));

    expect(envByName.ADMIN_SSO_ISSUER).toMatchObject({ secret: false });
    expect(envByName.ADMIN_SSO_ISSUER.optional).not.toBe(true);
    expect(envByName.ADMIN_SSO_CLIENT_ID).toMatchObject({ secret: false });
    expect(envByName.ADMIN_SSO_CLIENT_ID.optional).not.toBe(true);
    for (const name of [
      'ADMIN_SSO_JWKS_URI',
      'ADMIN_SSO_AUDIENCE',
      'ADMIN_SSO_REDIRECT_URI',
      'ADMIN_SSO_POST_LOGOUT_REDIRECT_URI',
      'ADMIN_SSO_REQUIRE_AAL2',
    ]) {
      expect(envByName[name]).toMatchObject({ secret: false, optional: true });
    }
    for (const name of ['ADMIN_SSO_ALLOWED_EMAILS', 'ADMIN_SSO_ALLOWED_DOMAINS']) {
      expect(envByName[name]).toMatchObject({ secret: true, optional: true });
    }
    expect(manifest.admin_sso.allowlist).toEqual({
      database_table: 'supaoauth.security_config',
      database_fields: ['admin_allowed_emails', 'admin_allowed_domains'],
      optional_secret_env: ['ADMIN_SSO_ALLOWED_EMAILS', 'ADMIN_SSO_ALLOWED_DOMAINS'],
      install_rule: 'exact-email-count-positive-and-domain-count-zero',
    });
    expect(manifest.admin_sso.client_contract).toEqual({
      verification: 'management-api-readback',
      client_type: 'public',
      token_endpoint_auth_method: 'none',
      redirect_uris: 'exact-single',
      grant_types: ['authorization_code', 'refresh_token'],
      pkce_code_challenge_method: 'S256',
      browser_client_secret: 'forbidden',
      required_aal: 'aal2-when-ADMIN_SSO_REQUIRE_AAL2=true',
    });
    expect(manifest.functions[0].deployment_bundle).toEqual({
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
    });
    expect(manifest.pages.find((page) => page.name === 'supauth-admin')?.routes).toEqual([
      '/admin',
      '/admin/*',
    ]);
    expect(manifest.functions[0].routes).toContainEqual({ path: '/admin' });
    expect(manifest.functions[0].routes).toContainEqual({ path: '/custom-ui/*' });
  });

  it('builds a project-generic console behind the same-origin BFF', () => {
    const buildScript = readFileSync('scripts/build-supacloud-app.ts', 'utf8');

    expect(buildScript).toContain("VITE_AUTH_SERVER_URL: '/api'");
    expect(buildScript).toContain("VITE_ADMIN_SSO_ISSUER: ''");
    expect(buildScript).toContain("VITE_ADMIN_SSO_CLIENT_ID: ''");
    expect(buildScript).toContain("resolve(artifactDir, 'function-bundle')");
    expect(buildScript).toContain("resolve(deploymentBundleDir, 'index.ts')");
    expect(buildScript).toContain("resolve(deploymentBundleDir, 'admin-console/build')");
  });

  it('builds file-type 22 through an Edge-safe root-entry transform', () => {
    const buildScript = readFileSync('scripts/build-supauth-function.ts', 'utf8');

    expect(buildScript).toContain("resolveRuntimeSafeEntry('file-type')");
    expect(buildScript).not.toContain("resolveRuntimeSafeEntry('file-type', 'core')");
    expect(buildScript).toContain('Edge Runtime 不支持 file-type 的文件系统入口');
  });

  it('declares SupaCloud-owned management domains and managed jobs', () => {
    const manifest = createSupacloudAppManifest({
      functionBundle: 'function.js',
      adminStaticDir: 'admin',
      openapiPath: 'openapi.json',
    });

    expect(manifest.supacloud_owned_management_domains).toEqual(expect.arrayContaining([
      'applications',
      'organizations',
      'rbac_roles',
      'audit',
      'webhooks',
      'webhook_delivery',
    ]));
    for (const runtimeDomain of [
      'application_secrets',
      'oauth_clients',
      'oauth_grants',
      'users',
      'user_sessions',
      'user_identities',
      'user_mfa',
      'user_passkeys',
    ]) {
      expect(manifest.supacloud_owned_management_domains).not.toContain(runtimeDomain);
    }
    expect(manifest.gotrue_owned_runtime_domains).toEqual(GOTRUE_OWNED_RUNTIME_DOMAINS);
    expect(manifest.supacloud_management_facades).toEqual(SUPACLOUD_MANAGEMENT_FACADES);
    expect(SUPACLOUD_OWNED_MANAGEMENT_DOMAINS).not.toContain('user_passkeys');
    expect(manifest.supacloud_managed_background_jobs.map((job) => job.name)).toEqual([
      'webhook-delivery',
      'account-provisioning-import',
    ]);
    expect(manifest.supauth_overlay_domains).toEqual(expect.arrayContaining([
      'hosted_auth_pages',
      'sign_in_experience_overrides',
      'oauth_consent_policy',
      'oauth_consent_decisions',
      'account_provisioning_records',
    ]));
  });

  it('classifies every supaoauth schema table owner', () => {
    const schema = readFileSync('packages/auth-server/src/db/schema.ts', 'utf8');
    const tables = [...schema.matchAll(/supaoauth\.table\('([^']+)'/g)].map((match) => match[1]).sort();
    const classified = Object.keys(SUPAOAUTH_TABLE_OWNERSHIP).sort();

    expect(classified).toEqual(tables);
    expect(SUPAOAUTH_TABLE_OWNERSHIP).not.toHaveProperty('webhooks');
    expect(SUPAOAUTH_TABLE_OWNERSHIP).not.toHaveProperty('webhook_deliveries');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.application_secrets.class).toBe('legacy-temporary');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.application_secrets.replacement).toBe('gotrue:oauth-client-secret-rotation');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.user_consents.class).toBe('legacy-temporary');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.user_consents.replacement).toBe('gotrue-oauth-grants');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.oauth_consent_decisions.class).toBe('supauth-overlay');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.sign_in_experience.class).toBe('supauth-overlay');
    expect(SUPAOAUTH_TABLE_OWNERSHIP.account_provisioning_records.class).toBe('supauth-overlay');
  });

  it('new project migration creates only overlay tables, not legacy source-of-truth tables', () => {
    const legacyTables = Object.entries(SUPAOAUTH_TABLE_OWNERSHIP)
      .filter(([, ownership]) => ownership.class === 'legacy-temporary')
      .map(([table]) => table);
    const overlayTables = Object.entries(SUPAOAUTH_TABLE_OWNERSHIP)
      .filter(([, ownership]) => ownership.class === 'supauth-overlay')
      .map(([table]) => table);

    for (const table of legacyTables) {
      expect(MIGRATION_SQL).not.toContain(`CREATE TABLE IF NOT EXISTS supaoauth.${table}`);
    }
    for (const table of overlayTables) {
      expect(MIGRATION_SQL).toContain(`CREATE TABLE IF NOT EXISTS supaoauth.${table}`);
    }
    expect(MIGRATION_SQL).toContain("auth.jwt() -> 'app_metadata' -> 'supaoauth'");
    expect(MIGRATION_SQL).not.toContain('JOIN supaoauth.permissions');
    expect(MIGRATION_SQL).not.toContain('FROM supaoauth.role_assignments');
    expect(MIGRATION_SQL).not.toContain('mfa_required');
    expect(MIGRATION_SQL).not.toContain('personal_access_tokens');
    expect(MIGRATION_SQL).not.toContain('inline_hook');
    expect(MIGRATION_SQL).not.toContain('recovery_code');
    expect(MIGRATION_SQL).not.toContain('subject_token');
  });

  it('publishes every hosted overlay migration in deterministic order', () => {
    const manifest = createSupacloudAppManifest({
      functionBundle: 'function.js',
      adminStaticDir: 'admin',
      openapiPath: 'openapi.json',
    });

    expect(HOSTED_MIGRATIONS.map((migration) => migration.name)).toEqual([
      'supauth-overlay-schema-v1',
      'supauth-overlay-hardening-v4',
      'supauth-overlay-provisioning-v5',
      'supauth-overlay-gotrue-authority-v6',
      'supauth-overlay-function-access-v7',
      'supauth-overlay-project-claims-v8',
      'supauth-overlay-legacy-webhook-revoke-v9',
      'supauth-overlay-legacy-webhook-retirement-v10',
      'supauth-overlay-application-permissions-v11',
      'supauth-overlay-account-claim-state-v12',
      'supauth-overlay-rls-permission-projection-v13',
      'supauth-overlay-connector-runtime-kind-v14',
      'supauth-overlay-connector-runtime-kind-repair-v15',
    ]);
    expect(manifest.migrations.map((migration) => migration.name)).toEqual(
      HOSTED_MIGRATIONS.map((migration) => migration.name),
    );
  });

  it('keeps hosted migrations out of GoTrue-owned OAuth authorization tables', () => {
    const hostedSql = HOSTED_MIGRATIONS.map((migration) => migration.sql).join('\n');
    expect(hostedSql).not.toContain('auth.oauth_authorizations');
    expect(hostedSql).not.toContain('GRANT USAGE ON SCHEMA auth');
  });

  it('creates project-scoped RBAC helpers without replacing auth.uid/auth.jwt patterns', () => {
    const hostedSql = HOSTED_MIGRATIONS.map((migration) => migration.sql).join('\n');
    expect(hostedSql).toContain('CREATE OR REPLACE FUNCTION supaoauth.current_project_claims()');
    expect(hostedSql).toContain('CREATE OR REPLACE FUNCTION supaoauth.authorize(permission_name TEXT, target_organization_id UUID DEFAULT NULL)');
    expect(hostedSql).toContain('CREATE OR REPLACE FUNCTION supaoauth.has_permission(permission_name TEXT, target_organization_id UUID DEFAULT NULL)');
    expect(hostedSql).toContain('SELECT supaoauth.authorize(permission_name, target_organization_id)');
    expect(hostedSql).toContain('CREATE OR REPLACE FUNCTION supaoauth.has_org_permission(organization_id UUID, permission_name TEXT)');
    expect(hostedSql).toContain('GRANT EXECUTE ON FUNCTION supaoauth.has_permission(TEXT, UUID) TO authenticated');
    expect(hostedSql).toContain("namespace -> 'projects' -> project_ref");
    expect(hostedSql).not.toContain("auth.jwt() ->> 'role' = 'admin'");
  });

  it('keeps RLS helpers fail-closed when JWT permission projection is truncated', () => {
    const helperSql = MIGRATION_V11_SQL.slice(
      MIGRATION_V11_SQL.indexOf('CREATE OR REPLACE FUNCTION supaoauth.current_permission_claims'),
      MIGRATION_V11_SQL.indexOf('REVOKE ALL ON FUNCTION supaoauth.current_permission_claims'),
    );

    expect(helperSql).toContain("project_claims -> 'projection_unavailable'");
    expect(helperSql).toContain("application_claims -> 'permissions_truncated'");
    expect(helperSql).toContain("permission_claims -> 'permissions_truncated'");
    expect(helperSql.match(/permissions_truncated/g) || []).toHaveLength(2);
  });

  it('preserves root permission inheritance when a target organization has no nested projection', () => {
    const organizationScopeStart = MIGRATION_V11_SQL.indexOf('), organization_scoped AS (');
    const organizationScopeSql = MIGRATION_V11_SQL.slice(
      organizationScopeStart,
      MIGRATION_V11_SQL.indexOf('  SELECT CASE', organizationScopeStart),
    );

    expect(organizationScopeSql).toContain(
      "THEN permission_claims -> 'organizations' -> target_organization_id::text",
    );
    expect(organizationScopeSql).toContain('ELSE permission_claims');
    expect(organizationScopeSql).not.toContain("ELSE '{}'::jsonb");
  });

  it('verifies RBAC helper grants without turning missing helper signatures into DB reachability failures', () => {
    const verifier = readFileSync('packages/auth-server/src/compatibility/rbac-verify.ts', 'utf8');

    expect(verifier).toContain("to_regprocedure('supaoauth.authorize(text, uuid)')");
    expect(verifier).toContain("to_regprocedure('supaoauth.has_permission(text, uuid)')");
    expect(verifier).toContain("to_regprocedure('supaoauth.has_org_permission(uuid, text)')");
    expect(verifier).toContain("to_regprocedure('supaoauth.current_project_claims()')");
    expect(verifier).toContain("to_regprocedure('supaoauth.current_permission_claims(uuid)')");
    expect(verifier).toContain("to_regclass('supaoauth.webhooks') IS NULL");
    expect(verifier).toContain("to_regclass('supaoauth.webhook_deliveries') IS NULL");
    expect(verifier).toContain('WHEN authorize_oid IS NULL THEN NULL');
    expect(verifier).toContain('WHEN has_permission_oid IS NULL THEN NULL');
    expect(verifier).toContain('WHEN has_org_permission_oid IS NULL THEN NULL');
    expect(verifier).toContain('WHEN current_project_claims_oid IS NULL THEN NULL');
    expect(verifier).toContain('WHEN current_permission_claims_oid IS NULL THEN NULL');
    expect(verifier).toContain("aclexplode(COALESCE(pg_proc.proacl, acldefault('f', pg_proc.proowner)))");
    expect(verifier).toContain('function_acl.grantee = 0');
    expect(verifier).toContain("NOT has_function_privilege('anon', pg_proc.oid, 'EXECUTE')");
    expect(verifier).toContain('pg_proc.prosecdef AS security_definer');
    expect(verifier).toContain("function_setting ~ '^search_path=(\"\"|)$'");
    expect(verifier).not.toContain("has_function_privilege('authenticated', 'supaoauth.authorize(TEXT, UUID)'");
    expect(verifier).not.toContain("has_function_privilege('authenticated', 'supaoauth.has_permission(TEXT, UUID)'");
    expect(verifier).not.toContain("has_function_privilege('authenticated', 'supaoauth.has_org_permission(UUID, TEXT)'");
  });

  it('legacy management repositories are SupaCloud facades, not local source-of-truth writes', () => {
    const repositoryContracts = [
      {
        file: 'packages/auth-server/src/repositories/roles.ts',
        forbidden: ["from '../db/index.js'", "from '../db/schema.js'"],
      },
      {
        file: 'packages/auth-server/src/repositories/organizations.ts',
        forbidden: ["from '../db/index.js'", "from '../db/schema.js'"],
      },
      {
        file: 'packages/auth-server/src/repositories/organization-control.ts',
        forbidden: ["from '../db/index.js'", "from '../db/schema.js'", 'randomBytes', 'createHash'],
      },
      {
        file: 'packages/auth-server/src/repositories/rbac-bridge.ts',
        forbidden: ["from '../db/index.js'", "from '../db/schema.js'", 'roleAssignments'],
      },
    ];

    for (const contract of repositoryContracts) {
      const source = readFileSync(contract.file, 'utf8');
      expect(source).toContain('getSupaCloudAdapter');
      for (const token of contract.forbidden) {
        expect(source).not.toContain(token);
      }
    }

    expect(existsSync('packages/auth-server/src/repositories/account-control.ts')).toBe(false);
    expect(existsSync('packages/auth-server/src/repositories/webhooks.ts')).toBe(false);
  });

  it('legacy route verifier delegates to installed SupaCloud app verification', () => {
    const verifierSource = readFileSync('scripts/kong-verify.ts', 'utf8');

    expect(verifierSource).toContain('verifySupacloudInstalledApp');
    expect(verifierSource).toContain('SUPAUTH_INSTALLED_BASE_URL');
    expect(verifierSource).not.toContain('Host routing');
    expect(verifierSource).not.toContain("headers['Host']");
    expect(verifierSource).not.toContain('localhost:8000');
  });
});
