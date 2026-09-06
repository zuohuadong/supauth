import { describe, it, expect } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  HOSTED_MIGRATIONS,
  MIGRATION_SQL,
  MIGRATION_V4_SQL,
  MIGRATION_V5_SQL,
  MIGRATION_V6_SQL,
  MIGRATION_V7_SQL,
  MIGRATION_V8_SQL,
  MIGRATION_V9_SQL,
  MIGRATION_V10_SQL,
  MIGRATION_V11_SQL,
  MIGRATION_V12_SQL,
  MIGRATION_V13_SQL,
  MIGRATION_V14_SQL,
  MIGRATION_V15_SQL,
  MIGRATION_V16_SQL,
  MIGRATION_V17_SQL,
  MIGRATION_V18_SQL,
} from '../db/migrate.js';

const __dirname2 = dirname(fileURLToPath(import.meta.url));
const migrateSrc = readFileSync(join(__dirname2, '../db/migrate.ts'), 'utf-8');

describe('Migration V4 — SQL structure', () => {
  it('defines MIGRATION_V4_SQL constant', () => {
    expect(migrateSrc).toContain('MIGRATION_V4_SQL');
  });

  it('does not create a local webhook delivery table', () => {
    expect(MIGRATION_V4_SQL).not.toContain('supaoauth.webhook_deliveries');
    expect(MIGRATION_V4_SQL).not.toContain('supaoauth.webhooks');
  });

  it('creates partial unique consent index', () => {
    expect(migrateSrc).toContain('uq_user_consents_active');
    expect(migrateSrc).toContain('WHERE revoked_at IS NULL');
  });

  it('adds secret_hash column to application_secrets', () => {
    expect(migrateSrc).toContain('ALTER TABLE supaoauth.application_secrets ADD COLUMN IF NOT EXISTS secret_hash');
  });

  it('wires V4 into runMigration', () => {
    expect(HOSTED_MIGRATIONS[1]).toEqual({
      name: 'supauth-overlay-hardening-v4',
      sql: MIGRATION_V4_SQL,
    });
  });
});

describe('Migration V5 — provisioning unique constraint', () => {
  it('defines MIGRATION_V5_SQL constant', () => {
    expect(migrateSrc).toContain('MIGRATION_V5_SQL');
  });

  it('deduplicates legacy provisioning rows before creating the unique index', () => {
    // Collapsing dupes is required so CREATE UNIQUE INDEX succeeds on tables
    // that accumulated duplicate (project_ref, step) rows pre-fix.
    expect(migrateSrc).toContain('DELETE FROM supaoauth.provisioning_records');
    expect(migrateSrc).toMatch(/keep\.updated_at.*keep\.id.*p\.updated_at.*p\.id/s);
  });

  it('creates unique index on (project_ref, step)', () => {
    expect(migrateSrc).toContain('uq_provisioning_records_project_step');
    expect(migrateSrc).toContain('ON supaoauth.provisioning_records (project_ref, step)');
  });

  it('wires V5 into runMigration after V4', () => {
    expect(HOSTED_MIGRATIONS[2]).toEqual({
      name: 'supauth-overlay-provisioning-v5',
      sql: MIGRATION_V5_SQL,
    });
  });
});

describe('Hosted migration chain', () => {
  it('grants the Function role only explicit runtime overlay tables', () => {
    expect(MIGRATION_V7_SQL).toContain('GRANT USAGE ON SCHEMA supaoauth');
    expect(MIGRATION_V7_SQL).toContain("'api_resources'");
    expect(MIGRATION_V7_SQL).toContain("'account_provisioning_records'");
    expect(MIGRATION_V7_SQL).toContain("'oauth_consent_decisions'");
    expect(MIGRATION_V7_SQL).toContain("'api_version_log'");
    expect(MIGRATION_V7_SQL).toContain("'user_consents'");
    expect(MIGRATION_V7_SQL).not.toMatch(/GRANT\s+.*ON\s+ALL\s+TABLES/i);
    expect(MIGRATION_V7_SQL).not.toMatch(/GRANT\s+.*ON\s+ALL\s+SEQUENCES/i);
    expect(MIGRATION_V7_SQL).not.toMatch(/GRANT\s+.*ON\s+ALL\s+FUNCTIONS/i);
    expect(MIGRATION_V7_SQL).not.toMatch(/GRANT\s+.*\s+ON\s+(?:ALL\s+TABLES\s+IN\s+SCHEMA\s+)?auth\b/i);
  });

  it('repairs historical broad grants and blocks future default privilege expansion', () => {
    expect(MIGRATION_V7_SQL).toContain('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA supaoauth');
    expect(MIGRATION_V7_SQL).toContain('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA supaoauth');
    expect(MIGRATION_V7_SQL).toContain('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA supaoauth');
    expect(MIGRATION_V7_SQL).toContain('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON TABLES');
    expect(MIGRATION_V7_SQL).toContain('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON SEQUENCES');
    expect(MIGRATION_V7_SQL).toContain('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON FUNCTIONS');
  });

  it('keeps sensitive account claiming and append-only records explicit', () => {
    const accountGrantStart = MIGRATION_V7_SQL.indexOf('read_write_tables TEXT[]');
    const accountGrantEnd = MIGRATION_V7_SQL.indexOf('insert_only_tables TEXT[]');
    const accountGrantSql = MIGRATION_V7_SQL.slice(accountGrantStart, accountGrantEnd);
    expect(accountGrantSql).toContain("'account_provisioning_records'");
    expect(accountGrantSql).not.toContain("'api_resources'");
    expect(accountGrantSql).not.toContain('DELETE');
    expect(MIGRATION_V7_SQL).toContain('Account claiming reads the encrypted initial password');
    expect(MIGRATION_V7_SQL).toContain('GRANT INSERT ON TABLE supaoauth.%I TO %I');
    expect(MIGRATION_V7_SQL).toContain('GRANT SELECT ON TABLE supaoauth.%I TO %I');
    expect(MIGRATION_V7_SQL).toContain('GRANT SELECT, INSERT ON TABLE supaoauth.%I TO %I');
    expect(MIGRATION_V7_SQL).not.toContain("'application_secrets'");
    expect(MIGRATION_V7_SQL).not.toContain("'webhook_deliveries'");
    expect(MIGRATION_V7_SQL).not.toContain("'webhooks'");
  });

  it('ships a forward-only repair for projects that already recorded V7', () => {
    expect(MIGRATION_V16_SQL).toBe(MIGRATION_V7_SQL);
    expect(HOSTED_MIGRATIONS.find((migration) => migration.name === 'supauth-overlay-function-access-repair-v16')).toEqual({
      name: 'supauth-overlay-function-access-repair-v16',
      sql: MIGRATION_V16_SQL,
    });
    expect(migrateSrc).toContain('forward-only, idempotent copy');
  });

  it('deduplicates existing defaults before enforcing one default template', () => {
    expect(MIGRATION_V17_SQL).toContain('ROW_NUMBER() OVER');
    expect(MIGRATION_V17_SQL).toContain('rank > 1');
    expect(MIGRATION_V17_SQL).toContain('uq_organization_templates_single_default');
    expect(MIGRATION_V17_SQL).toContain('WHERE is_default = true');
  });

  it('persists organization template instantiation idempotency state', () => {
    expect(MIGRATION_V18_SQL).toContain('organization_template_instantiations');
    expect(MIGRATION_V18_SQL).toContain('uq_org_template_instantiations_idempotency_key');
    expect(MIGRATION_V18_SQL).toContain('request_hash');
    expect(MIGRATION_V18_SQL).toContain('recovery_required');
  });

  it('retires empty legacy webhook tables and blocks non-empty tables without CASCADE', () => {
    expect(MIGRATION_V9_SQL).toContain("REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhook_deliveries FROM PUBLIC");
    expect(MIGRATION_V9_SQL).toContain("REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhooks FROM PUBLIC");
    expect(MIGRATION_V9_SQL).not.toContain('RAISE EXCEPTION');
    expect(MIGRATION_V10_SQL).toContain('reason_code=legacy_webhook_data_present');
    expect(MIGRATION_V10_SQL).toContain('HINT =');
    expect(MIGRATION_V10_SQL).toContain('DROP TABLE IF EXISTS supaoauth.webhook_deliveries;');
    expect(MIGRATION_V10_SQL).toContain('DROP TABLE IF EXISTS supaoauth.webhooks;');
    expect(MIGRATION_V10_SQL.indexOf('DROP TABLE IF EXISTS supaoauth.webhook_deliveries;'))
      .toBeLessThan(MIGRATION_V10_SQL.indexOf('DROP TABLE IF EXISTS supaoauth.webhooks;'));
    expect(MIGRATION_V10_SQL).not.toMatch(/DROP TABLE[^;]+CASCADE/i);
  });

  it('keeps every forward-only migration in deterministic version order', () => {
    expect(HOSTED_MIGRATIONS).toEqual([
      { name: 'supauth-overlay-schema-v1', sql: MIGRATION_SQL },
      { name: 'supauth-overlay-hardening-v4', sql: MIGRATION_V4_SQL },
      { name: 'supauth-overlay-provisioning-v5', sql: MIGRATION_V5_SQL },
      { name: 'supauth-overlay-gotrue-authority-v6', sql: MIGRATION_V6_SQL },
      { name: 'supauth-overlay-function-access-v7', sql: MIGRATION_V7_SQL },
      { name: 'supauth-overlay-project-claims-v8', sql: MIGRATION_V8_SQL },
      { name: 'supauth-overlay-legacy-webhook-revoke-v9', sql: MIGRATION_V9_SQL },
      { name: 'supauth-overlay-legacy-webhook-retirement-v10', sql: MIGRATION_V10_SQL },
      { name: 'supauth-overlay-application-permissions-v11', sql: MIGRATION_V11_SQL },
      { name: 'supauth-overlay-account-claim-state-v12', sql: MIGRATION_V12_SQL },
      { name: 'supauth-overlay-rls-permission-projection-v13', sql: MIGRATION_V13_SQL },
      { name: 'supauth-overlay-connector-runtime-kind-v14', sql: MIGRATION_V14_SQL },
      { name: 'supauth-overlay-connector-runtime-kind-repair-v15', sql: MIGRATION_V15_SQL },
      { name: 'supauth-overlay-function-access-repair-v16', sql: MIGRATION_V16_SQL },
      { name: 'supauth-overlay-organization-template-default-v17', sql: MIGRATION_V17_SQL },
      { name: 'supauth-overlay-organization-template-idempotency-v18', sql: MIGRATION_V18_SQL },
    ]);
    expect(migrateSrc).toContain('for (const migration of HOSTED_MIGRATIONS)');
    expect(migrateSrc).toContain('await sql.unsafe(migration.sql)');
  });

  it('adds an immutable connector runtime-kind backfill and typed enterprise factory seeds', () => {
    expect(MIGRATION_V14_SQL).toContain('ADD COLUMN IF NOT EXISTS runtime_kind');
    expect(MIGRATION_V14_SQL).toContain("provider_id = 'oidc-enterprise' THEN 'custom_oidc'");
    expect(MIGRATION_V14_SQL).toContain("provider_id = 'saml-enterprise' THEN 'saml'");
    expect(MIGRATION_V14_SQL).toContain("CHECK (runtime_kind IN ('builtin_oauth', 'custom_oidc', 'saml'))");
    expect(MIGRATION_V14_SQL).toContain('"identifier","name","client_id","client_secret","issuer"');
    expect(MIGRATION_V14_SQL).toContain('"required":["name"]');
    expect(MIGRATION_V14_SQL).toContain('"one_of":[["metadata_url","metadata_xml"]]');
  });

  it('repairs legacy factory placeholders without rewriting the v14 migration', () => {
    expect(MIGRATION_V15_SQL).toContain("SET runtime_kind = 'builtin_oauth'");
    expect(MIGRATION_V15_SQL).toContain("provider_id IN ('oidc-enterprise', 'saml-enterprise')");
    expect(MIGRATION_V15_SQL).toContain("runtime_kind IN ('custom_oidc', 'saml')");
  });

  it('adds forward-only account claim proof and state columns without changing prior migrations', () => {
    expect(MIGRATION_V12_SQL).toContain('ALTER TABLE supaoauth.account_provisioning_records');
    expect(MIGRATION_V12_SQL).toContain('claim_proof_hash');
    expect(MIGRATION_V12_SQL).toContain('claim_state');
    expect(MIGRATION_V12_SQL).toContain('claim_operation_id');
    expect(MIGRATION_V12_SQL).toContain('claim_lease_expires_at');
    expect(MIGRATION_V12_SQL).toContain('claim_password_hash');
    expect(MIGRATION_V12_SQL).toContain("initial_password_claimed THEN 'claimed'");
    expect(MIGRATION_V12_SQL).toContain('claim_state IN');
    expect(MIGRATION_V12_SQL).toContain('password_update_unknown');
    expect(MIGRATION_SQL).not.toContain('claim_proof_hash');
    expect(MIGRATION_V11_SQL).not.toContain('claim_proof_hash');
  });

  it('grants only authenticated callers direct access to their own permission projection', () => {
    expect(MIGRATION_V13_SQL).toContain(
      'REVOKE ALL ON FUNCTION supaoauth.current_permission_claims(UUID) FROM PUBLIC, anon',
    );
    expect(MIGRATION_V13_SQL).toContain(
      'GRANT EXECUTE ON FUNCTION supaoauth.current_permission_claims(UUID) TO authenticated',
    );
    expect(MIGRATION_V13_SQL).toContain(
      "ALTER FUNCTION supaoauth.current_permission_claims(UUID) SET search_path = ''",
    );
  });

  it('reads only the current schema-v2 project projection and rejects legacy roots', () => {
    expect(MIGRATION_V8_SQL).toContain("current_database() ~ '^supa_.+$'");
    expect(MIGRATION_V8_SQL).toContain("namespace ->> 'schema_version' = '2'");
    expect(MIGRATION_V8_SQL).toContain("namespace -> 'projects' -> project_ref");
    expect(MIGRATION_V8_SQL).toContain("project_ref -> 'projection_unavailable'");
    expect(MIGRATION_V8_SQL).not.toContain("namespace -> 'permissions'");
    expect(MIGRATION_V8_SQL).toContain('supaoauth.current_project_claims()');
    expect(MIGRATION_V8_SQL).toContain('GRANT EXECUTE ON FUNCTION supaoauth.current_project_claims() TO authenticated');
  });

  it('selects schema-v2 permissions across project, application, and organization contexts', () => {
    expect(MIGRATION_V11_SQL).toContain('supaoauth.current_project_claims()');
    expect(MIGRATION_V11_SQL).toContain("auth.jwt() ->> 'client_id'");
    expect(MIGRATION_V11_SQL).toContain("project_claims -> 'applications' -> trusted_application_id");
    expect(MIGRATION_V11_SQL).toContain("permission_claims -> 'organizations' -> target_organization_id::text");
    expect(MIGRATION_V11_SQL).toContain("project_claims ->> 'application_id' = trusted_application_id");
  });

  it('inherits selected root permissions when an organization projection is absent', () => {
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

  it('fails closed for missing, unavailable, or truncated permission projections', () => {
    expect(MIGRATION_V11_SQL).toContain("ELSE '{}'::jsonb");
    expect(MIGRATION_V11_SQL).toContain("project_claims -> 'projection_unavailable'");
    expect(MIGRATION_V11_SQL).toContain("application_claims -> 'permissions_truncated'");
    expect(MIGRATION_V11_SQL).toContain("permission_claims -> 'permissions_truncated'");
    expect(MIGRATION_V11_SQL).toContain('supaoauth.current_permission_claims(target_organization_id)');
  });

  it('binds explicit application checks to the token or narrowed project application', () => {
    expect(MIGRATION_V11_SQL).toContain(
      "COALESCE(token_application_id, NULLIF(project_claims ->> 'application_id', '')) = client_id",
    );
    expect(MIGRATION_V11_SQL).toContain('supaoauth.authorize(permission_name, organization_id)');
  });
});
