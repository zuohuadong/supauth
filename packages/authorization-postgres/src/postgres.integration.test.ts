/**
 * 真实 PostgreSQL/RLS 集成门禁。
 * 仅在 RUN_AUTHORIZATION_POSTGRES_TESTS=1 时运行，并要求
 * AUTHORIZATION_POSTGRES_URL 指向 loopback 上以 authorization_test 结尾的专用数据库。
 */

import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test';
import postgres from 'postgres';
import { checkAuthorizationExplain } from '../../authorization-conformance/src/index.js';
import {
  generateAuthorizationProjectionPreflightSql,
  generateAuthorizationSchemaSql,
  generateRlsPoliciesSql,
} from './index.js';

const DATABASE_URL = process.env.AUTHORIZATION_POSTGRES_URL || '';
const AUTHORIZATION_SCHEMA = 'authorization_test_rbac';
const STRICT_AUTHORIZATION_SCHEMA = 'authorization_test_rbac_strict';
const SOURCE_SCHEMA = 'authorization_test_source';
const DATA_SCHEMA = 'authorization_test_data';
const STRICT_DATA_SCHEMA = 'authorization_test_data_strict';
const ISSUER = 'https://tenant.example.test/auth/v1';
const APPLICATION_ID = 'xigu-fa';

function isDisposableDatabaseUrl(databaseUrl: string): boolean {
  try {
    const parsed = new URL(databaseUrl);
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
    return ['postgres:', 'postgresql:'].includes(parsed.protocol)
      && loopback
      && decodeURIComponent(parsed.pathname.slice(1)).endsWith('authorization_test');
  } catch {
    return false;
  }
}

const postgresGateRequested = process.env.RUN_AUTHORIZATION_POSTGRES_TESTS === '1';
if (postgresGateRequested && !isDisposableDatabaseUrl(DATABASE_URL)) {
  throw new Error(
    'Authorization PostgreSQL tests require AUTHORIZATION_POSTGRES_URL to use a loopback disposable *authorization_test database',
  );
}
const describePostgres = postgresGateRequested ? describe : describe.skip;

let sql: ReturnType<typeof postgres>;

const nativeClaims = {
  iss: ISSUER,
  sub: 'user-1',
  role: 'authenticated',
};

async function seedAuthorizationState(): Promise<void> {
  await sql.unsafe(`
    TRUNCATE ${SOURCE_SCHEMA}.memberships, ${SOURCE_SCHEMA}.role_assignments,
      ${DATA_SCHEMA}.invoices, ${STRICT_DATA_SCHEMA}.invoices;

    INSERT INTO ${SOURCE_SCHEMA}.memberships (
      membership_key,
      principal_kind,
      principal_issuer,
      principal_subject,
      application_id,
      domain_type,
      domain_id,
      active
    ) VALUES
      ('membership-native', 'user', '${ISSUER}', 'user-1', '${APPLICATION_ID}', 'organization', 'org-a', TRUE),
      ('membership-cross-application', 'user', '${ISSUER}', 'user-1', 'other-application', 'organization', 'org-b', TRUE),
      ('membership-cross-issuer', 'user', 'https://other.example.test/auth/v1', 'user-1', '${APPLICATION_ID}', 'organization', 'org-c', TRUE),
      ('membership-cross-domain', 'user', '${ISSUER}', 'user-1', '${APPLICATION_ID}', 'project', 'org-b', TRUE),
      ('membership-service', 'service', '${ISSUER}', 'service-worker', '${APPLICATION_ID}', 'organization', 'org-a', TRUE),
      ('membership-empty-service', 'service', '${ISSUER}', '', '${APPLICATION_ID}', 'organization', 'org-b', TRUE),
      ('membership-whitespace-service', 'service', '${ISSUER}', ' ', '${APPLICATION_ID}', 'organization', 'org-c', TRUE);

    INSERT INTO ${SOURCE_SCHEMA}.role_assignments (membership_key, role_key, active)
    SELECT membership_key, 'invoice-operator', TRUE
    FROM ${SOURCE_SCHEMA}.memberships;

    INSERT INTO ${DATA_SCHEMA}.invoices (id, organization_id) VALUES
      ('invoice-a', 'org-a'),
      ('invoice-b', 'org-b'),
      ('invoice-c', 'org-c');
    INSERT INTO ${STRICT_DATA_SCHEMA}.invoices (id, organization_id) VALUES
      ('invoice-a', 'org-a'),
      ('invoice-b', 'org-b'),
      ('invoice-c', 'org-c');
  `);
}

async function withClaims<T>(
  claims: Record<string, unknown>,
  execute: (transaction: postgres.TransactionSql) => Promise<T>,
) {
  return sql.begin(async transaction => {
    await transaction.unsafe('SET LOCAL ROLE authenticated');
    await transaction`SELECT set_config('request.jwt.claims', ${JSON.stringify(claims)}, TRUE)`;
    return execute(transaction);
  });
}

async function visibleInvoiceIds(claims: Record<string, unknown>): Promise<string[]> {
  return withClaims(claims, async transaction => {
    const rows = await transaction<{ id: string }[]>`
      SELECT id
      FROM authorization_test_data.invoices
      ORDER BY id
    `;
    return rows.map(row => row.id);
  });
}

async function visibleStrictInvoiceIds(claims: Record<string, unknown>): Promise<string[]> {
  return withClaims(claims, async transaction => {
    const rows = await transaction<{ id: string }[]>`
      SELECT id
      FROM authorization_test_data_strict.invoices
      ORDER BY id
    `;
    return rows.map(row => row.id);
  });
}

async function invoiceExplainPlan(claims: Record<string, unknown>): Promise<unknown> {
  return withClaims(claims, async transaction => {
    const rows = await transaction.unsafe<Record<string, unknown>[]>(`
      EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
      SELECT id FROM authorization_test_data.invoices ORDER BY id
    `);
    return rows[0]?.['QUERY PLAN'];
  });
}

async function projectionViolationRules(schema: string): Promise<string[]> {
  const rows = await sql.unsafe<Array<{ rule: string }>>(generateAuthorizationProjectionPreflightSql({ schema }));
  return rows.map(row => row.rule);
}

describePostgres('@supauth/authorization-postgres real RLS', () => {
  beforeAll(async () => {
    sql = postgres(DATABASE_URL, { max: 4, onnotice: () => {} });
    await sql.unsafe(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
          CREATE ROLE anon NOLOGIN NOBYPASSRLS;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
          CREATE ROLE authenticated NOLOGIN NOBYPASSRLS;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated' AND rolbypassrls) THEN
          RAISE EXCEPTION 'authenticated role must not bypass RLS';
        END IF;
      END $$;

      DROP SCHEMA IF EXISTS ${AUTHORIZATION_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${STRICT_AUTHORIZATION_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${SOURCE_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${DATA_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${STRICT_DATA_SCHEMA} CASCADE;

      CREATE SCHEMA IF NOT EXISTS auth;
      CREATE OR REPLACE FUNCTION auth.jwt()
      RETURNS JSONB
      LANGUAGE sql
      STABLE
      SET search_path = ''
      AS $$
        SELECT COALESCE(NULLIF(current_setting('request.jwt.claims', TRUE), ''), '{}')::JSONB
      $$;

      CREATE SCHEMA ${AUTHORIZATION_SCHEMA};
      CREATE SCHEMA ${STRICT_AUTHORIZATION_SCHEMA};
      CREATE SCHEMA ${SOURCE_SCHEMA};
      CREATE SCHEMA ${DATA_SCHEMA};
      CREATE SCHEMA ${STRICT_DATA_SCHEMA};

      CREATE TABLE ${SOURCE_SCHEMA}.memberships (
        membership_key TEXT PRIMARY KEY,
        principal_kind TEXT NOT NULL,
        principal_issuer TEXT NOT NULL,
        principal_subject TEXT NOT NULL,
        application_id TEXT NOT NULL,
        domain_type TEXT NOT NULL,
        domain_id TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE
      );
      CREATE TABLE ${SOURCE_SCHEMA}.role_assignments (
        membership_key TEXT NOT NULL REFERENCES ${SOURCE_SCHEMA}.memberships(membership_key) ON DELETE CASCADE,
        role_key TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        PRIMARY KEY (membership_key, role_key)
      );
      CREATE TABLE ${SOURCE_SCHEMA}.role_permissions (
        role_key TEXT NOT NULL,
        permission_name TEXT NOT NULL,
        PRIMARY KEY (role_key, permission_name)
      );
      CREATE VIEW ${AUTHORIZATION_SCHEMA}.effective_permission_grants AS
        WITH unambiguous_memberships AS (
          SELECT membership.*
          FROM ${SOURCE_SCHEMA}.memberships AS membership
          WHERE membership.active
            AND NOT EXISTS (
              SELECT 1
              FROM ${SOURCE_SCHEMA}.memberships AS duplicate
              WHERE duplicate.active
                AND duplicate.membership_key <> membership.membership_key
                AND duplicate.principal_kind = membership.principal_kind
                AND duplicate.principal_issuer = membership.principal_issuer
                AND duplicate.principal_subject = membership.principal_subject
                AND duplicate.application_id = membership.application_id
                AND duplicate.domain_type = membership.domain_type
                AND duplicate.domain_id = membership.domain_id
            )
        )
        SELECT
          membership.principal_kind,
          membership.principal_issuer,
          membership.principal_subject,
          membership.application_id,
          membership.domain_type,
          membership.domain_id,
          role_permission.permission_name
        FROM unambiguous_memberships AS membership
        JOIN ${SOURCE_SCHEMA}.role_assignments AS assignment
          ON assignment.membership_key = membership.membership_key
        JOIN ${SOURCE_SCHEMA}.role_permissions AS role_permission
          ON role_permission.role_key = assignment.role_key
        WHERE assignment.active;

      CREATE VIEW ${STRICT_AUTHORIZATION_SCHEMA}.effective_permission_grants AS
        SELECT * FROM ${AUTHORIZATION_SCHEMA}.effective_permission_grants;

      INSERT INTO ${SOURCE_SCHEMA}.role_permissions (role_key, permission_name) VALUES
        ('invoice-operator', 'invoice:read'),
        ('invoice-operator', 'invoice:create'),
        ('invoice-operator', 'invoice:update'),
        ('invoice-operator', 'invoice:delete');

      CREATE TABLE ${DATA_SCHEMA}.invoices (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL
      );
      CREATE TABLE ${STRICT_DATA_SCHEMA}.invoices (
        id TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL
      );
      GRANT USAGE ON SCHEMA ${DATA_SCHEMA} TO authenticated;
      GRANT USAGE ON SCHEMA ${STRICT_DATA_SCHEMA} TO authenticated;
      GRANT SELECT, INSERT, UPDATE, DELETE ON ${DATA_SCHEMA}.invoices TO authenticated;
      GRANT SELECT ON ${STRICT_DATA_SCHEMA}.invoices TO authenticated;
    `);

    await expect(projectionViolationRules(AUTHORIZATION_SCHEMA)).resolves.toEqual([]);
    await expect(projectionViolationRules(STRICT_AUTHORIZATION_SCHEMA)).resolves.toEqual([]);
    await sql.unsafe(generateAuthorizationSchemaSql({
      schema: AUTHORIZATION_SCHEMA,
      applicationId: APPLICATION_ID,
    }));
    await sql.unsafe(generateRlsPoliciesSql({
      schema: AUTHORIZATION_SCHEMA,
      tableSchema: DATA_SCHEMA,
      table: 'invoices',
      domainColumn: 'organization_id',
      domainIdType: 'text',
      domainType: 'organization',
      policies: [
        { command: 'select', usingPermission: 'invoice:read' },
        { command: 'insert', checkPermission: 'invoice:create' },
        { command: 'update', usingPermission: 'invoice:read', checkPermission: 'invoice:update' },
        { command: 'delete', usingPermission: 'invoice:delete' },
      ],
    }));
    await sql.unsafe(generateAuthorizationSchemaSql({
      schema: STRICT_AUTHORIZATION_SCHEMA,
      applicationId: APPLICATION_ID,
      requireOAuthApplicationClaim: true,
    }));
    await sql.unsafe(generateRlsPoliciesSql({
      schema: STRICT_AUTHORIZATION_SCHEMA,
      tableSchema: STRICT_DATA_SCHEMA,
      table: 'invoices',
      domainColumn: 'organization_id',
      domainIdType: 'text',
      domainType: 'organization',
      policies: [{ command: 'select', usingPermission: 'invoice:read' }],
    }));
  });

  afterAll(async () => {
    if (!sql) return;
    await sql.unsafe(`
      DROP SCHEMA IF EXISTS ${AUTHORIZATION_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${STRICT_AUTHORIZATION_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${SOURCE_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${DATA_SCHEMA} CASCADE;
      DROP SCHEMA IF EXISTS ${STRICT_DATA_SCHEMA} CASCADE;
    `);
    await sql.end();
  });

  beforeEach(seedAuthorizationState);

  test('native GoTrue token without an application claim uses the authorization-schema application boundary', async () => {
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual(['invoice-a']);
    await expect(visibleInvoiceIds({ ...nativeClaims, azp: 'other-application' }))
      .resolves.toEqual(['invoice-a']);
  });

  test('matching OAuth client_id and signed app_metadata application claims are accepted', async () => {
    await expect(visibleInvoiceIds({ ...nativeClaims, client_id: APPLICATION_ID }))
      .resolves.toEqual(['invoice-a']);
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      app_metadata: { authorization_context: { application_id: APPLICATION_ID } },
    })).resolves.toEqual(['invoice-a']);
  });

  test('mismatched, preferred, and empty client_id claims fail closed', async () => {
    await expect(visibleInvoiceIds({ ...nativeClaims, client_id: 'other-application' }))
      .resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      app_metadata: { authorization_context: { application_id: 'other-application' } },
    })).resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      client_id: 'other-application',
      app_metadata: { authorization_context: { application_id: APPLICATION_ID } },
    })).resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      client_id: '',
      app_metadata: { authorization_context: { application_id: APPLICATION_ID } },
    })).resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      client_id: null,
      app_metadata: { authorization_context: { application_id: APPLICATION_ID } },
    })).resolves.toEqual([]);
  });

  test('strict OAuth binding requires a matching root client_id or azp claim', async () => {
    await expect(visibleStrictInvoiceIds(nativeClaims)).resolves.toEqual([]);
    await expect(visibleStrictInvoiceIds({ ...nativeClaims, client_id: APPLICATION_ID }))
      .resolves.toEqual(['invoice-a']);
    await expect(visibleStrictInvoiceIds({ ...nativeClaims, azp: APPLICATION_ID }))
      .resolves.toEqual(['invoice-a']);
    await expect(visibleStrictInvoiceIds({
      ...nativeClaims,
      client_id: APPLICATION_ID,
      azp: APPLICATION_ID,
    })).resolves.toEqual(['invoice-a']);
    await expect(visibleStrictInvoiceIds({
      ...nativeClaims,
      app_metadata: { authorization_context: { application_id: APPLICATION_ID } },
    })).resolves.toEqual([]);
  });

  test('strict OAuth binding rejects mismatched, conflicting, and malformed claims', async () => {
    const deniedClaims: Array<Record<string, unknown>> = [
      { client_id: 'other-application' },
      { azp: 'other-application' },
      { client_id: APPLICATION_ID, azp: 'other-application' },
      { client_id: 'other-application', azp: APPLICATION_ID },
      { client_id: '' },
      { azp: '' },
      { client_id: null },
      { azp: null },
      { client_id: null, azp: APPLICATION_ID },
      { client_id: APPLICATION_ID, azp: null },
      { client_id: 42 },
      { azp: { application_id: APPLICATION_ID } },
      { client_id: [APPLICATION_ID], azp: APPLICATION_ID },
    ];

    for (const applicationClaims of deniedClaims) {
      await expect(visibleStrictInvoiceIds({ ...nativeClaims, ...applicationClaims }))
        .resolves.toEqual([]);
    }
  });

  test('cross-issuer, cross-application, and cross-domain memberships stay denied', async () => {
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual(['invoice-a']);
    await expect(visibleInvoiceIds({ ...nativeClaims, iss: 'https://unknown.example.test/auth/v1' }))
      .resolves.toEqual([]);
  });

  test('revocation is visible on the next statement', async () => {
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual(['invoice-a']);
    await sql`
      UPDATE authorization_test_source.role_assignments
      SET active = FALSE
      WHERE membership_key = 'membership-native'
    `;
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual([]);
  });

  test('exposes one-time helper execution in JSON EXPLAIN', async () => {
    expect(checkAuthorizationExplain(await invoiceExplainPlan(nativeClaims)))
      .toEqual({ passed: true, violations: [] });
  });

  test('enforces USING and WITH CHECK across insert, update, and delete', async () => {
    await withClaims(nativeClaims, async transaction => {
      await transaction`
        INSERT INTO authorization_test_data.invoices (id, organization_id)
        VALUES ('invoice-created', 'org-a')
      `;
    });
    await expect(withClaims(nativeClaims, async transaction => {
      await transaction`
        INSERT INTO authorization_test_data.invoices (id, organization_id)
        VALUES ('invoice-cross-scope', 'org-b')
      `;
    })).rejects.toThrow('new row violates row-level security policy');
    await expect(withClaims(nativeClaims, async transaction => {
      await transaction`
        UPDATE authorization_test_data.invoices
        SET organization_id = 'org-b'
        WHERE id = 'invoice-a'
      `;
    })).rejects.toThrow('new row violates row-level security policy');
    await withClaims(nativeClaims, async transaction => {
      await transaction`DELETE FROM authorization_test_data.invoices WHERE id = 'invoice-created'`;
    });
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual(['invoice-a']);
  });

  test('user_metadata cannot override signed identity or application binding', async () => {
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      user_metadata: {
        authorization_context: {
          kind: 'service',
          subject: 'service-worker',
          application_id: 'other-application',
        },
      },
    })).resolves.toEqual(['invoice-a']);
  });

  test('a user principal always binds to JWT sub even when signed app_metadata contains a subject', async () => {
    await expect(visibleInvoiceIds({
      ...nativeClaims,
      app_metadata: {
        authorization_context: {
          kind: 'user',
          subject: 'service-worker',
          application_id: APPLICATION_ID,
        },
      },
    })).resolves.toEqual(['invoice-a']);
  });

  test('signed service kind and subject remain supported', async () => {
    await expect(visibleInvoiceIds({
      iss: ISSUER,
      sub: 'unrelated-user-subject',
      app_metadata: {
        authorization_context: {
          kind: 'service',
          subject: 'service-worker',
          application_id: APPLICATION_ID,
        },
      },
    })).resolves.toEqual(['invoice-a']);
  });

  test('a service principal without an explicit signed subject fails closed', async () => {
    await expect(visibleInvoiceIds({
      iss: ISSUER,
      sub: 'service-worker',
      app_metadata: {
        authorization_context: {
          kind: 'service',
          application_id: APPLICATION_ID,
        },
      },
    })).resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      iss: ISSUER,
      sub: 'service-worker',
      app_metadata: {
        authorization_context: {
          kind: 'service',
          subject: '',
          application_id: APPLICATION_ID,
        },
      },
    })).resolves.toEqual([]);
    await expect(visibleInvoiceIds({
      iss: ISSUER,
      sub: 'service-worker',
      app_metadata: {
        authorization_context: {
          kind: 'service',
          subject: ' ',
          application_id: APPLICATION_ID,
        },
      },
    })).resolves.toEqual([]);
  });

  test('duplicate active memberships for one domain fail closed', async () => {
    await sql.unsafe(`
      INSERT INTO ${SOURCE_SCHEMA}.memberships (
        membership_key,
        principal_kind,
        principal_issuer,
        principal_subject,
        application_id,
        domain_type,
        domain_id,
        active
      ) VALUES (
        'membership-native-duplicate',
        'user',
        '${ISSUER}',
        'user-1',
        '${APPLICATION_ID}',
        'organization',
        'org-a',
        TRUE
      );
      INSERT INTO ${SOURCE_SCHEMA}.role_assignments (membership_key, role_key, active)
      VALUES ('membership-native-duplicate', 'invoice-operator', TRUE);
    `);
    await expect(visibleInvoiceIds(nativeClaims)).resolves.toEqual([]);
  });

  test('reports every projection contract violation as a stable result row', async () => {
    const invalidSchema = 'authorization_test_invalid_projection';
    await sql.unsafe(`DROP SCHEMA IF EXISTS ${invalidSchema} CASCADE;`);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_missing']);

    await sql.unsafe(`
      CREATE SCHEMA ${invalidSchema};
      CREATE TABLE ${invalidSchema}.effective_permission_grants (
        principal_kind TEXT, principal_issuer TEXT, principal_subject TEXT,
        application_id TEXT, domain_type TEXT, domain_id TEXT, permission_name TEXT
      );
    `);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_kind']);

    await sql.unsafe(`
      DROP SCHEMA ${invalidSchema} CASCADE;
      CREATE SCHEMA ${invalidSchema};
      CREATE VIEW ${invalidSchema}.effective_permission_grants AS
      SELECT ''::TEXT AS principal_kind
      WHERE FALSE;
    `);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_columns']);

    await sql.unsafe(`
      DROP SCHEMA ${invalidSchema} CASCADE;
      CREATE SCHEMA ${invalidSchema};
      CREATE VIEW ${invalidSchema}.effective_permission_grants AS
      SELECT
        ''::TEXT AS principal_kind, ''::TEXT AS principal_issuer, ''::TEXT AS principal_subject,
        ''::TEXT AS application_id, ''::TEXT AS domain_type, ''::TEXT AS domain_id,
        0::INTEGER AS permission_name
      WHERE FALSE;
    `);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_column_types']);

    await sql.unsafe(`
      DROP SCHEMA ${invalidSchema} CASCADE;
      CREATE SCHEMA ${invalidSchema};
      CREATE VIEW ${invalidSchema}.effective_permission_grants AS
      SELECT
        ''::TEXT AS principal_kind, ''::TEXT AS principal_issuer, ''::TEXT AS principal_subject,
        ''::TEXT AS application_id, ''::TEXT AS domain_type, ''::TEXT AS domain_id,
        ''::TEXT AS permission_name
      WHERE FALSE;
      GRANT SELECT ON ${invalidSchema}.effective_permission_grants TO authenticated;
    `);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_privileges']);

    await sql.unsafe(`
      REVOKE SELECT ON ${invalidSchema}.effective_permission_grants FROM authenticated;
      GRANT SELECT ON ${invalidSchema}.effective_permission_grants TO PUBLIC;
    `);
    await expect(projectionViolationRules(invalidSchema)).resolves.toEqual(['projection_privileges']);
    await sql.unsafe(`DROP SCHEMA ${invalidSchema} CASCADE;`);
  });
});
