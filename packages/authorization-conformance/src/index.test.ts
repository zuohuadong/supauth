import { describe, expect, it } from 'bun:test';
import {
  checkAuthorizationExplain,
  checkAuthorizationSql,
  REQUIRED_AUTHORIZATION_DENIAL_SCENARIOS,
  REQUIRED_AUTHORIZATION_SCENARIOS,
  runAuthorizationConformance,
  type AuthorizationOutcome,
  type AuthorizationDenialScenario,
} from './index.js';

function deniedOutcome(scenario: AuthorizationDenialScenario): AuthorizationOutcome {
  return { allowed: false, status: scenario === 'adapter_unavailable' ? 503 : 403 };
}

const projectionPreflightSql = `WITH projection AS (
  SELECT pg_catalog.to_regclass('authz.effective_permission_grants') AS relation_oid
), violations(rule, message) AS (
  SELECT 'projection_missing', 'projection view is required'
  FROM projection
  WHERE relation_oid IS NULL
  UNION ALL
  SELECT 'projection_kind', 'must be an ordinary view'
  FROM projection
  WHERE (SELECT relkind FROM pg_catalog.pg_class WHERE oid = relation_oid) IS DISTINCT FROM 'v'
  UNION ALL
  SELECT 'projection_columns', 'columns do not match the required contract'
  FROM projection
  WHERE ARRAY(
    SELECT attribute.attname::TEXT FROM pg_catalog.pg_attribute AS attribute
  ) IS DISTINCT FROM ARRAY['principal_kind']::TEXT[]
  UNION ALL
  SELECT 'projection_column_types', 'columns must all use TEXT'
  FROM projection
  WHERE EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.atttypid <> 'pg_catalog.text'::pg_catalog.regtype
  )
  UNION ALL
  SELECT 'projection_privileges', 'must not be directly readable'
  FROM projection
  WHERE has_table_privilege('anon', relation_oid, 'SELECT')
    OR has_table_privilege('authenticated', relation_oid, 'SELECT')
)
SELECT rule, message FROM violations;`;

const installSql = `CREATE FUNCTION authorization_allowed_scope_ids(
  requested_permission TEXT,
  requested_domain_type TEXT
)
RETURNS TABLE(scope_id TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$ SELECT permission_grant.domain_id FROM effective_permission_grants AS permission_grant
WHERE permission_grant.application_id = 'xigu-fa' $$;
REVOKE ALL ON SCHEMA authz FROM PUBLIC;
GRANT USAGE ON SCHEMA authz TO authenticated;
REVOKE ALL ON FUNCTION authorization_allowed_scope_ids(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION authorization_allowed_scope_ids(TEXT, TEXT) FROM anon;
GRANT EXECUTE ON FUNCTION authorization_allowed_scope_ids(TEXT, TEXT) TO authenticated;`;

const legacyCleanupSql = 'DROP FUNCTION IF EXISTS authorization_allowed_scope_ids(TEXT, TEXT, TEXT);';

const rlsSql = `CREATE POLICY invoice_update ON invoices FOR UPDATE TO authenticated
USING (organization_id IN (
  SELECT allowed_scope.scope_id::uuid
  FROM authorization_allowed_scope_ids('invoice:read', 'organization') AS allowed_scope
))
WITH CHECK (organization_id IN (
  SELECT allowed_scope.scope_id::uuid
  FROM authorization_allowed_scope_ids('invoice:update', 'organization') AS allowed_scope
));`;

function passingPlan(actualLoops = 1): unknown {
  return [{
    Plan: {
      'Node Type': 'Seq Scan',
      Filter: '(ANY (organization_id = (hashed SubPlan 1).col1))',
      Plans: [{
        'Node Type': 'Function Scan',
        'Parent Relationship': 'SubPlan',
        'Subplan Name': 'SubPlan 1',
        'Function Name': 'authorization_allowed_scope_ids',
        'Actual Loops': actualLoops,
      }],
    },
  }];
}

describe('@supauth/authorization-conformance', () => {
  it('executes every required scenario through the supplied application harness', async () => {
    const observed: string[] = [];
    const report = await runAuthorizationConformance({
      async runDenialScenario(scenario) {
        observed.push(scenario);
        return deniedOutcome(scenario);
      },
      async runRevocationVisibilityScenario() {
        observed.push('revocation_visibility');
        return { before: { allowed: true, status: 200 }, after: { allowed: false, status: 403 } };
      },
    });
    expect(report).toEqual({ passed: true, violations: [] });
    expect(observed).toEqual([...REQUIRED_AUTHORIZATION_SCENARIOS]);
  });

  it('reports unsafe outcomes and scenario runner failures', async () => {
    const report = await runAuthorizationConformance({
      async runDenialScenario(scenario) {
        if (scenario === 'cross_domain') return { allowed: true, status: 200 };
        if (scenario === 'adapter_unavailable') throw new Error('database offline');
        return deniedOutcome(scenario);
      },
      async runRevocationVisibilityScenario() {
        return { before: { allowed: false, status: 403 }, after: { allowed: false, status: 403 } };
      },
    });
    expect(report.violations.map(violation => violation.rule))
      .toEqual(['cross_domain', 'adapter_unavailable', 'revocation_visibility']);
    expect(REQUIRED_AUTHORIZATION_DENIAL_SCENARIOS).toContain('explicit_deny_precedence');
  });

  it('checks final-grant ownership, fixed application binding, and RLS shape', () => {
    expect(checkAuthorizationSql({
      projectionPreflightSql,
      installSql,
      rlsSql,
      legacyCleanupSql,
    })).toEqual({ passed: true, violations: [] });
    const unsafe = checkAuthorizationSql({
      projectionPreflightSql,
      installSql: `${installSql}\nCREATE TABLE authz.role_permissions (role_key TEXT);`,
      rlsSql: `CREATE POLICY open_access ON invoices FOR SELECT TO authenticated USING (true);`,
    });
    expect(unsafe.violations.map(violation => violation.rule)).toContain('package_owned_policy');
    expect(unsafe.violations.map(violation => violation.rule)).toContain('policy_scope_set');
    expect(unsafe.violations.map(violation => violation.rule)).toContain('permissive_policy');
  });

  it('does not accept safety keywords hidden in comments or string literals', () => {
    const report = checkAuthorizationSql({
      projectionPreflightSql: `-- pg_catalog.to_regclass effective_permission_grants\nSELECT 'violations(rule, message) SELECT rule, message FROM violations';`,
      installSql: `-- effective_permission_grants ordinary view\nSELECT 'SECURITY DEFINER SET search_path = ''';`,
      rlsSql: `/* authorization_allowed_scope_ids('invoice:read') */\nCREATE POLICY open_access ON invoices FOR SELECT TO authenticated USING (true);`,
    });
    expect(report.passed).toBe(false);
    expect(report.violations.map(violation => violation.rule)).toContain('catalog_resolution');
    expect(report.violations.map(violation => violation.rule)).toContain('hardened_helper');
  });

  it('does not accept safety keywords hidden in dollar-quoted literals', () => {
    const report = checkAuthorizationSql({
      projectionPreflightSql: `SELECT $spoof$${projectionPreflightSql}$spoof$;`,
      installSql: `SELECT $spoof$${installSql}$spoof$;`,
      rlsSql: `SELECT $$${rlsSql}$$;`,
    });
    expect(report.passed).toBe(false);
    expect(report.violations.map(violation => violation.rule)).toContain('catalog_resolution');
    expect(report.violations.map(violation => violation.rule)).toContain('rls_policy');
  });

  it('rejects procedural migrations and a mutating projection preflight', () => {
    const report = checkAuthorizationSql({
      projectionPreflightSql: `${projectionPreflightSql}\nDELETE FROM authz.effective_permission_grants;`,
      installSql: `DO $$ BEGIN NULL; END $$;\n${installSql}`,
      rlsSql: `${rlsSql}\nDO $$ BEGIN NULL; END $$;`,
      legacyCleanupSql: `DO $$ BEGIN NULL; END $$;\n${legacyCleanupSql}`,
    });
    const rules = report.violations.map(violation => violation.rule);
    expect(rules).toContain('projection_preflight_read_only');
    expect(rules).toContain('projection_preflight_statement');
    expect(rules).toContain('install_static_sql');
    expect(rules).toContain('rls_static_sql');
    expect(rules).toContain('legacy_cleanup_static_sql');
  });

  it('requires parsed JSON plans with one helper loop and a hashed subplan', () => {
    expect(checkAuthorizationExplain(passingPlan())).toEqual({ passed: true, violations: [] });
    expect(checkAuthorizationExplain(passingPlan(250_000)).violations.map(violation => violation.rule))
      .toEqual(['one_time_execution']);
    const unrelatedSubplan = passingPlan() as Array<{ Plan: { Plans: Array<Record<string, unknown>> } }>;
    unrelatedSubplan[0]!.Plan.Plans[0]!['Subplan Name'] = 'SubPlan 2';
    expect(checkAuthorizationExplain(unrelatedSubplan).violations.map(violation => violation.rule))
      .toEqual(['one_time_scope_plan']);
    expect(checkAuthorizationExplain('Seq Scan').violations.map(violation => violation.rule))
      .toEqual(['explain_json']);
  });
});
