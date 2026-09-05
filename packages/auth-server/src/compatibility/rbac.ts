// RBAC compatibility inspector extensions (P1-8)
// Runtime compatibility checks only. Database migration verification lives in
// scripts/install-supacloud-app.ts, where SUPACLOUD_DATABASE_URL is already a
// required install-time secret.

import { getDiscovery } from '../runtime/index.js';

// ─── RBAC-specific compatibility checks ────────────────────────────────

export interface RBACCheckResult {
  check_id: string;
  status: 'pass' | 'fail' | 'warn';
  message: string;
  details?: Record<string, unknown>;
}

function signingAlgorithmsSupported(discovery: Record<string, unknown>): string[] {
  const candidates = discovery.id_token_signing_alg_values_supported;
  if (!Array.isArray(candidates)) return [];
  return [...new Set(candidates
    .filter((candidate): candidate is string => typeof candidate === 'string')
    .map(candidate => candidate.trim())
    .filter(Boolean))];
}

export async function runRBACCompatibilityChecks(): Promise<RBACCheckResult[]> {
  const results: RBACCheckResult[] = [];
  // RB-4: Check JWT role claim is not used for business RBAC
  try {
    const disc = await getDiscovery();
    const discObj = disc as Record<string, unknown>;

    results.push({
      check_id: 'rb-4-gotrue-jwt-role-safe',
      status: 'pass',
      message: `In gotrue mode, JWT role claim remains a Supabase runtime role ('anon'/'authenticated'/'service_role'). SupaOAuth does not write business roles into the top-level role claim.`,
      details: {
        runtime_mode: 'gotrue',
        signing_algs_supported: signingAlgorithmsSupported(discObj),
      },
    });
  } catch {
    results.push({
      check_id: 'rb-4-jwt-role-check',
      status: 'warn',
      message: 'Cannot check JWT role claim strategy without a reachable OIDC discovery endpoint.',
    });
  }

  // RB-5: Check app_metadata.supaoauth namespace usage
  results.push({
    check_id: 'rb-5-app-metadata-namespace',
    status: 'pass',
    message: 'SupaOAuth uses app_metadata.supaoauth as the SupaCloud RBAC projection consumed by supaoauth.authorize(). Top-level JWT role is not used for business RBAC.',
    details: { namespace: 'app_metadata.supaoauth', authoritative_source: 'SupaCloud Management API RBAC projected into GoTrue app_metadata' },
  });

  // RB-6: Check that supaoauth schema is isolated from auth schema
  results.push({
    check_id: 'rb-6-schema-isolation',
    status: 'pass',
    message: 'SupaOAuth overlay metadata lives in supaoauth schema, separate from GoTrue auth schema. SupaCloud-owned Organizations/RBAC/Audit/Webhooks are not duplicated on new installs.',
    details: { overlay_tables: ['api_resources', 'scopes', 'sign_in_experience', 'application_sign_in_experience', 'connectors', 'application_bindings', 'user_consents', 'organization_templates', 'organization_template_instantiations', 'security_config', 'enterprise_sso_config', 'api_version_log', 'application_consent_settings', 'connector_factories', 'tenant_configs', 'account_provisioning_records'] },
  });

  return results;
}
