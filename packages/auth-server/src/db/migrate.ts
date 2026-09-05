// Migration script for SupAuth overlay tables in a SupaCloud project.
// SupaCloud owns identity management tables; this migration intentionally does
// not create duplicate Organizations/RBAC/Users/Audit/Webhooks source tables.

import postgres from 'postgres';

export const MIGRATION_SQL = `
CREATE SCHEMA IF NOT EXISTS supaoauth;

-- API resource overlay used by SupAuth product UX and RLS migration helpers.
CREATE TABLE IF NOT EXISTS supaoauth.api_resources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  indicator VARCHAR(1024) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_resources_indicator ON supaoauth.api_resources (indicator);

CREATE TABLE IF NOT EXISTS supaoauth.scopes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  resource_id UUID NOT NULL REFERENCES supaoauth.api_resources(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scopes_resource_id ON supaoauth.scopes (resource_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scopes_resource_name ON supaoauth.scopes (resource_id, name);

-- Hosted sign-in experience overlays. SupaCloud/GoTrue still own runtime auth.
CREATE TABLE IF NOT EXISTS supaoauth.sign_in_experience (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  logo_url TEXT,
  favicon_url TEXT,
  primary_color VARCHAR(32),
  page_title VARCHAR(255),
  description TEXT,
  background_url TEXT,
  button_label VARCHAR(255),
  custom_css TEXT,
  content JSONB,
  sign_in_methods JSONB DEFAULT '[]'::jsonb,
  sign_up_enabled BOOLEAN NOT NULL DEFAULT true,
  password_min_length INTEGER NOT NULL DEFAULT 8,
  password_require_uppercase BOOLEAN NOT NULL DEFAULT false,
  password_require_lowercase BOOLEAN NOT NULL DEFAULT false,
  password_require_numbers BOOLEAN NOT NULL DEFAULT false,
  password_require_symbols BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Login page theme fields (config-driven tenant default).
ALTER TABLE supaoauth.sign_in_experience ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE supaoauth.sign_in_experience ADD COLUMN IF NOT EXISTS background_url TEXT;
ALTER TABLE supaoauth.sign_in_experience ADD COLUMN IF NOT EXISTS button_label VARCHAR(255);
ALTER TABLE supaoauth.sign_in_experience ADD COLUMN IF NOT EXISTS custom_css TEXT;
DO $$
DECLARE
  current_type TEXT;
BEGIN
  SELECT data_type INTO current_type
  FROM information_schema.columns
  WHERE table_schema = 'supaoauth'
    AND table_name = 'sign_in_experience'
    AND column_name = 'content';

  IF current_type IS NULL THEN
    ALTER TABLE supaoauth.sign_in_experience ADD COLUMN content JSONB;
  ELSIF current_type <> 'jsonb' THEN
    ALTER TABLE supaoauth.sign_in_experience RENAME COLUMN content TO content_legacy;
    ALTER TABLE supaoauth.sign_in_experience ADD COLUMN content JSONB;
    DROP FUNCTION IF EXISTS supaoauth.try_parse_jsonb(TEXT);
    CREATE FUNCTION supaoauth.try_parse_jsonb(input TEXT) RETURNS JSONB
    LANGUAGE plpgsql IMMUTABLE AS $fn$
    BEGIN
      RETURN input::jsonb;
    EXCEPTION WHEN others THEN
      RETURN NULL;
    END;
    $fn$;
    UPDATE supaoauth.sign_in_experience
    SET content = supaoauth.try_parse_jsonb(content_legacy)
    WHERE content_legacy IS NOT NULL;
    ALTER TABLE supaoauth.sign_in_experience DROP COLUMN content_legacy;
    DROP FUNCTION supaoauth.try_parse_jsonb(TEXT);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS supaoauth.application_sign_in_experience (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id VARCHAR(255) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  logo_url TEXT,
  favicon_url TEXT,
  primary_color VARCHAR(32),
  page_title VARCHAR(255),
  background_url TEXT,
  button_label VARCHAR(255),
  custom_css TEXT,
  content JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
DO $$
DECLARE
  current_type TEXT;
BEGIN
  SELECT data_type INTO current_type
  FROM information_schema.columns
  WHERE table_schema = 'supaoauth'
    AND table_name = 'application_sign_in_experience'
    AND column_name = 'content';

  IF current_type IS NULL THEN
    ALTER TABLE supaoauth.application_sign_in_experience ADD COLUMN content JSONB;
  ELSIF current_type <> 'jsonb' THEN
    ALTER TABLE supaoauth.application_sign_in_experience RENAME COLUMN content TO content_legacy;
    ALTER TABLE supaoauth.application_sign_in_experience ADD COLUMN content JSONB;
    DROP FUNCTION IF EXISTS supaoauth.try_parse_jsonb(TEXT);
    CREATE FUNCTION supaoauth.try_parse_jsonb(input TEXT) RETURNS JSONB
    LANGUAGE plpgsql IMMUTABLE AS $fn$
    BEGIN
      RETURN input::jsonb;
    EXCEPTION WHEN others THEN
      RETURN NULL;
    END;
    $fn$;
    UPDATE supaoauth.application_sign_in_experience
    SET content = supaoauth.try_parse_jsonb(content_legacy)
    WHERE content_legacy IS NOT NULL;
    ALTER TABLE supaoauth.application_sign_in_experience DROP COLUMN content_legacy;
    DROP FUNCTION supaoauth.try_parse_jsonb(TEXT);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_app_sie_app_id ON supaoauth.application_sign_in_experience (application_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_sie_app_id ON supaoauth.application_sign_in_experience (application_id);

-- Connector visibility/display overlay on top of SupaCloud providers.
CREATE TABLE IF NOT EXISTS supaoauth.connectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_id VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(50) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT false,
  config JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_provider_id ON supaoauth.connectors (provider_id);

CREATE TABLE IF NOT EXISTS supaoauth.connector_factories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  factory_id VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  protocol VARCHAR(50) NOT NULL,
  category VARCHAR(100) NOT NULL,
  config_schema JSONB DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_connector_factories_factory_id ON supaoauth.connector_factories (factory_id);

-- Application/resource binding overlay. Applications themselves live in SupaCloud.
CREATE TABLE IF NOT EXISTS supaoauth.application_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id VARCHAR(255) NOT NULL,
  resource_id UUID NOT NULL REFERENCES supaoauth.api_resources(id) ON DELETE CASCADE,
  scope_id UUID REFERENCES supaoauth.scopes(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_app_bindings_app_id ON supaoauth.application_bindings (application_id);
CREATE INDEX IF NOT EXISTS idx_app_bindings_resource_id ON supaoauth.application_bindings (resource_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_application_bindings_target
  ON supaoauth.application_bindings (
    application_id,
    resource_id,
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000')
  );

-- Consent policy is local, but grants remain authoritative in GoTrue.
CREATE TABLE IF NOT EXISTS supaoauth.application_consent_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  application_id VARCHAR(255) NOT NULL,
  user_scopes JSONB DEFAULT '[]'::jsonb,
  organization_scopes JSONB DEFAULT '[]'::jsonb,
  allowed_organization_ids JSONB DEFAULT '[]'::jsonb,
  require_explicit_consent BOOLEAN NOT NULL DEFAULT true,
  custom_data JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_application_consent_settings_app_id ON supaoauth.application_consent_settings (application_id);

CREATE TABLE IF NOT EXISTS supaoauth.oauth_consent_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  authorization_id VARCHAR(255),
  user_id UUID NOT NULL,
  application_id VARCHAR(255) NOT NULL,
  requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
  organization_id VARCHAR(255),
  decision VARCHAR(16) NOT NULL CHECK (decision IN ('approved', 'denied')),
  grant_id VARCHAR(255),
  request_id VARCHAR(255),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_consent_decisions_authorization_id
  ON supaoauth.oauth_consent_decisions (authorization_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_decisions_user_id
  ON supaoauth.oauth_consent_decisions (user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_decisions_app_id
  ON supaoauth.oauth_consent_decisions (application_id);

-- Template overlay; instantiation calls SupaCloud Organizations/RBAC APIs.
CREATE TABLE IF NOT EXISTS supaoauth.organization_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  template_roles JSONB DEFAULT '[]'::jsonb,
  template_scopes JSONB DEFAULT '[]'::jsonb,
  is_default BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS supaoauth.organization_template_instantiations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key VARCHAR(255) NOT NULL,
  template_id UUID NOT NULL,
  request_hash VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'completed', 'failed', 'recovery_required')),
  organization_id VARCHAR(255),
  result JSONB,
  error_details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_org_template_instantiations_idempotency_key
  ON supaoauth.organization_template_instantiations (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_org_template_instantiations_template_id
  ON supaoauth.organization_template_instantiations (template_id);
CREATE INDEX IF NOT EXISTS idx_org_template_instantiations_status
  ON supaoauth.organization_template_instantiations (status);

-- Product/security/tenant UX overlays.
CREATE TABLE IF NOT EXISTS supaoauth.security_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  admin_auth_mode VARCHAR(50) NOT NULL DEFAULT 'auto',
  admin_allowed_emails JSONB DEFAULT '[]'::jsonb,
  admin_allowed_domains JSONB DEFAULT '[]'::jsonb,
  rate_limit_rpm INTEGER NOT NULL DEFAULT 300,
  rate_limit_burst INTEGER NOT NULL DEFAULT 50,
  brute_force_protection BOOLEAN NOT NULL DEFAULT true,
  max_login_attempts INTEGER NOT NULL DEFAULT 10,
  lockout_duration_sec INTEGER NOT NULL DEFAULT 900,
  secret_rotation_reminder_days INTEGER NOT NULL DEFAULT 90,
  enforce_https BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS supaoauth.enterprise_sso_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  connector_id UUID NOT NULL REFERENCES supaoauth.connectors(id) ON DELETE CASCADE,
  domains JSONB NOT NULL,
  sso_protocol VARCHAR(50) NOT NULL DEFAULT 'oidc',
  jit_provisioning BOOLEAN NOT NULL DEFAULT false,
  org_membership_mapping JSONB DEFAULT '{}'::jsonb,
  role_mapping JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_enterprise_sso_connector_id ON supaoauth.enterprise_sso_config (connector_id);

CREATE TABLE IF NOT EXISTS supaoauth.api_version_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version VARCHAR(50) NOT NULL,
  change_type VARCHAR(50) NOT NULL,
  path VARCHAR(500) NOT NULL,
  method VARCHAR(10) NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_version_log_version ON supaoauth.api_version_log (version);

CREATE TABLE IF NOT EXISTS supaoauth.tenant_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  config_type VARCHAR(100) NOT NULL,
  key VARCHAR(255) NOT NULL,
  value JSONB DEFAULT '{}'::jsonb,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tenant_configs_type ON supaoauth.tenant_configs (config_type);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_configs_type_key ON supaoauth.tenant_configs (config_type, key);

-- Account provisioning overlay. User creation itself goes through SupaCloud.
CREATE TABLE IF NOT EXISTS supaoauth.account_provisioning_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  external_id VARCHAR(100) NOT NULL,
  external_type VARCHAR(100) NOT NULL DEFAULT 'generic',
  display_name VARCHAR(255) NOT NULL,
  normalized_display_name VARCHAR(255) NOT NULL,
  email VARCHAR(320) NOT NULL,
  user_id UUID,
  initial_password_encrypted TEXT,
  initial_password_claimed BOOLEAN NOT NULL DEFAULT false,
  claimed_at TIMESTAMPTZ,
  claim_count INTEGER NOT NULL DEFAULT 0,
  source_status VARCHAR(50) NOT NULL DEFAULT 'active',
  profile JSONB DEFAULT '{}'::jsonb,
  import_batch VARCHAR(255),
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_account_provisioning_external ON supaoauth.account_provisioning_records (external_type, external_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_account_provisioning_email ON supaoauth.account_provisioning_records (email);
CREATE INDEX IF NOT EXISTS idx_account_provisioning_normalized_name ON supaoauth.account_provisioning_records (normalized_display_name);
CREATE INDEX IF NOT EXISTS idx_account_provisioning_user_id ON supaoauth.account_provisioning_records (user_id);

-- Supabase-compatible RBAC projection helpers.
--
-- Historical helper definitions retained for ordered installs. Migration V8
-- replaces them with schema-v2 project-scoped readers before installation ends.
CREATE OR REPLACE FUNCTION supaoauth.authorize(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH claims AS (
    SELECT COALESCE(auth.jwt() -> 'app_metadata' -> 'supaoauth', '{}'::jsonb) AS supaoauth_claims
  )
  SELECT
    COALESCE((supaoauth_claims -> 'permissions') ? permission_name, false)
    AND COALESCE(supaoauth_claims -> 'permissions_truncated', 'false'::jsonb) <> 'true'::jsonb
    AND (
      target_organization_id IS NULL
      OR supaoauth_claims ->> 'current_org_id' = target_organization_id::text
      OR COALESCE((supaoauth_claims -> 'organization_ids') ? target_organization_id::text, false)
    )
  FROM claims;
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_org_permission(organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_permission(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, target_organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.app_has_org_permission(client_id TEXT, organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH claims AS (
    SELECT COALESCE(auth.jwt() -> 'app_metadata' -> 'supaoauth', '{}'::jsonb) AS supaoauth_claims
  )
  SELECT
    COALESCE((supaoauth_claims -> 'permissions') ? permission_name, false)
    AND COALESCE(supaoauth_claims -> 'permissions_truncated', 'false'::jsonb) <> 'true'::jsonb
    AND (
      supaoauth_claims ->> 'application_id' = client_id
      OR auth.jwt() ->> 'client_id' = client_id
    )
    AND (
      organization_id IS NULL
      OR supaoauth_claims ->> 'current_org_id' = organization_id::text
      OR COALESCE((supaoauth_claims -> 'organization_ids') ? organization_id::text, false)
    )
  FROM claims;
$$;

REVOKE ALL ON FUNCTION supaoauth.authorize(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_permission(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) FROM PUBLIC;
GRANT USAGE ON SCHEMA supaoauth TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.authorize(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_permission(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) TO authenticated;

-- Defaults for overlay tables.
INSERT INTO supaoauth.sign_in_experience (page_title, sign_up_enabled)
SELECT 'SupaOAuth', true
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.sign_in_experience);

INSERT INTO supaoauth.security_config (admin_auth_mode, rate_limit_rpm, brute_force_protection, enforce_https)
SELECT 'auto', 300, true, true
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.security_config);

INSERT INTO supaoauth.organization_templates (name, description, template_roles, template_scopes, is_default)
SELECT 'Default Organization', 'Standard organization with owner/admin/member roles',
  '[{"name":"owner","permissions":["organization.manage","organization.members.manage","organization.settings.manage","resource.read","resource.write"]},{"name":"admin","permissions":["organization.members.manage","resource.read","resource.write"]},{"name":"member","permissions":["resource.read"]}]'::jsonb,
  '[{"name":"organization.manage","description":"Manage organization settings"},{"name":"organization.members.manage","description":"Manage organization members"},{"name":"organization.settings.manage","description":"Manage organization configuration"},{"name":"resource.read","description":"Read organization resources"},{"name":"resource.write","description":"Write organization resources"}]'::jsonb,
  true
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.organization_templates);

INSERT INTO supaoauth.connector_factories (factory_id, name, protocol, category, config_schema, enabled)
SELECT 'oidc-enterprise', 'Enterprise OIDC', 'oidc', 'enterprise_sso',
  '{"required":["client_id","issuer"],"secret_fields":["client_secret"]}'::jsonb, true
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.connector_factories WHERE factory_id = 'oidc-enterprise');

INSERT INTO supaoauth.connector_factories (factory_id, name, protocol, category, config_schema, enabled)
SELECT 'saml-enterprise', 'Enterprise SAML', 'saml', 'enterprise_sso',
  '{"required":["entity_id","sso_url","certificate"],"secret_fields":["certificate"]}'::jsonb, true
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.connector_factories WHERE factory_id = 'saml-enterprise');

-- Enterprise social SSO connectors (reserved — no runtime adapter yet)
INSERT INTO supaoauth.connector_factories (factory_id, name, protocol, category, config_schema, enabled)
SELECT 'wecom-work', '企业微信', 'oauth2', 'enterprise_sso',
  '{"required":["corp_id","agent_id"],"secret_fields":["secret"],"optional":["callback_url"],"notes":"Reserved for future WeCom Work OAuth2 adapter"}'::jsonb, false
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.connector_factories WHERE factory_id = 'wecom-work');

INSERT INTO supaoauth.connector_factories (factory_id, name, protocol, category, config_schema, enabled)
SELECT 'feishu', '飞书', 'oauth2', 'enterprise_sso',
  '{"required":["app_id"],"secret_fields":["app_secret"],"optional":["callback_url"],"notes":"Reserved for future Feishu/Lark OAuth2 adapter"}'::jsonb, false
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.connector_factories WHERE factory_id = 'feishu');

INSERT INTO supaoauth.connector_factories (factory_id, name, protocol, category, config_schema, enabled)
SELECT 'dingtalk', '钉钉', 'oauth2', 'enterprise_sso',
  '{"required":["app_key"],"secret_fields":["app_secret"],"optional":["callback_url"],"notes":"Reserved for future DingTalk OAuth2 adapter"}'::jsonb, false
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.connector_factories WHERE factory_id = 'dingtalk');

INSERT INTO supaoauth.tenant_configs (config_type, key, value, enabled)
SELECT 'captcha', 'default', '{"provider":"none","configured":false}'::jsonb, false
WHERE NOT EXISTS (SELECT 1 FROM supaoauth.tenant_configs WHERE config_type = 'captcha' AND key = 'default');
`;

export const MIGRATION_V4_SQL = `
-- Existing installations retain historical consent rows for read-only audit.
DO $$
BEGIN
  IF to_regclass('supaoauth.user_consents') IS NOT NULL THEN
    EXECUTE $legacy_consent_dedupe$
UPDATE supaoauth.user_consents AS c
SET revoked_at = COALESCE(c.revoked_at, now())
WHERE c.revoked_at IS NULL
  AND EXISTS (
    SELECT 1 FROM supaoauth.user_consents AS keep
    WHERE keep.revoked_at IS NULL
      AND keep.user_id = c.user_id
      AND keep.application_id = c.application_id
      AND COALESCE(keep.scope_id, '00000000-0000-0000-0000-000000000000')
        = COALESCE(c.scope_id, '00000000-0000-0000-0000-000000000000')
      AND COALESCE(keep.organization_id, '00000000-0000-0000-0000-000000000000')
        = COALESCE(c.organization_id, '00000000-0000-0000-0000-000000000000')
      AND (keep.granted_at, keep.id) > (c.granted_at, c.id)
  )
$legacy_consent_dedupe$;
    EXECUTE $legacy_consent_index$
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_consents_active
  ON supaoauth.user_consents (user_id, application_id, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'), COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'))
  WHERE revoked_at IS NULL
$legacy_consent_index$;
  END IF;
END $$;

-- Legacy application-secret tables are no longer created on new installs.
DO $$
BEGIN
  IF to_regclass('supaoauth.application_secrets') IS NOT NULL THEN
    ALTER TABLE supaoauth.application_secrets ADD COLUMN IF NOT EXISTS secret_hash TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS uq_application_secrets_active
      ON supaoauth.application_secrets (application_id, secret_id)
      WHERE status = 'active';
  END IF;
END $$;
`;

export const MIGRATION_V5_SQL = `
DO $$
BEGIN
  IF to_regclass('supaoauth.provisioning_records') IS NOT NULL THEN
    EXECUTE $legacy_provisioning_dedupe$
DELETE FROM supaoauth.provisioning_records AS p
WHERE EXISTS (
  SELECT 1 FROM supaoauth.provisioning_records AS keep
  WHERE keep.project_ref = p.project_ref
    AND keep.step = p.step
    AND (keep.updated_at, keep.id) > (p.updated_at, p.id)
)
$legacy_provisioning_dedupe$;

    CREATE UNIQUE INDEX IF NOT EXISTS uq_provisioning_records_project_step
      ON supaoauth.provisioning_records (project_ref, step);
  END IF;
END $$;
`;

export const MIGRATION_V6_SQL = `
-- GoTrue owns active OAuth grants. This table stores only the user's decision
-- and correlation identifiers needed for product audit and reconciliation.
CREATE TABLE IF NOT EXISTS supaoauth.oauth_consent_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  authorization_id VARCHAR(255),
  user_id UUID NOT NULL,
  application_id VARCHAR(255) NOT NULL,
  requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
  organization_id VARCHAR(255),
  decision VARCHAR(16) NOT NULL CHECK (decision IN ('approved', 'denied')),
  grant_id VARCHAR(255),
  request_id VARCHAR(255),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_consent_decisions_authorization_id
  ON supaoauth.oauth_consent_decisions (authorization_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_decisions_user_id
  ON supaoauth.oauth_consent_decisions (user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_consent_decisions_app_id
  ON supaoauth.oauth_consent_decisions (application_id);

-- Duplicate configuration represents ambiguous runtime state. The migration
-- fails instead of choosing a winner and silently discarding user settings.
CREATE UNIQUE INDEX IF NOT EXISTS uq_api_resources_indicator
  ON supaoauth.api_resources (indicator);
CREATE UNIQUE INDEX IF NOT EXISTS uq_scopes_resource_name
  ON supaoauth.scopes (resource_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS uq_connectors_provider_id
  ON supaoauth.connectors (provider_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_connector_factories_factory_id
  ON supaoauth.connector_factories (factory_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_application_bindings_target
  ON supaoauth.application_bindings (
    application_id,
    resource_id,
    COALESCE(scope_id, '00000000-0000-0000-0000-000000000000')
  );
CREATE UNIQUE INDEX IF NOT EXISTS uq_application_consent_settings_app_id
  ON supaoauth.application_consent_settings (application_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_configs_type_key
  ON supaoauth.tenant_configs (config_type, key);
`;

export const MIGRATION_V7_SQL = `
-- The project Function role may access only the overlay tables used by the
-- auth-server runtime. GoTrue auth schema tables remain inaccessible and are
-- reached through /auth/v1.
DO $$
DECLARE
  project_role TEXT := 'role_' || regexp_replace(current_database(), '^supa_', '');
  table_name TEXT;
  select_insert_update_delete_tables TEXT[] := ARRAY[
    'api_resources',
    'scopes',
    'application_sign_in_experience',
    'organization_templates',
    'organization_template_instantiations',
    'enterprise_sso_config',
    'tenant_configs',
    'provisioning_records'
  ];
  select_insert_update_tables TEXT[] := ARRAY[
    'sign_in_experience',
    'connectors',
    'connector_factories',
    'application_consent_settings',
    'security_config'
  ];
  select_insert_delete_tables TEXT[] := ARRAY[
    'application_bindings'
  ];
  read_write_tables TEXT[] := ARRAY[
    'account_provisioning_records'
  ];
  select_insert_tables TEXT[] := ARRAY[
    'api_version_log'
  ];
  insert_only_tables TEXT[] := ARRAY[
    'oauth_consent_decisions'
  ];
  read_only_tables TEXT[] := ARRAY[
    'user_consents'
  ];
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = project_role) THEN
    EXECUTE format('GRANT USAGE ON SCHEMA supaoauth TO %I', project_role);

    -- Remove grants left by the historical V7 implementation. This keeps the
    -- repair idempotent and prevents retired or future objects from inheriting
    -- access through the old default privileges.
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA supaoauth FROM %I', project_role);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA supaoauth FROM %I', project_role);
    EXECUTE format('REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA supaoauth FROM %I', project_role);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON TABLES FROM %I', project_role);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON SEQUENCES FROM %I', project_role);
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA supaoauth REVOKE ALL PRIVILEGES ON FUNCTIONS FROM %I', project_role);

    FOREACH table_name IN ARRAY select_insert_update_delete_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    FOREACH table_name IN ARRAY select_insert_update_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT, INSERT, UPDATE ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    FOREACH table_name IN ARRAY select_insert_delete_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT, INSERT, DELETE ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    -- Account claiming reads the encrypted initial password in the Function,
    -- decrypts it there, and uses full-row RETURNING for its state machine.
    -- Keep this as an explicit table-level exception until that flow is moved
    -- behind a SECURITY DEFINER function boundary.
    FOREACH table_name IN ARRAY read_write_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT, INSERT, UPDATE ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    FOREACH table_name IN ARRAY select_insert_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT, INSERT ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    FOREACH table_name IN ARRAY insert_only_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT INSERT ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;

    FOREACH table_name IN ARRAY read_only_tables LOOP
      IF to_regclass(format('supaoauth.%I', table_name)) IS NOT NULL THEN
        EXECUTE format(
          'GRANT SELECT ON TABLE supaoauth.%I TO %I',
          table_name,
          project_role
        );
      END IF;
    END LOOP;
  END IF;
END $$;
`;

// V7 may already be recorded as applied on existing projects. Keep a
// forward-only, idempotent copy so those projects also receive the privilege
// repair instead of relying on a migration body being re-executed by name.
export const MIGRATION_V16_SQL = MIGRATION_V7_SQL;

// Repair duplicate defaults before enforcing the invariant on existing
// installations. The newest default is retained deterministically.
export const MIGRATION_V17_SQL = `
WITH ranked_defaults AS (
  SELECT id,
    ROW_NUMBER() OVER (ORDER BY updated_at DESC, id DESC) AS rank
  FROM supaoauth.organization_templates
  WHERE is_default = true
)
UPDATE supaoauth.organization_templates AS templates
SET is_default = false,
    updated_at = now()
FROM ranked_defaults
WHERE templates.id = ranked_defaults.id
  AND ranked_defaults.rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_organization_templates_single_default
  ON supaoauth.organization_templates (is_default)
  WHERE is_default = true;
`;

export const MIGRATION_V18_SQL = `
CREATE TABLE IF NOT EXISTS supaoauth.organization_template_instantiations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key VARCHAR(255) NOT NULL,
  template_id UUID NOT NULL,
  request_hash VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'completed', 'failed', 'recovery_required')),
  organization_id VARCHAR(255),
  result JSONB,
  error_details JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_org_template_instantiations_idempotency_key
  ON supaoauth.organization_template_instantiations (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_org_template_instantiations_template_id
  ON supaoauth.organization_template_instantiations (template_id);
CREATE INDEX IF NOT EXISTS idx_org_template_instantiations_status
  ON supaoauth.organization_template_instantiations (status);
`;

export const MIGRATION_V8_SQL = `
-- RBAC projections are project-scoped even when several projects share one
-- GoTrue authority. Legacy root-level projections intentionally fail closed.
CREATE OR REPLACE FUNCTION supaoauth.current_project_ref()
RETURNS TEXT
LANGUAGE sql
STABLE
SET search_path = supaoauth, public, auth
AS $$
  SELECT CASE
    WHEN current_database() ~ '^supa_.+$' THEN substring(current_database() FROM 6)
    ELSE NULL
  END;
$$;

CREATE OR REPLACE FUNCTION supaoauth.current_project_claims()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH projection AS (
    SELECT
      COALESCE(auth.jwt() -> 'app_metadata' -> 'supaoauth', '{}'::jsonb) AS namespace,
      supaoauth.current_project_ref() AS project_ref
  )
  SELECT CASE
    WHEN namespace ->> 'schema_version' = '2'
      AND project_ref IS NOT NULL
      AND jsonb_typeof(namespace -> 'projects' -> project_ref) = 'object'
      AND COALESCE(namespace -> 'projects' -> project_ref -> 'projection_unavailable', 'false'::jsonb) <> 'true'::jsonb
    THEN namespace -> 'projects' -> project_ref
    ELSE '{}'::jsonb
  END
  FROM projection;
$$;

CREATE OR REPLACE FUNCTION supaoauth.authorize(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH claims AS (
    SELECT supaoauth.current_project_claims() AS project_claims
  )
  SELECT
    COALESCE((project_claims -> 'permissions') ? permission_name, false)
    AND COALESCE(project_claims -> 'permissions_truncated', 'false'::jsonb) <> 'true'::jsonb
    AND (
      target_organization_id IS NULL
      OR project_claims ->> 'current_org_id' = target_organization_id::text
      OR COALESCE((project_claims -> 'organization_ids') ? target_organization_id::text, false)
    )
  FROM claims;
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_org_permission(organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_permission(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, target_organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.app_has_org_permission(client_id TEXT, organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH claims AS (
    SELECT supaoauth.current_project_claims() AS project_claims
  )
  SELECT
    COALESCE((project_claims -> 'permissions') ? permission_name, false)
    AND COALESCE(project_claims -> 'permissions_truncated', 'false'::jsonb) <> 'true'::jsonb
    AND (
      project_claims ->> 'application_id' = client_id
      OR auth.jwt() ->> 'client_id' = client_id
    )
    AND (
      organization_id IS NULL
      OR project_claims ->> 'current_org_id' = organization_id::text
      OR COALESCE((project_claims -> 'organization_ids') ? organization_id::text, false)
    )
  FROM claims;
$$;

REVOKE ALL ON FUNCTION supaoauth.current_project_ref() FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.current_project_claims() FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.authorize(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_permission(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION supaoauth.current_project_claims() TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.authorize(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_permission(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) TO authenticated;
`;

export const MIGRATION_V9_SQL = `
-- SupaCloud owns webhook definitions, secrets, outbox state, and deliveries.
-- This migration commits independently so a later retirement block cannot
-- restore Function access to legacy secrets or queued payloads.
DO $$
DECLARE
  project_role TEXT := 'role_' || regexp_replace(current_database(), '^supa_', '');
BEGIN
  IF to_regclass('supaoauth.webhook_deliveries') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhook_deliveries FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = project_role) THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhook_deliveries FROM %I', project_role);
    END IF;
  END IF;

  IF to_regclass('supaoauth.webhooks') IS NOT NULL THEN
    EXECUTE 'REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhooks FROM PUBLIC';
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = project_role) THEN
      EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE supaoauth.webhooks FROM %I', project_role);
    END IF;
  END IF;
END $$;
`;

export const MIGRATION_V10_SQL = `
DO $$
DECLARE
  webhook_count BIGINT := 0;
  delivery_count BIGINT := 0;
BEGIN
  IF to_regclass('supaoauth.webhooks') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM supaoauth.webhooks' INTO webhook_count;
  END IF;
  IF to_regclass('supaoauth.webhook_deliveries') IS NOT NULL THEN
    EXECUTE 'SELECT count(*) FROM supaoauth.webhook_deliveries' INTO delivery_count;
  END IF;

  IF webhook_count > 0 OR delivery_count > 0 THEN
    RAISE EXCEPTION USING
      ERRCODE = 'P0001',
      MESSAGE = 'legacy_webhook_retirement_blocked',
      DETAIL = format(
        'reason_code=legacy_webhook_data_present; webhook_rows=%s; delivery_rows=%s',
        webhook_count,
        delivery_count
      ),
      HINT = 'Back up the legacy tables, recreate and rotate every webhook in SupaCloud Secret Manager, then clear the retired rows and rerun this migration.';
  END IF;
END $$;

DROP TABLE IF EXISTS supaoauth.webhook_deliveries;
DROP TABLE IF EXISTS supaoauth.webhooks;
`;

export const MIGRATION_V11_SQL = `
-- Select the permission set from the trusted OAuth application and optional
-- organization context. Unknown applications and truncated projections fail closed;
-- an absent organization projection keeps root permissions inherited by that scope.
CREATE OR REPLACE FUNCTION supaoauth.current_permission_claims(target_organization_id UUID DEFAULT NULL)
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH project_context AS (
    SELECT
      supaoauth.current_project_claims() AS project_claims,
      NULLIF(auth.jwt() ->> 'client_id', '') AS token_application_id
  ), application_context AS (
    SELECT
      project_claims,
      COALESCE(token_application_id, NULLIF(project_claims ->> 'application_id', '')) AS trusted_application_id
    FROM project_context
  ), scoped AS (
    SELECT
      project_claims,
      CASE
        WHEN trusted_application_id IS NULL THEN project_claims
        WHEN project_claims ->> 'application_id' = trusted_application_id THEN project_claims
        WHEN jsonb_typeof(project_claims -> 'applications' -> trusted_application_id) = 'object'
          THEN project_claims -> 'applications' -> trusted_application_id
        ELSE '{}'::jsonb
      END AS permission_claims
    FROM application_context
  ), organization_scoped AS (
    SELECT
      project_claims,
      permission_claims AS application_claims,
      CASE
        WHEN target_organization_id IS NULL THEN permission_claims
        WHEN jsonb_typeof(permission_claims -> 'organizations' -> target_organization_id::text) = 'object'
          THEN permission_claims -> 'organizations' -> target_organization_id::text
        ELSE permission_claims
      END AS permission_claims
    FROM scoped
  )
  SELECT CASE
    WHEN COALESCE(project_claims -> 'projection_unavailable', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(project_claims -> 'truncated', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(application_claims -> 'projection_unavailable', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(application_claims -> 'truncated', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(application_claims -> 'permissions_truncated', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(permission_claims -> 'projection_unavailable', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(permission_claims -> 'truncated', 'false'::jsonb) = 'true'::jsonb
      OR COALESCE(permission_claims -> 'permissions_truncated', 'false'::jsonb) = 'true'::jsonb
    THEN '{}'::jsonb
    ELSE permission_claims
  END
  FROM organization_scoped;
$$;

CREATE OR REPLACE FUNCTION supaoauth.authorize(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT COALESCE(
    (supaoauth.current_permission_claims(target_organization_id) -> 'permissions') ? permission_name,
    false
  );
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_org_permission(organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.has_permission(permission_name TEXT, target_organization_id UUID DEFAULT NULL)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  SELECT supaoauth.authorize(permission_name, target_organization_id);
$$;

CREATE OR REPLACE FUNCTION supaoauth.app_has_org_permission(client_id TEXT, organization_id UUID, permission_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = supaoauth, public, auth
AS $$
  WITH context AS (
    SELECT
      supaoauth.current_project_claims() AS project_claims,
      NULLIF(auth.jwt() ->> 'client_id', '') AS token_application_id
  )
  SELECT
    COALESCE(
      COALESCE(token_application_id, NULLIF(project_claims ->> 'application_id', '')) = client_id,
      false
    )
    AND supaoauth.authorize(permission_name, organization_id)
  FROM context;
$$;

REVOKE ALL ON FUNCTION supaoauth.current_permission_claims(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.authorize(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_permission(TEXT, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION supaoauth.authorize(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_permission(TEXT, UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.has_org_permission(UUID, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION supaoauth.app_has_org_permission(TEXT, UUID, TEXT) TO authenticated;
`;

export const MIGRATION_V12_SQL = `
ALTER TABLE supaoauth.account_provisioning_records
  ADD COLUMN IF NOT EXISTS claim_proof_hash TEXT,
  ADD COLUMN IF NOT EXISTS claim_state VARCHAR(32) NOT NULL DEFAULT 'ready',
  ADD COLUMN IF NOT EXISTS claim_mode VARCHAR(32),
  ADD COLUMN IF NOT EXISTS claim_password_hash TEXT,
  ADD COLUMN IF NOT EXISTS claim_operation_id UUID,
  ADD COLUMN IF NOT EXISTS claim_lease_expires_at TIMESTAMPTZ;

UPDATE supaoauth.account_provisioning_records
SET claim_state = CASE
  WHEN initial_password_claimed THEN 'claimed'
  ELSE claim_state
END;

ALTER TABLE supaoauth.account_provisioning_records
  DROP CONSTRAINT IF EXISTS account_provisioning_claim_state_check;

ALTER TABLE supaoauth.account_provisioning_records
  ADD CONSTRAINT account_provisioning_claim_state_check
  CHECK (claim_state IN ('ready', 'pending', 'password_applied', 'password_update_unknown', 'claimed'));
`;

export const MIGRATION_V13_SQL = `
-- current_permission_claims reads only the caller's signed JWT projection. Direct
-- execution enables reviewable one-time RLS scope sets without exposing server data.
REVOKE ALL ON FUNCTION supaoauth.current_permission_claims(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION supaoauth.current_permission_claims(UUID) TO authenticated;
ALTER FUNCTION supaoauth.current_permission_claims(UUID) SET search_path = '';
`;

export const MIGRATION_V14_SQL = `
ALTER TABLE supaoauth.connectors
  ADD COLUMN IF NOT EXISTS runtime_kind VARCHAR(32) NOT NULL DEFAULT 'builtin_oauth';

UPDATE supaoauth.connectors
SET runtime_kind = CASE
  WHEN provider_id = 'oidc-enterprise' THEN 'custom_oidc'
  WHEN provider_id = 'saml-enterprise' THEN 'saml'
  ELSE runtime_kind
END;

ALTER TABLE supaoauth.connectors
  DROP CONSTRAINT IF EXISTS connectors_runtime_kind_check;
ALTER TABLE supaoauth.connectors
  ADD CONSTRAINT connectors_runtime_kind_check
  CHECK (runtime_kind IN ('builtin_oauth', 'custom_oidc', 'saml'));

UPDATE supaoauth.connector_factories
SET config_schema = '{"required":["identifier","name","client_id","client_secret","issuer"],"secret_fields":["client_secret"],"optional":["scopes"]}'::jsonb,
    updated_at = now()
WHERE factory_id = 'oidc-enterprise';

UPDATE supaoauth.connector_factories
SET config_schema = '{"required":["name"],"one_of":[["metadata_url","metadata_xml"]],"optional":["resource_id","domains","metadata_url","metadata_xml","attribute_mapping","name_id_format"]}'::jsonb,
    updated_at = now()
WHERE factory_id = 'saml-enterprise';
`;

export const MIGRATION_V15_SQL = `
UPDATE supaoauth.connectors
SET runtime_kind = 'builtin_oauth'
WHERE provider_id IN ('oidc-enterprise', 'saml-enterprise')
  AND runtime_kind IN ('custom_oidc', 'saml');
`;

export const HOSTED_MIGRATIONS = [
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
] as const;

export async function runMigration(databaseUrl?: string) {
  const url = databaseUrl || process.env.SUPACLOUD_DATABASE_URL || process.env.DATABASE_URL || '';
  if (!url) throw new Error('SUPACLOUD_DATABASE_URL or DATABASE_URL is required for migration');
  const sql = postgres(url, { max: 1 });

  try {
    for (const migration of HOSTED_MIGRATIONS) {
      await sql.unsafe(migration.sql);
    }
    console.log('SupaOAuth overlay schema migration completed');
  } catch (e) {
    console.error(`Migration failed: ${e instanceof Error ? e.message : String(e)}`);
    throw e;
  } finally {
    await sql.end();
  }
}

if (import.meta.main) {
  console.error('Direct DB migration is removed. Run `bun run install:supacloud` so SupaCloud Management API applies hosted migrations.');
  process.exit(1);
}
