// SupaOAuth metadata schema — lives in `supaoauth` schema on SupaCloud's Postgres
// Does NOT touch `auth` schema (GoTrue owns that)

import { pgSchema, uuid, varchar, text, boolean, integer, timestamp, jsonb, index, uniqueIndex } from 'drizzle-orm/pg-core';

const supaoauth = pgSchema('supaoauth');

// ─── API Resources ───────────────────────────────────────────────────────
export const apiResources = supaoauth.table('api_resources', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  indicator: varchar('indicator', { length: 1024 }).notNull(), // audience URL
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_api_resources_indicator').on(t.indicator),
]);

// ─── Scopes ───────────────────────────────────────────────────────────────
export const scopes = supaoauth.table('scopes', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  resourceId: uuid('resource_id').notNull().references(() => apiResources.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_scopes_resource_id').on(t.resourceId),
  uniqueIndex('uq_scopes_resource_name').on(t.resourceId, t.name),
]);

// ─── Organizations ────────────────────────────────────────────────────────
export const organizations = supaoauth.table('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─── Organization Members ─────────────────────────────────────────────────
export const organizationMembers = supaoauth.table('organization_members', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').notNull(), // references auth.users.id (FK across schema)
  role: varchar('role', { length: 100 }).notNull().default('member'),
  joinedAt: timestamp('joined_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_org_members_org_id').on(t.organizationId),
  index('idx_org_members_user_id').on(t.userId),
]);

// ─── Roles ────────────────────────────────────────────────────────────────
export const roles = supaoauth.table('roles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─── Permissions ──────────────────────────────────────────────────────────
export const permissions = supaoauth.table('permissions', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  scopeId: uuid('scope_id').references(() => scopes.id, { onDelete: 'set null' }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_permissions_role_id').on(t.roleId),
]);

// ─── Sign-in Experience ───────────────────────────────────────────────────
export const signInExperience = supaoauth.table('sign_in_experience', {
  id: uuid('id').primaryKey().defaultRandom(),
  // Branding
  logoUrl: text('logo_url'),
  faviconUrl: text('favicon_url'),
  primaryColor: varchar('primary_color', { length: 32 }),
  pageTitle: varchar('page_title', { length: 255 }),
  description: text('description'),
  backgroundUrl: text('background_url'),
  buttonLabel: varchar('button_label', { length: 255 }),
  customCss: text('custom_css'),
  content: jsonb('content').$type<Record<string, unknown> | null>(),
  // Auth flow
  signInMethods: jsonb('sign_in_methods').$type<string[]>().default([]),
  signUpEnabled: boolean('sign_up_enabled').default(true).notNull(),
  // Password policy
  passwordMinLength: integer('password_min_length').default(8).notNull(),
  passwordRequireUppercase: boolean('password_require_uppercase').default(false).notNull(),
  passwordRequireLowercase: boolean('password_require_lowercase').default(false).notNull(),
  passwordRequireNumbers: boolean('password_require_numbers').default(false).notNull(),
  passwordRequireSymbols: boolean('password_require_symbols').default(false).notNull(),
  // Metadata
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─── Per-Application Sign-in Experience ─────────────────────────────────
// Optional branding overrides for a GoTrue OAuth client application.
export const applicationSignInExperience = supaoauth.table('application_sign_in_experience', {
  id: uuid('id').primaryKey().defaultRandom(),
  applicationId: varchar('application_id', { length: 255 }).notNull(),
  enabled: boolean('enabled').default(true).notNull(),
  logoUrl: text('logo_url'),
  faviconUrl: text('favicon_url'),
  primaryColor: varchar('primary_color', { length: 32 }),
  pageTitle: varchar('page_title', { length: 255 }),
  backgroundUrl: text('background_url'),
  buttonLabel: varchar('button_label', { length: 255 }),
  customCss: text('custom_css'),
  content: jsonb('content').$type<Record<string, unknown> | null>(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_app_sie_app_id').on(t.applicationId),
]);

// ─── Audit Logs ───────────────────────────────────────────────────────────
export const auditLogs = supaoauth.table('audit_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  eventType: varchar('event_type', { length: 255 }).notNull(),
  actorId: uuid('actor_id'),
  actorType: varchar('actor_type', { length: 50 }).notNull().default('system'), // admin | user | system
  resourceType: varchar('resource_type', { length: 255 }).notNull(),
  resourceId: varchar('resource_id', { length: 255 }).notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_audit_logs_event_type').on(t.eventType),
  index('idx_audit_logs_resource').on(t.resourceType, t.resourceId),
  index('idx_audit_logs_created_at').on(t.createdAt),
]);

// ─── Connectors (SupaOAuth metadata layer on top of GoTrue providers) ─────
export const connectors = supaoauth.table('connectors', {
  id: uuid('id').primaryKey().defaultRandom(),
  providerId: varchar('provider_id', { length: 255 }).notNull(), // GoTrue provider ID
  runtimeKind: varchar('runtime_kind', { length: 32 }).notNull().default('builtin_oauth'),
  name: varchar('name', { length: 255 }).notNull(),
  category: varchar('category', { length: 50 }).notNull(), // social | enterprise_sso
  enabled: boolean('enabled').default(false).notNull(),
  config: jsonb('config').$type<Record<string, unknown>>().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_connectors_provider_id').on(t.providerId),
]);

// ─── Application-Resource/Scope Bindings ──────────────────────────────────
// Links OAuth client applications to API resources and their scopes.
// application_id is the GoTrue OAuth client_id (string, not UUID FK).
export const applicationBindings = supaoauth.table('application_bindings', {
  id: uuid('id').primaryKey().defaultRandom(),
  applicationId: varchar('application_id', { length: 255 }).notNull(), // GoTrue client_id
  resourceId: uuid('resource_id').notNull().references(() => apiResources.id, { onDelete: 'cascade' }),
  scopeId: uuid('scope_id').references(() => scopes.id, { onDelete: 'cascade' }), // null = all scopes for resource
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_app_bindings_app_id').on(t.applicationId),
  index('idx_app_bindings_resource_id').on(t.resourceId),
]);

// ─── Role Assignments ────────────────────────────────────────────────────
// Binds roles to users at user-level, org-level, or M2M app-level
export const roleAssignments = supaoauth.table('role_assignments', {
  id: uuid('id').primaryKey().defaultRandom(),
  roleId: uuid('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  userId: uuid('user_id'), // references auth.users.id (cross-schema); null for M2M assignments
  organizationId: uuid('organization_id').references(() => organizations.id, { onDelete: 'cascade' }),
  applicationId: varchar('application_id', { length: 255 }), // GoTrue client_id for M2M
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_role_assignments_role_id').on(t.roleId),
  index('idx_role_assignments_user_id').on(t.userId),
  index('idx_role_assignments_org_id').on(t.organizationId),
]);

// ─── User Consents (P0-17) ───────────────────────────────────────────────
// Existing installations may retain these historical overlay records.
// Active OAuth grants are authoritative in GoTrue and are never derived here.
export const userConsents = supaoauth.table('user_consents', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('user_id').notNull(), // references auth.users.id (cross-schema)
  applicationId: varchar('application_id', { length: 255 }).notNull(), // GoTrue client_id
  scopeId: uuid('scope_id').references(() => scopes.id, { onDelete: 'cascade' }),
  organizationId: uuid('organization_id').references(() => organizations.id, { onDelete: 'cascade' }),
  grantedAt: timestamp('granted_at', { withTimezone: true }).defaultNow().notNull(),
  revokedAt: timestamp('revoked_at', { withTimezone: true }),
}, (t) => [
  index('idx_user_consents_user_id').on(t.userId),
  index('idx_user_consents_app_id').on(t.applicationId),
  index('idx_user_consents_org_id').on(t.organizationId),
]);

// Records an OAuth approval or denial for audit without becoming a parallel
// grant store. `grant_id` only correlates with the authoritative GoTrue grant.
export const oauthConsentDecisions = supaoauth.table('oauth_consent_decisions', {
  id: uuid('id').primaryKey().defaultRandom(),
  authorizationId: varchar('authorization_id', { length: 255 }),
  userId: uuid('user_id').notNull(),
  applicationId: varchar('application_id', { length: 255 }).notNull(),
  requestedScopes: jsonb('requested_scopes').$type<string[]>().default([]).notNull(),
  organizationId: varchar('organization_id', { length: 255 }),
  decision: varchar('decision', { length: 16 }).notNull(),
  grantId: varchar('grant_id', { length: 255 }),
  requestId: varchar('request_id', { length: 255 }),
  details: jsonb('details').$type<Record<string, unknown>>().default({}).notNull(),
  decidedAt: timestamp('decided_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_oauth_consent_decisions_authorization_id').on(t.authorizationId),
  index('idx_oauth_consent_decisions_user_id').on(t.userId),
  index('idx_oauth_consent_decisions_app_id').on(t.applicationId),
]);

// ─── Organization Templates (P0-18) ──────────────────────────────────────
// Templates define the default roles, permissions, and scopes that are
// auto-created when a new organization is instantiated from the template.
export const organizationTemplates = supaoauth.table('organization_templates', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  // Template defines roles as JSON: [{ name, permissions: [string] }]
  templateRoles: jsonb('template_roles').$type<Array<{ name: string; permissions: string[] }>>().default([]),
  // Template defines default scopes as JSON: [{ name, description }]
  templateScopes: jsonb('template_scopes').$type<Array<{ name: string; description?: string }>>().default([]),
  isDefault: boolean('is_default').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

export const organizationTemplateInstantiations = supaoauth.table('organization_template_instantiations', {
  id: uuid('id').primaryKey().defaultRandom(),
  idempotencyKey: varchar('idempotency_key', { length: 255 }).notNull(),
  templateId: uuid('template_id').notNull(),
  requestHash: varchar('request_hash', { length: 64 }).notNull(),
  status: varchar('status', { length: 32 }).notNull().default('pending'),
  organizationId: varchar('organization_id', { length: 255 }),
  result: jsonb('result').$type<Record<string, unknown> | null>(),
  errorDetails: jsonb('error_details').$type<Record<string, unknown> | null>(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_org_template_instantiations_idempotency_key').on(t.idempotencyKey),
  index('idx_org_template_instantiations_template_id').on(t.templateId),
  index('idx_org_template_instantiations_status').on(t.status),
]);

// ─── Provisioning Records (P0-20) ────────────────────────────────────────
// Tracks SupaCloud project provisioning state for idempotent reconcile.
export const provisioningRecords = supaoauth.table('provisioning_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  projectRef: varchar('project_ref', { length: 255 }).notNull(),
  step: varchar('step', { length: 100 }).notNull(), // e.g. 'db_migration', 'gotrue_config', 'supacloud_gateway_routes', etc.
  status: varchar('status', { length: 50 }).notNull().default('pending'), // pending | completed | failed
  details: jsonb('details').$type<Record<string, unknown>>().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_provisioning_project_ref').on(t.projectRef),
  index('idx_provisioning_step').on(t.step),
  // One record per (projectRef, step). Backs recordStep()'s ON CONFLICT upsert.
  uniqueIndex('uq_provisioning_records_project_step').on(t.projectRef, t.step),
]);

// ─── Security Config (P0-19) ─────────────────────────────────────────────
// Production security settings enforced by auth-server.
export const securityConfig = supaoauth.table('security_config', {
  id: uuid('id').primaryKey().defaultRandom(),
  adminAuthMode: varchar('admin_auth_mode', { length: 50 }).notNull().default('auto'), // auto | sso | token
  adminAllowedEmails: jsonb('admin_allowed_emails').$type<string[]>().default([]),
  adminAllowedDomains: jsonb('admin_allowed_domains').$type<string[]>().default([]),
  rateLimitRpm: integer('rate_limit_rpm').default(300).notNull(), // requests per minute per IP
  rateLimitBurst: integer('rate_limit_burst').default(50).notNull(),
  bruteForceProtection: boolean('brute_force_protection').default(true).notNull(),
  maxLoginAttempts: integer('max_login_attempts').default(10).notNull(),
  lockoutDurationSec: integer('lockout_duration_sec').default(900).notNull(), // 15 min
  secretRotationReminderDays: integer('secret_rotation_reminder_days').default(90).notNull(),
  enforceHttps: boolean('enforce_https').default(true).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ─── Enterprise SSO Connectors (P1-9) ────────────────────────────────────
// Extended connector metadata for enterprise SSO (SAML, OIDC, domain mapping)
export const enterpriseSSOConfig = supaoauth.table('enterprise_sso_config', {
  id: uuid('id').primaryKey().defaultRandom(),
  connectorId: uuid('connector_id').notNull().references(() => connectors.id, { onDelete: 'cascade' }),
  domains: jsonb('domains').$type<string[]>().notNull(), // e.g. ['company.com']
  ssoProtocol: varchar('sso_protocol', { length: 50 }).notNull().default('oidc'), // oidc | saml
  jitProvisioning: boolean('jit_provisioning').default(false).notNull(),
  orgMembershipMapping: jsonb('org_membership_mapping').$type<Record<string, string>>().default({}), // domain → org_id
  roleMapping: jsonb('role_mapping').$type<Record<string, string>>().default({}), // IdP group → supaoauth role
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_enterprise_sso_connector_id').on(t.connectorId),
]);

// ─── API Version Log (P1-10) ─────────────────────────────────────────────
// Tracks API version changes for contract enforcement
export const apiVersionLog = supaoauth.table('api_version_log', {
  id: uuid('id').primaryKey().defaultRandom(),
  version: varchar('version', { length: 50 }).notNull(), // e.g. '0.2.0'
  changeType: varchar('change_type', { length: 50 }).notNull(), // added | deprecated | breaking | removed
  path: varchar('path', { length: 500 }).notNull(),
  method: varchar('method', { length: 10 }).notNull(),
  description: text('description'),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_api_version_log_version').on(t.version),
]);

// ─── Application Secrets / Consent Configuration (P0-24) ────────────────
export const applicationSecrets = supaoauth.table('application_secrets', {
  id: uuid('id').primaryKey().defaultRandom(),
  applicationId: varchar('application_id', { length: 255 }).notNull(),
  secretId: varchar('secret_id', { length: 255 }).notNull(),
  secretHash: text('secret_hash'), // SHA-256 hash of the plaintext secret; null only for legacy rows
  name: varchar('name', { length: 255 }).notNull(),
  status: varchar('status', { length: 50 }).notNull().default('active'), // active | disabled | deleted
  lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  disabledAt: timestamp('disabled_at', { withTimezone: true }),
}, (t) => [
  index('idx_application_secrets_app_id').on(t.applicationId),
  index('idx_application_secrets_secret_id').on(t.secretId),
]);

export const applicationConsentSettings = supaoauth.table('application_consent_settings', {
  id: uuid('id').primaryKey().defaultRandom(),
  applicationId: varchar('application_id', { length: 255 }).notNull(),
  userScopes: jsonb('user_scopes').$type<string[]>().default([]),
  organizationScopes: jsonb('organization_scopes').$type<string[]>().default([]),
  allowedOrganizationIds: jsonb('allowed_organization_ids').$type<string[]>().default([]),
  requireExplicitConsent: boolean('require_explicit_consent').default(true).notNull(),
  customData: jsonb('custom_data').$type<Record<string, unknown>>().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_application_consent_settings_app_id').on(t.applicationId),
]);

// ─── Account Provisioning / Claiming ─────────────────────────────────────
// Keeps tenant-owned external identities separate from GoTrue auth.users UUIDs.
export const accountProvisioningRecords = supaoauth.table('account_provisioning_records', {
  id: uuid('id').primaryKey().defaultRandom(),
  externalId: varchar('external_id', { length: 100 }).notNull(),
  externalType: varchar('external_type', { length: 100 }).notNull().default('generic'),
  displayName: varchar('display_name', { length: 255 }).notNull(),
  normalizedDisplayName: varchar('normalized_display_name', { length: 255 }).notNull(),
  email: varchar('email', { length: 320 }).notNull(),
  userId: uuid('user_id'),
  initialPasswordEncrypted: text('initial_password_encrypted'),
  initialPasswordClaimed: boolean('initial_password_claimed').default(false).notNull(),
  claimedAt: timestamp('claimed_at', { withTimezone: true }),
  claimCount: integer('claim_count').default(0).notNull(),
  claimProofHash: text('claim_proof_hash'),
  claimState: varchar('claim_state', { length: 32 }).default('ready').notNull(),
  claimMode: varchar('claim_mode', { length: 32 }),
  claimPasswordHash: text('claim_password_hash'),
  claimOperationId: uuid('claim_operation_id'),
  claimLeaseExpiresAt: timestamp('claim_lease_expires_at', { withTimezone: true }),
  sourceStatus: varchar('source_status', { length: 50 }).notNull().default('active'),
  profile: jsonb('profile').$type<Record<string, unknown>>().default({}),
  importBatch: varchar('import_batch', { length: 255 }),
  metadata: jsonb('metadata').$type<Record<string, unknown>>().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_account_provisioning_external').on(t.externalType, t.externalId),
  uniqueIndex('uq_account_provisioning_email').on(t.email),
  index('idx_account_provisioning_normalized_name').on(t.normalizedDisplayName),
  index('idx_account_provisioning_user_id').on(t.userId),
]);

export const organizationInvitations = supaoauth.table('organization_invitations', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  email: varchar('email', { length: 320 }).notNull(),
  role: varchar('role', { length: 100 }).notNull().default('member'),
  status: varchar('status', { length: 50 }).notNull().default('pending'), // pending | accepted | revoked | expired
  tokenHash: varchar('token_hash', { length: 255 }).notNull(),
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  acceptedAt: timestamp('accepted_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_org_invitations_org_id').on(t.organizationId),
  index('idx_org_invitations_email').on(t.email),
]);

export const organizationJitSettings = supaoauth.table('organization_jit_settings', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  emailDomains: jsonb('email_domains').$type<string[]>().default([]),
  ssoConnectorIds: jsonb('sso_connector_ids').$type<string[]>().default([]),
  defaultRoleIds: jsonb('default_role_ids').$type<string[]>().default([]),
  enabled: boolean('enabled').default(false).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_org_jit_settings_org_id').on(t.organizationId),
]);

export const organizationApplications = supaoauth.table('organization_applications', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  applicationId: varchar('application_id', { length: 255 }).notNull(),
  roleIds: jsonb('role_ids').$type<string[]>().default([]),
  enabled: boolean('enabled').default(true).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_org_apps_org_id').on(t.organizationId),
  index('idx_org_apps_app_id').on(t.applicationId),
]);

// ─── Connector Factory / Tenant UX Configuration (P1-14/P1-16) ──────────
export const connectorFactories = supaoauth.table('connector_factories', {
  id: uuid('id').primaryKey().defaultRandom(),
  factoryId: varchar('factory_id', { length: 255 }).notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  protocol: varchar('protocol', { length: 50 }).notNull(),
  category: varchar('category', { length: 100 }).notNull(),
  configSchema: jsonb('config_schema').$type<Record<string, unknown>>().default({}),
  enabled: boolean('enabled').default(true).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  uniqueIndex('uq_connector_factories_factory_id').on(t.factoryId),
]);

export const tenantConfigs = supaoauth.table('tenant_configs', {
  id: uuid('id').primaryKey().defaultRandom(),
  configType: varchar('config_type', { length: 100 }).notNull(), // captcha | email_template | sms_template | domain | phrase | profile_field | branding_asset
  key: varchar('key', { length: 255 }).notNull(),
  value: jsonb('value').$type<Record<string, unknown>>().default({}),
  enabled: boolean('enabled').default(true).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (t) => [
  index('idx_tenant_configs_type').on(t.configType),
  uniqueIndex('uq_tenant_configs_type_key').on(t.configType, t.key),
]);
