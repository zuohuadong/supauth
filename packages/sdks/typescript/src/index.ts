// @supauth/sdk-typescript — TypeScript SDK for SupaOAuth Management API
import type {
  Application,
  CreateApplicationInput,
  ApiResource,
  CreateResourceInput,
  Scope,
  Connector,
  Organization,
  OrganizationMember,
  Role,
  Permission,
  SignInExperience,
  ApplicationSignInExperience,
  EffectiveSignInExperience,
  PublicEffectiveSignInExperience,
  PublicPhraseBundle,
  AuditLogEntry,
  Webhook,
  RuntimeMode,
  CapabilitiesResponse,
  CompatibilityCheckResult,
} from '@supauth/shared';

// ─── Response wrappers ──────────────────────────────────
interface ListResponse<T> {
  items: T[];
  total: number;
  page?: number;
  limit?: number;
}

interface CursorListResponse<T> {
  items: T[];
  total: number;
  limit: number;
  next_cursor: string | null;
}

interface HealthResponse {
  status: string;
  runtime_mode: RuntimeMode;
  project_ref: string;
}

interface ProjectResponse {
  id: string;
  ref?: string;
  project_ref?: string;
  name: string;
  region?: string;
}

interface OAuthServerStatus {
  enabled: boolean;
  signing_alg: string;
  allow_dynamic_registration: boolean;
  migration_status?: string;
}

interface DiscoveryResponse {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  [key: string]: unknown;
}

interface JWKSResponse {
  keys: Record<string, unknown>[];
}

interface AuthConfigResponse {
  enable_signup: boolean;
  enable_confirmations: boolean;
  external_anonymous_users_enabled: boolean;
  jwt_expiry: number;
  password_min_length: number;
  mfa_max_enrolled_factors: number;
  [key: string]: unknown;
}

interface ApplicationBinding {
  id: string;
  application_id: string;
  resource_id: string;
  scope_id?: string;
  created_at: string;
}

interface OAuthApplication {
  client_id: string;
  client_name?: string;
  client_type?: string;
  redirect_uris?: string[];
  grant_types?: string[];
  token_endpoint_auth_method?: string;
  client_secret?: string;
  created_at?: string;
  updated_at?: string;
  [key: string]: unknown;
}

interface RoleAssignment {
  id: string;
  role_id: string;
  user_id: string;
  organization_id?: string;
  application_id?: string;
  created_at: string;
}

interface UserPermissions {
  roles: string[];
  permissions: string[];
  scopes: string[];
}

interface SyncResult {
  synced: boolean;
  warnings?: string[];
}

interface WebhookEventList {
  events: string[];
}

interface WebhookDeliveryLog {
  id?: string;
  event?: string;
  event_type?: string;
  eventType?: string;
  status?: string | number;
  status_code?: number;
  statusCode?: number;
  http_status?: number;
  httpStatus?: number;
  success?: boolean;
  ok?: boolean;
  delivered?: boolean;
  error?: string;
  error_message?: string;
  errorMessage?: string;
  signature_status?: string;
  signatureStatus?: string;
  signature_verified?: boolean;
  signatureVerified?: boolean;
  signature_valid?: boolean;
  signatureValid?: boolean;
  payload?: Record<string, unknown>;
  body?: Record<string, unknown>;
  created_at?: string;
  createdAt?: string;
  delivered_at?: string;
  deliveredAt?: string;
  [key: string]: unknown;
}

interface OrganizationTemplate {
  id: string;
  name: string;
  description?: string | null;
  templateRoles?: Array<{ name: string; permissions: string[] }>;
  template_roles?: Array<{ name: string; permissions: string[] }>;
  templateScopes?: Array<{ name: string; description?: string }>;
  template_scopes?: Array<{ name: string; description?: string }>;
  isDefault?: boolean;
  is_default?: boolean;
}

interface SecurityStatus {
  admin_auth_mode: string;
  token_auth_allowed: boolean;
  rate_limit_rpm: number;
  brute_force_protection: boolean;
  enforce_https: boolean;
  warnings: string[];
}

interface EnterpriseSSOConfig {
  id: string;
  connectorId?: string;
  connector_id?: string;
  domains: string[];
  ssoProtocol?: string;
  sso_protocol?: string;
  jitProvisioning?: boolean;
  jit_provisioning?: boolean;
  orgMembershipMapping?: Record<string, string>;
  org_membership_mapping?: Record<string, string>;
  roleMapping?: Record<string, string>;
  role_mapping?: Record<string, string>;
}

interface ApplicationConsentSettings {
  user_scopes?: string[];
  organization_scopes?: string[];
  allowed_organization_ids?: string[];
  require_explicit_consent?: boolean;
  custom_data?: Record<string, unknown>;
}

type ApplicationSignInExperienceInput = Partial<Omit<ApplicationSignInExperience, 'application_id'>>;

interface OrganizationInvitation {
  id: string;
  email: string;
  role: string;
  status: string;
  token?: string;
}

interface OrganizationJitSettings {
  enabled: boolean;
  domains: string[];
}

interface ConnectorFactory {
  id: string;
  factoryId?: string;
  factory_id?: string;
  name: string;
  protocol: string;
  category: string;
  configSchema?: Record<string, unknown>;
  config_schema?: Record<string, unknown>;
  enabled: boolean;
}

interface TenantConfig {
  id: string;
  configType?: string;
  config_type?: string;
  key: string;
  value: Record<string, unknown>;
  enabled: boolean;
}

interface AuthHookRegistrationGuide {
  before_user_created: string;
  custom_access_token: string;
  protocol: 'standard-webhooks-v1';
  required_headers: string[];
  secret_format: string;
}

// ─── RLS Migration Assistant types ──────────────────────
export interface ExistingPolicy {
  schemaname: string;
  tablename: string;
  policyname: string;
  policytype: 'permissive' | 'restrictive';
  cmd: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'ALL';
  qual: string | null;
  with_check: string | null;
  roles: string[];
}

export interface WrapperPolicy {
  original_policy: string;
  wrapper_policy_name: string;
  tablename: string;
  schemaname: string;
  cmd: string;
  original_using: string | null;
  original_with_check: string | null;
  wrapper_using: string | null;
  wrapper_with_check: string | null;
  sql: string;
  permission_name: string;
}

export interface MigrationResult {
  scanned_policies: number;
  candidate_policies: number;
  wrappers: WrapperPolicy[];
  migration_sql: string;
  warnings: string[];
}

export type AuthorizationOperation = 'read' | 'create' | 'update' | 'delete' | 'manage';

export interface AuthorizationCompileRequest {
  tables?: Array<{
    schema?: string;
    table: string;
    permission_prefix?: string;
    operations?: AuthorizationOperation[];
    owner_column?: string;
    organization_column?: string;
  }>;
  storage_buckets?: Array<{
    bucket_id: string;
    permission_prefix?: string;
    owner_path_prefix?: string;
    organization_path_prefix?: string;
    operations?: AuthorizationOperation[];
  }>;
  realtime_channels?: Array<{
    topic: string;
    permission: string;
    organization_claim?: string;
  }>;
  edge_functions?: Array<{
    name: string;
    permission: string;
    require_organization?: boolean;
  }>;
  include_helper_sql?: boolean;
}

export interface AuthorizationCompileResult {
  generated_at: string;
  assumptions: string[];
  warnings: string[];
  permissions: string[];
  sql: {
    helpers: string;
    tables: string;
    storage: string;
    realtime: string;
    rollback: string;
  };
  edge_functions: Array<{
    name: string;
    permission: string;
    middleware: string;
    negative_tests: string[];
  }>;
  negative_tests: string[];
  deploy_checklist: string[];
}

// ─── Error class ─────────────────────────────────────────
export class SupaOAuthAPIError extends Error {
  status: number;
  body: string;
  path: string;

  constructor(status: number, body: string, path: string) {
    super(`SupaOAuth API ${status}: ${body}`);
    this.name = 'SupaOAuthAPIError';
    this.status = status;
    this.body = body;
    this.path = path;
  }
}

function pathSegment(value: string): string {
  if (value.length === 0 || value === '.' || value === '..') {
    throw new TypeError('Path segments must be non-empty and cannot be "." or "..".');
  }
  return encodeURIComponent(value);
}

function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '' || value === 0) continue;
    search.set(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
}

// ─── Client ──────────────────────────────────────────────
export class SupaOAuthClient {
  private baseUrl: string;
  private accessToken: string | null = null;

  constructor(options: { baseUrl: string; accessToken?: string }) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    if (options.accessToken) this.accessToken = options.accessToken;
  }

  /** Set or update the access token (e.g. after login) */
  setAccessToken(token: string | null) {
    this.accessToken = token;
  }

  private requestHeaders(options: RequestInit): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }
    return headers;
  }

  private async response(path: string, options: RequestInit = {}): Promise<Response> {
    const res = await fetch(`${this.baseUrl}${path}`, { ...options, headers: this.requestHeaders(options) });
    if (!res.ok) {
      const body = await res.text();
      throw new SupaOAuthAPIError(res.status, body, path);
    }
    return res;
  }

  private async request<T = unknown>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await this.response(path, options);
    if (res.status === 204) return null as T;
    return res.json() as Promise<T>;
  }

  private async requestBlob(path: string): Promise<Blob> {
    return (await this.response(path)).blob();
  }

  // ─── Health / Project ─────────────────────────────────
  health() {
    return this.request<HealthResponse>('/v1/health');
  }

  getProject() {
    return this.request<ProjectResponse>('/v1/project');
  }

  getCapabilities() {
    return this.request<CapabilitiesResponse>('/v1/capabilities');
  }

  // ─── Runtime ──────────────────────────────────────────
  getRuntimeHealth() {
    return this.request<{ status: string }>('/v1/runtime/health');
  }

  getOAuthServerStatus() {
    return this.request<OAuthServerStatus>('/v1/runtime/oauth-server');
  }

  getDiscovery() {
    return this.request<DiscoveryResponse>('/v1/runtime/discovery');
  }

  getJWKS() {
    return this.request<JWKSResponse>('/v1/runtime/jwks');
  }

  // ─── Applications ──────────────────────────────────────
  listApplications() {
    return this.request<ListResponse<OAuthApplication>>('/v1/applications');
  }

  createApplication(data: CreateApplicationInput) {
    return this.request<Application>('/v1/applications', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getApplication(appId: string) {
    return this.request<Application>(`/v1/applications/${pathSegment(appId)}`);
  }

  updateApplication(appId: string, data: Partial<CreateApplicationInput>) {
    return this.request<Application>(`/v1/applications/${pathSegment(appId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteApplication(appId: string) {
    return this.request<void>(`/v1/applications/${pathSegment(appId)}`, { method: 'DELETE' });
  }

  rotateApplicationSecret(appId: string) {
    return this.request<Application & { client_secret: string }>(
      `/v1/applications/${pathSegment(appId)}/rotate-secret`,
      { method: 'POST' },
    );
  }

  getApplicationConsentSettings(appId: string) {
    return this.request<ApplicationConsentSettings>(`/v1/applications/${pathSegment(appId)}/consent`);
  }

  updateApplicationConsentSettings(appId: string, data: ApplicationConsentSettings) {
    return this.request<ApplicationConsentSettings>(`/v1/applications/${pathSegment(appId)}/consent`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  getApplicationSignInExperience(appId: string) {
    return this.request<ApplicationSignInExperience>(`/v1/applications/${pathSegment(appId)}/sign-in-experience`);
  }

  updateApplicationSignInExperience(appId: string, data: ApplicationSignInExperienceInput) {
    return this.request<ApplicationSignInExperience>(`/v1/applications/${pathSegment(appId)}/sign-in-experience`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteApplicationSignInExperience(appId: string) {
    return this.request<void>(`/v1/applications/${pathSegment(appId)}/sign-in-experience`, { method: 'DELETE' });
  }

  // ─── Application bindings ──────────────────────────────
  listApplicationBindings(appId: string) {
    return this.request<ListResponse<ApplicationBinding>>(`/v1/applications/${pathSegment(appId)}/bindings`);
  }

  createApplicationBinding(appId: string, data: { resource_id: string; scope_id?: string }) {
    return this.request<ApplicationBinding>(`/v1/applications/${pathSegment(appId)}/bindings`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  deleteApplicationBinding(appId: string, bindingId: string) {
    return this.request<void>(`/v1/applications/${pathSegment(appId)}/bindings/${pathSegment(bindingId)}`, { method: 'DELETE' });
  }

  listApplicationScopes(appId: string) {
    return this.request<ListResponse<Scope>>(`/v1/applications/${pathSegment(appId)}/scopes`);
  }

  listApplicationRoles(appId: string) {
    return this.request<ListResponse<RoleAssignment>>(`/v1/applications/${pathSegment(appId)}/roles`);
  }

  listApplicationLogs(appId: string, params: { limit?: number; cursor?: string } = {}) {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.cursor) query.set('cursor', params.cursor);
    return this.request<CursorListResponse<AuditLogEntry>>(`/v1/applications/${pathSegment(appId)}/logs${query.toString() ? `?${query}` : ''}`);
  }

  listApplicationOrganizations(appId: string) {
    return this.request<ListResponse<Organization>>(`/v1/applications/${pathSegment(appId)}/organizations`);
  }

  getApplicationAccessControl(appId: string) {
    return this.request<ApplicationConsentSettings>(`/v1/applications/${pathSegment(appId)}/access-control`);
  }

  updateApplicationAccessControl(appId: string, data: ApplicationConsentSettings) {
    return this.request<ApplicationConsentSettings>(`/v1/applications/${pathSegment(appId)}/access-control`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // ─── Connectors ───────────────────────────────────────
  listConnectors() {
    return this.request<unknown[]>('/v1/connectors');
  }

  getConnector(connectorId: string) {
    return this.request<Connector>(`/v1/connectors/${pathSegment(connectorId)}`);
  }

  updateConnector(connectorId: string, data: Partial<Connector>) {
    return this.request<Connector>(`/v1/connectors/${pathSegment(connectorId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  testConnector(connectorId: string) {
    return this.request<{ connector_id: string; status: string }>(
      `/v1/connectors/${pathSegment(connectorId)}/test`,
      { method: 'POST' },
    );
  }

  getConnectorAuthorizationUri(connectorId: string, params?: { redirect_uri?: string; state?: string; scope?: string }) {
    const qs = new URLSearchParams();
    if (params?.redirect_uri) qs.set('redirect_uri', params.redirect_uri);
    if (params?.state) qs.set('state', params.state);
    if (params?.scope) qs.set('scope', params.scope);
    const query = qs.toString();
    return this.request<unknown>(`/v1/connectors/${pathSegment(connectorId)}/authorization-uri${query ? `?${query}` : ''}`);
  }

  listConnectorFactories(category?: string) {
    return this.request<ListResponse<ConnectorFactory>>(`/v1/connectors/factories${queryString({ category })}`);
  }

  upsertConnectorFactory(factoryId: string, data: {
    name: string;
    protocol: string;
    category: string;
    config_schema?: Record<string, unknown>;
    enabled?: boolean;
  }) {
    return this.request<ConnectorFactory>(`/v1/connectors/factories/${pathSegment(factoryId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // ─── API Resources ────────────────────────────────────
  listResources() {
    return this.request<ListResponse<ApiResource>>('/v1/resources');
  }

  createResource(data: CreateResourceInput) {
    return this.request<ApiResource>('/v1/resources', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getResource(resourceId: string) {
    return this.request<ApiResource>(`/v1/resources/${pathSegment(resourceId)}`);
  }

  updateResource(resourceId: string, data: Partial<CreateResourceInput>) {
    return this.request<ApiResource>(`/v1/resources/${pathSegment(resourceId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteResource(resourceId: string) {
    return this.request<void>(`/v1/resources/${pathSegment(resourceId)}`, { method: 'DELETE' });
  }

  // ─── Scopes ───────────────────────────────────────────
  addScope(resourceId: string, data: { name: string; description?: string }) {
    return this.request<Scope>(`/v1/resources/${pathSegment(resourceId)}/scopes`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  updateScope(resourceId: string, scopeId: string, data: { name?: string; description?: string }) {
    return this.request<Scope>(`/v1/resources/${pathSegment(resourceId)}/scopes/${pathSegment(scopeId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  removeScope(resourceId: string, scopeId: string) {
    return this.request<void>(`/v1/resources/${pathSegment(resourceId)}/scopes/${pathSegment(scopeId)}`, { method: 'DELETE' });
  }

  listResourceApplications(resourceId: string) {
    return this.request<ListResponse<ApplicationBinding>>(`/v1/resources/${pathSegment(resourceId)}/applications`);
  }

  // ─── Users ────────────────────────────────────────────
  listUsers(params: { page?: number; limit?: number; search?: string; email?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', String(params.page));
    if (params.limit) query.set('limit', String(params.limit));
    if (params.search) query.set('search', params.search);
    if (params.email) query.set('email', params.email);
    return this.request<ListResponse<unknown>>(`/v1/users${query.toString() ? `?${query}` : ''}`);
  }

  createUser(data: {
    email?: string;
    phone?: string;
    password?: string;
    email_confirm?: boolean;
    phone_confirm?: boolean;
    user_metadata?: Record<string, unknown>;
  }) {
    return this.request<unknown>('/v1/users', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getUser(userId: string) {
    return this.request<unknown>(`/v1/users/${pathSegment(userId)}`);
  }

  updateUser(userId: string, data: Record<string, unknown>) {
    return this.request<unknown>(`/v1/users/${pathSegment(userId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  suspendUser(userId: string, data: Record<string, unknown> = {}) {
    return this.request<unknown>(`/v1/users/${pathSegment(userId)}/suspend`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  deleteUser(userId: string) {
    return this.request<void>(`/v1/users/${pathSegment(userId)}`, { method: 'DELETE' });
  }

  resetUserMfa(userId: string, factorId: string) {
    return this.request<unknown>(`/v1/users/${pathSegment(userId)}/mfa/${pathSegment(factorId)}/reset`, { method: 'POST' });
  }

  listUserLogs(userId: string, params: { limit?: number; cursor?: string } = {}) {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.cursor) query.set('cursor', params.cursor);
    return this.request<CursorListResponse<AuditLogEntry>>(`/v1/users/${pathSegment(userId)}/logs${query.toString() ? `?${query}` : ''}`);
  }

  listUserOrganizations(userId: string) {
    return this.request<ListResponse<Organization>>(`/v1/users/${pathSegment(userId)}/organizations`);
  }

  getUserPermissions(userId: string, orgId?: string) {
    return this.request<UserPermissions>(`/v1/users/${pathSegment(userId)}/permissions${queryString({ org_id: orgId })}`);
  }

  getUserRoles(userId: string) {
    return this.request<ListResponse<RoleAssignment>>(`/v1/users/${pathSegment(userId)}/roles`);
  }

  // ─── Organizations ────────────────────────────────────
  listOrganizations(params: { page?: number; limit?: number; search?: string; application_id?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', String(params.page));
    if (params.limit) query.set('limit', String(params.limit));
    if (params.search) query.set('search', params.search);
    if (params.application_id) query.set('application_id', params.application_id);
    return this.request<ListResponse<Organization>>(`/v1/organizations${query.toString() ? `?${query}` : ''}`);
  }

  createOrganization(data: { name: string; description?: string }) {
    return this.request<Organization>('/v1/organizations', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getOrganization(orgId: string) {
    return this.request<Organization>(`/v1/organizations/${pathSegment(orgId)}`);
  }

  updateOrganization(orgId: string, data: { name?: string; description?: string }) {
    return this.request<Organization>(`/v1/organizations/${pathSegment(orgId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteOrganization(orgId: string) {
    return this.request<void>(`/v1/organizations/${pathSegment(orgId)}`, { method: 'DELETE' });
  }

  addOrganizationMember(orgId: string, data: { user_id: string; role?: string }) {
    return this.request<OrganizationMember>(`/v1/organizations/${pathSegment(orgId)}/members`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  listOrganizationMembers(orgId: string, params: { page?: number; limit?: number; search?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', String(params.page));
    if (params.limit) query.set('limit', String(params.limit));
    if (params.search) query.set('search', params.search);
    return this.request<ListResponse<OrganizationMember>>(`/v1/organizations/${pathSegment(orgId)}/members${query.toString() ? `?${query}` : ''}`);
  }

  removeOrganizationMember(orgId: string, userId: string) {
    return this.request<void>(`/v1/organizations/${pathSegment(orgId)}/members/${pathSegment(userId)}`, { method: 'DELETE' });
  }

  updateOrganizationMemberRole(orgId: string, userId: string, data: { role: string }) {
    return this.request<OrganizationMember>(`/v1/organizations/${pathSegment(orgId)}/members/${pathSegment(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  listOrganizationInvitations(orgId: string) {
    return this.request<ListResponse<OrganizationInvitation>>(`/v1/organizations/${pathSegment(orgId)}/invitations`);
  }

  createOrganizationInvitation(orgId: string, data: { email: string; role?: string; ttl_hours?: number }) {
    return this.request<OrganizationInvitation>(`/v1/organizations/${pathSegment(orgId)}/invitations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  acceptOrganizationInvitation(orgId: string, invitationId: string, data: { token: string }) {
    return this.request<OrganizationInvitation>(`/v1/organizations/${pathSegment(orgId)}/invitations/${pathSegment(invitationId)}/accept`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  revokeOrganizationInvitation(orgId: string, invitationId: string) {
    return this.request<OrganizationInvitation>(`/v1/organizations/${pathSegment(orgId)}/invitations/${pathSegment(invitationId)}`, { method: 'DELETE' });
  }

  getOrganizationJitSettings(orgId: string) {
    return this.request<OrganizationJitSettings>(`/v1/organizations/${pathSegment(orgId)}/jit`);
  }

  updateOrganizationJitSettings(orgId: string, data: OrganizationJitSettings) {
    return this.request<OrganizationJitSettings>(`/v1/organizations/${pathSegment(orgId)}/jit`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  listOrganizationApplications(orgId: string) {
    return this.request<ListResponse<unknown>>(`/v1/organizations/${pathSegment(orgId)}/applications`);
  }

  bindOrganizationApplication(orgId: string, appId: string) {
    return this.request<unknown>(`/v1/organizations/${pathSegment(orgId)}/applications/${pathSegment(appId)}`, {
      method: 'PUT',
      body: '{}',
    });
  }

  removeOrganizationApplication(orgId: string, appId: string) {
    return this.request<unknown>(`/v1/organizations/${pathSegment(orgId)}/applications/${pathSegment(appId)}`, { method: 'DELETE' });
  }

  getOrganizationBranding(orgId: string) {
    return this.request<Record<string, unknown>>(`/v1/organizations/${pathSegment(orgId)}/branding`);
  }

  updateOrganizationBranding(orgId: string, data: Record<string, unknown>) {
    return this.request<Record<string, unknown>>(`/v1/organizations/${pathSegment(orgId)}/branding`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // ─── Roles ────────────────────────────────────────────
  listRoles() {
    return this.request<ListResponse<Role>>('/v1/roles');
  }

  createRole(data: { name: string; description?: string }) {
    return this.request<Role>('/v1/roles', { method: 'POST', body: JSON.stringify(data) });
  }

  getRole(roleId: string) {
    return this.request<Role>(`/v1/roles/${pathSegment(roleId)}`);
  }

  updateRole(roleId: string, data: { name?: string; description?: string }) {
    return this.request<Role>(`/v1/roles/${pathSegment(roleId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteRole(roleId: string) {
    return this.request<void>(`/v1/roles/${pathSegment(roleId)}`, { method: 'DELETE' });
  }

  // ─── Permissions ──────────────────────────────────────
  listRolePermissions(roleId: string) {
    return this.request<ListResponse<Permission>>(`/v1/roles/${pathSegment(roleId)}/permissions`);
  }

  createRolePermission(
    roleId: string,
    data: { name: string; description?: string; scope_id?: string },
  ) {
    return this.request<Permission>(`/v1/roles/${pathSegment(roleId)}/permissions`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  deleteRolePermission(roleId: string, permissionId: string) {
    return this.request<void>(`/v1/roles/${pathSegment(roleId)}/permissions/${pathSegment(permissionId)}`, {
      method: 'DELETE',
    });
  }

  // ─── Role assignments ─────────────────────────────────
  assignRole(
    roleId: string,
    data: { user_id?: string; organization_id?: string; application_id?: string },
  ) {
    return this.request<RoleAssignment>(`/v1/roles/${pathSegment(roleId)}/assign`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  listRoleAssignments(roleId: string) {
    return this.request<ListResponse<RoleAssignment>>(`/v1/roles/${pathSegment(roleId)}/assign`);
  }

  revokeRole(roleId: string, assignmentId: string) {
    return this.request<void>(`/v1/roles/${pathSegment(roleId)}/assign/${pathSegment(assignmentId)}`, {
      method: 'DELETE',
    });
  }

  getOrgRoleAssignments(orgId: string) {
    return this.request<ListResponse<RoleAssignment>>(`/v1/organizations/${pathSegment(orgId)}/roles`);
  }

  // ─── Sign-in Experience ───────────────────────────────
  getSignInExperience() {
    return this.request<SignInExperience>('/v1/sign-in-experience');
  }

  resolveSignInExperience(applicationId?: string) {
    return this.request<EffectiveSignInExperience>(`/v1/sign-in-experience/resolve${queryString({ application_id: applicationId })}`);
  }

  resolvePublicSignInExperience(params: { application_id?: string; authorization_id?: string } = {}) {
    const qs = new URLSearchParams();
    if (params.application_id) qs.set('application_id', params.application_id);
    if (params.authorization_id) qs.set('authorization_id', params.authorization_id);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return this.request<PublicEffectiveSignInExperience>(`/v1/public/sign-in-experience/resolve${suffix}`);
  }

  getPublicPhrases(languageTag: string) {
    return this.request<PublicPhraseBundle>(`/v1/public/phrases/${pathSegment(languageTag)}`);
  }

  updateSignInExperience(data: Partial<SignInExperience>) {
    return this.request<SignInExperience>('/v1/sign-in-experience', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  // ─── Auth Config ──────────────────────────────────────
  getAuthConfig() {
    return this.request<AuthConfigResponse>('/v1/auth-config');
  }

  updateAuthConfig(data: Partial<AuthConfigResponse>) {
    return this.request<AuthConfigResponse>('/v1/auth-config', {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  // ─── Compatibility ────────────────────────────────────
  getCompatibilityReport() {
    return this.request<{ checks: CompatibilityCheckResult[]; total: number; passed: number }>('/v1/compatibility/supabase');
  }

  // ─── Tenant Config ────────────────────────────────────
  listTenantConfigs(type?: string) {
    return this.request<ListResponse<TenantConfig>>(`/v1/tenant-config${queryString({ type })}`);
  }

  getTenantConfig(type: string, key: string) {
    return this.request<TenantConfig>(`/v1/tenant-config/${pathSegment(type)}/${pathSegment(key)}`);
  }

  upsertTenantConfig(type: string, key: string, data: { value?: Record<string, unknown>; enabled?: boolean }) {
    return this.request<TenantConfig>(`/v1/tenant-config/${pathSegment(type)}/${pathSegment(key)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteTenantConfig(type: string, key: string) {
    return this.request<TenantConfig>(`/v1/tenant-config/${pathSegment(type)}/${pathSegment(key)}`, {
      method: 'DELETE',
    });
  }

  checkTenantDomain(domain: string) {
    return this.request<unknown>(`/v1/tenant-config/domain/${pathSegment(domain)}/check`, { method: 'POST' });
  }

  // ─── Auth Hooks ───────────────────────────────────────
  getAuthHookRegistrationGuide() {
    return this.request<AuthHookRegistrationGuide>('/v1/auth-hooks/registration-guide');
  }

  getAuthHookStatus() {
    return this.request<Record<string, unknown>>('/v1/auth-hooks/custom-access-token/status');
  }

  verifyAuthHook() {
    return this.request<Record<string, unknown>>('/v1/auth-hooks/custom-access-token/verify', { method: 'POST' });
  }

  getBeforeUserCreatedHookStatus() {
    return this.request<Record<string, unknown>>('/v1/auth-hooks/before-user-created/status');
  }

  verifyBeforeUserCreatedHook() {
    return this.request<Record<string, unknown>>('/v1/auth-hooks/before-user-created/verify', { method: 'POST' });
  }

  listTenantMembers(params: { page?: number; limit?: number; search?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', String(params.page));
    if (params.limit) query.set('limit', String(params.limit));
    if (params.search) query.set('search', params.search);
    return this.request<ListResponse<Record<string, unknown>>>(`/v1/tenant/members${query.toString() ? `?${query}` : ''}`);
  }

  updateTenantMember(memberId: string, data: Record<string, unknown>) {
    return this.request<Record<string, unknown>>(`/v1/tenant/members/${pathSegment(memberId)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  removeTenantMember(memberId: string) {
    return this.request<void>(`/v1/tenant/members/${pathSegment(memberId)}`, { method: 'DELETE' });
  }

  listTenantInvitations(params: { page?: number; limit?: number; status?: string } = {}) {
    const query = new URLSearchParams();
    if (params.page) query.set('page', String(params.page));
    if (params.limit) query.set('limit', String(params.limit));
    if (params.status) query.set('status', params.status);
    return this.request<ListResponse<Record<string, unknown>>>(`/v1/tenant/invitations${query.toString() ? `?${query}` : ''}`);
  }

  createTenantInvitation(data: Record<string, unknown>) {
    return this.request<Record<string, unknown>>('/v1/tenant/invitations', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // ─── Webhooks ─────────────────────────────────────────
  listWebhooks() {
    return this.request<ListResponse<Webhook>>('/v1/webhooks');
  }

  createWebhook(data: { url: string; events: string[]; enabled?: boolean }) {
    return this.request<Webhook>('/v1/webhooks', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getWebhook(webhookId: string) {
    return this.request<Webhook>(`/v1/webhooks/${pathSegment(webhookId)}`);
  }

  updateWebhook(webhookId: string, data: Partial<{ url: string; events: string[]; enabled: boolean }>) {
    return this.request<Webhook>(`/v1/webhooks/${pathSegment(webhookId)}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  deleteWebhook(webhookId: string) {
    return this.request<void>(`/v1/webhooks/${pathSegment(webhookId)}`, { method: 'DELETE' });
  }

  rotateWebhookSecret(webhookId: string) {
    return this.request<Webhook>(`/v1/webhooks/${pathSegment(webhookId)}/rotate-secret`, {
      method: 'POST',
    });
  }

  listWebhookLogs(webhookId: string, limit?: number) {
    return this.request<ListResponse<WebhookDeliveryLog>>(`/v1/webhooks/${pathSegment(webhookId)}/logs${queryString({ limit })}`);
  }

  testWebhook(webhookId: string) {
    return this.request<{ ok: boolean; status?: number; error?: string }>(`/v1/webhooks/${pathSegment(webhookId)}/test`, {
      method: 'POST',
      body: '{}',
    });
  }

  listWebhookEvents() {
    return this.request<WebhookEventList>('/v1/webhooks/events');
  }

  listWebhookDeliveries(webhookId: string, params: { limit?: number; cursor?: string; status?: string } = {}) {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.cursor) query.set('cursor', params.cursor);
    if (params.status) query.set('status', params.status);
    return this.request<CursorListResponse<WebhookDeliveryLog>>(`/v1/webhooks/${pathSegment(webhookId)}/deliveries${query.toString() ? `?${query}` : ''}`);
  }

  getWebhookDelivery(webhookId: string, deliveryId: string) {
    return this.request<WebhookDeliveryLog>(`/v1/webhooks/${pathSegment(webhookId)}/deliveries/${pathSegment(deliveryId)}`);
  }

  replayWebhookDelivery(webhookId: string, deliveryId: string) {
    return this.request<WebhookDeliveryLog>(`/v1/webhooks/${pathSegment(webhookId)}/deliveries/${pathSegment(deliveryId)}/replay`, {
      method: 'POST',
    });
  }

  // ─── Metadata sync ────────────────────────────────────
  syncUserMetadata(userId: string, orgId?: string) {
    return this.request<SyncResult>(`/v1/sync/user/${pathSegment(userId)}${queryString({ org_id: orgId })}`, { method: 'POST' });
  }

  syncOrgMetadata(orgId: string) {
    return this.request<{ results: SyncResult[]; total: number; failed: number }>(
      `/v1/sync/org/${pathSegment(orgId)}`,
      { method: 'POST' },
    );
  }

  // ─── Audit ────────────────────────────────────────────
  listAuditLogs(params?: {
    event_type?: string;
    resource_type?: string;
    resource_id?: string;
    actor_id?: string;
    status?: number;
    method?: string;
    limit?: number;
    offset?: number;
    from?: string;
    to?: string;
    cursor?: string;
  }) {
    const qs = new URLSearchParams();
    if (params?.event_type) qs.set('event_type', params.event_type);
    if (params?.resource_type) qs.set('resource_type', params.resource_type);
    if (params?.resource_id) qs.set('resource_id', params.resource_id);
    if (params?.actor_id) qs.set('actor_id', params.actor_id);
    if (params?.status) qs.set('status', String(params.status));
    if (params?.method) qs.set('method', params.method);
    if (params?.limit) qs.set('limit', String(params.limit));
    if (params?.offset) qs.set('offset', String(params.offset));
    if (params?.from) qs.set('from', params.from);
    if (params?.to) qs.set('to', params.to);
    if (params?.cursor) qs.set('cursor', params.cursor);
    const query = qs.toString();
    return this.request<CursorListResponse<AuditLogEntry>>(`/v1/audit${query ? `?${query}` : ''}`);
  }

  getAuditLog(logId: string) {
    return this.request<AuditLogEntry>(`/v1/audit/${pathSegment(logId)}`);
  }

  createAuditExport(params: Record<string, unknown> = {}) {
    return this.request<Record<string, unknown>>('/v1/audit/export', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  getAuditExport(exportId: string) {
    return this.request<Record<string, unknown>>(`/v1/audit/export/${pathSegment(exportId)}`);
  }

  getAuditExportDownload(exportId: string) {
    return this.requestBlob(`/v1/audit/export/${pathSegment(exportId)}/download`);
  }

  getAuditIntegrity() {
    return this.request<Record<string, unknown>>('/v1/audit/integrity');
  }

  // ─── RLS Migration Assistant ──────────────────────────
  compileAuthorizationPlan(data: AuthorizationCompileRequest) {
    return this.request<AuthorizationCompileResult>('/v1/admin-tools/authorization-compiler', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  getAuthorizationCompilerDemo() {
    return this.request<AuthorizationCompileResult>('/v1/admin-tools/authorization-compiler/demo');
  }

  generateRLSMigration(policies: ExistingPolicy[]) {
    return this.request<MigrationResult>('/v1/admin-tools/rls-migration', {
      method: 'POST',
      body: JSON.stringify({ policies }),
    });
  }

  getRLSMigrationDemo() {
    return this.request<MigrationResult>('/v1/admin-tools/rls-migration/demo');
  }

  // ─── Organization templates ───────────────────────────
  listOrgTemplates() {
    return this.request<ListResponse<OrganizationTemplate>>('/v1/org-templates');
  }

  createOrgTemplate(data: {
    name: string;
    description?: string;
    template_roles?: Array<{ name: string; permissions: string[] }>;
    template_scopes?: Array<{ name: string; description?: string }>;
    is_default?: boolean;
  }) {
    return this.request<OrganizationTemplate>('/v1/org-templates', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  instantiateOrgTemplate(
    templateId: string,
    data: { name: string; description?: string; creator_user_id: string },
    idempotencyKey = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`,
  ) {
    return this.request<unknown>(`/v1/org-templates/${pathSegment(templateId)}/instantiate`, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(data),
    });
  }

  // ─── Security and provisioning ────────────────────────
  getSecurityStatus() {
    return this.request<SecurityStatus>('/v1/security-config/status');
  }

  getProvisioningStatus(projectRef: string) {
    return this.request<unknown>(`/v1/provisioning/${pathSegment(projectRef)}`);
  }

  reconcileProject(projectRef: string) {
    return this.request<unknown>(`/v1/provisioning/${pathSegment(projectRef)}/reconcile`, { method: 'POST' });
  }

  // ─── Enterprise SSO ───────────────────────────────────
  listEnterpriseSSOConfigs() {
    return this.request<ListResponse<EnterpriseSSOConfig>>('/v1/enterprise-sso');
  }

  createEnterpriseSSOConfig(data: {
    connector_id: string;
    domains: string[];
    sso_protocol?: string;
    jit_provisioning?: boolean;
    org_membership_mapping?: Record<string, string>;
    role_mapping?: Record<string, string>;
  }) {
    return this.request<EnterpriseSSOConfig>('/v1/enterprise-sso', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }
}
