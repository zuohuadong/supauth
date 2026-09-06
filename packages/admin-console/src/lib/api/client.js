// SupaOAuth API client — all management calls go through the auth-server BFF.
// No SupaCloud master token or service-role key is exposed to the browser.

import { adminApiBlob, adminApiRequest } from "../admin-api.js";

async function request(path, options = {}) {
  return adminApiRequest(path, options);
}

function queryString(params) {
  const query = new URLSearchParams();
  for (const [key, rawValue] of Object.entries(params)) {
    if (
      rawValue !== undefined &&
      rawValue !== null &&
      String(rawValue).trim() !== ""
    ) {
      query.set(key, String(rawValue).trim());
    }
  }
  return query.size ? `?${query}` : "";
}

function pathSegment(identifier) {
  return encodeURIComponent(String(identifier));
}

function pathSegments(path) {
  return String(path).split("/").map(pathSegment).join("/");
}

// Dashboard / Runtime status
export function getOAuthServerStatus() {
  return request("/v1/runtime/oauth-server");
}

export function getProject() {
  return request("/v1/project");
}

export function getDiscovery() {
  return request("/v1/runtime/discovery");
}

export function getJWKS() {
  return request("/v1/runtime/jwks");
}

export function getCapabilities() {
  return request("/v1/capabilities");
}

// Applications
export function listApplications() {
  return request("/v1/applications");
}

export function createApplication(data) {
  return request("/v1/applications", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getApplication(appId) {
  return request(`/v1/applications/${pathSegment(appId)}`);
}

export function updateApplication(appId, data) {
  return request(`/v1/applications/${pathSegment(appId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteApplication(appId) {
  return request(`/v1/applications/${pathSegment(appId)}`, {
    method: "DELETE",
  });
}

export function rotateApplicationSecret(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/rotate-secret`, {
    method: "POST",
  });
}

export function getApplicationConsent(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/consent`);
}

export function updateApplicationConsent(appId, data) {
  return request(`/v1/applications/${pathSegment(appId)}/consent`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function getApplicationSignInExperience(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/sign-in-experience`);
}

export function updateApplicationSignInExperience(appId, data) {
  return request(`/v1/applications/${pathSegment(appId)}/sign-in-experience`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteApplicationSignInExperience(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/sign-in-experience`, {
    method: "DELETE",
  });
}

// Application-Resource/Scope bindings
export function listApplicationBindings(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/bindings`);
}

export function createApplicationBinding(appId, data) {
  return request(`/v1/applications/${pathSegment(appId)}/bindings`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function deleteApplicationBinding(appId, bindingId) {
  return request(
    `/v1/applications/${pathSegment(appId)}/bindings/${pathSegment(bindingId)}`,
    {
      method: "DELETE",
    },
  );
}

export function listApplicationScopes(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/scopes`);
}

export function listApplicationRoles(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/roles`);
}

export function listApplicationLogs(appId, params = {}) {
  return request(
    `/v1/applications/${pathSegment(appId)}/logs${queryString(params)}`,
  );
}

export function listApplicationOrganizations(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/organizations`);
}

export function getApplicationAccessControl(appId) {
  return request(`/v1/applications/${pathSegment(appId)}/access-control`);
}

export function updateApplicationAccessControl(appId, data) {
  return request(`/v1/applications/${pathSegment(appId)}/access-control`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

// Connectors
export function listConnectors() {
  return request("/v1/connectors");
}

export function getConnector(connectorId) {
  return request(`/v1/connectors/${pathSegment(connectorId)}`);
}

export function updateConnector(connectorId, data) {
  return request(`/v1/connectors/${pathSegment(connectorId)}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function testConnector(connectorId) {
  return request(`/v1/connectors/${pathSegment(connectorId)}/test`, {
    method: "POST",
  });
}

export function listConnectorFactories(category) {
  const qs = category ? `?category=${encodeURIComponent(category)}` : "";
  return request(`/v1/connectors/factories${qs}`);
}

export function upsertConnectorFactory(factoryId, data) {
  return request(`/v1/connectors/factories/${pathSegment(factoryId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function createConnectorFromFactory(factoryId, data) {
  return request(`/v1/connectors/from-factory/${pathSegment(factoryId)}`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

// API Resources
export function listResources() {
  return request("/v1/resources");
}

export function createResource(data) {
  return request("/v1/resources", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getResource(resourceId) {
  return request(`/v1/resources/${pathSegment(resourceId)}`);
}

export function updateResource(resourceId, data) {
  return request(`/v1/resources/${pathSegment(resourceId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteResource(resourceId) {
  return request(`/v1/resources/${pathSegment(resourceId)}`, {
    method: "DELETE",
  });
}

export function createResourceScope(resourceId, data) {
  return request(`/v1/resources/${pathSegment(resourceId)}/scopes`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateResourceScope(resourceId, scopeId, data) {
  return request(
    `/v1/resources/${pathSegment(resourceId)}/scopes/${pathSegment(scopeId)}`,
    {
      method: "PUT",
      body: JSON.stringify(data),
    },
  );
}

export function deleteResourceScope(resourceId, scopeId) {
  return request(
    `/v1/resources/${pathSegment(resourceId)}/scopes/${pathSegment(scopeId)}`,
    { method: "DELETE" },
  );
}

export function listResourceApplications(resourceId) {
  return request(`/v1/resources/${pathSegment(resourceId)}/applications`);
}

// Users
export function listUsers(params = {}) {
  return request(`/v1/users${queryString(params)}`);
}

export function createUser(data) {
  return request("/v1/users", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getUser(userId) {
  return request(`/v1/users/${pathSegment(userId)}`);
}

export function updateUser(userId, data) {
  return request(`/v1/users/${pathSegment(userId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function suspendUser(userId, data = {}) {
  return request(`/v1/users/${pathSegment(userId)}/suspend`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function unsuspendUser(userId) {
  return request(`/v1/users/${pathSegment(userId)}/unsuspend`, {
    method: "POST",
  });
}

export function deleteUser(userId) {
  return request(`/v1/users/${pathSegment(userId)}`, {
    method: "DELETE",
  });
}

export function getUserPermissions(userId, orgId, applicationId) {
  const qs = queryString({
    org_id: orgId,
    application_id: applicationId,
  });
  return request(`/v1/users/${pathSegment(userId)}/permissions${qs}`);
}

export function getUserRoles(userId, applicationId) {
  const qs = queryString({ application_id: applicationId });
  return request(`/v1/users/${pathSegment(userId)}/roles${qs}`);
}

export function resetUserMfa(userId, factorId) {
  return request(
    `/v1/users/${pathSegment(userId)}/mfa/${pathSegment(factorId)}/reset`,
    { method: "POST" },
  );
}

export function listUserLogs(userId, params = {}) {
  return request(`/v1/users/${pathSegment(userId)}/logs${queryString(params)}`);
}

export function listUserOrganizations(userId) {
  return request(`/v1/users/${pathSegment(userId)}/organizations`);
}

export function listUserGrants(userId) {
  return request(`/v1/users/${pathSegment(userId)}/grants`);
}

// Organizations
export function listOrganizations(params = {}) {
  return request(`/v1/organizations${queryString(params)}`);
}

export function createOrganization(data) {
  return request("/v1/organizations", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getOrganization(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}`);
}

export function updateOrganization(orgId, data) {
  return request(`/v1/organizations/${pathSegment(orgId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteOrganization(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}`, {
    method: "DELETE",
  });
}

export function listOrganizationInvitations(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}/invitations`);
}

export function createOrganizationInvitation(orgId, data) {
  return request(`/v1/organizations/${pathSegment(orgId)}/invitations`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateOrganizationInvitationStatus(
  orgId,
  invitationId,
  action,
) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/invitations/${pathSegment(invitationId)}/${pathSegment(action)}`,
    { method: "POST" },
  );
}

export function getOrganizationJit(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}/jit`);
}

export function updateOrganizationJit(orgId, data) {
  return request(`/v1/organizations/${pathSegment(orgId)}/jit`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function listOrganizationApplications(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}/applications`);
}

export function upsertOrganizationApplication(orgId, appId) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/applications/${pathSegment(appId)}`,
    {
      method: "PUT",
    },
  );
}

export function deleteOrganizationApplication(orgId, appId) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/applications/${pathSegment(appId)}`,
    { method: "DELETE" },
  );
}

export function listOrganizationMembers(orgId, params = {}) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/members${queryString(params)}`,
  );
}

export function addOrganizationMember(orgId, data) {
  return request(`/v1/organizations/${pathSegment(orgId)}/members`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateOrganizationMember(orgId, userId, data) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/members/${pathSegment(userId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(data),
    },
  );
}

export function removeOrganizationMember(orgId, userId) {
  return request(
    `/v1/organizations/${pathSegment(orgId)}/members/${pathSegment(userId)}`,
    { method: "DELETE" },
  );
}

export function getOrganizationBranding(orgId) {
  return request(`/v1/organizations/${pathSegment(orgId)}/branding`);
}

export function updateOrganizationBranding(orgId, data) {
  return request(`/v1/organizations/${pathSegment(orgId)}/branding`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

// Roles
export function listRoles() {
  return request("/v1/roles");
}

export function createRole(data) {
  return request("/v1/roles", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getRole(roleId) {
  return request(`/v1/roles/${pathSegment(roleId)}`);
}

export function updateRole(roleId, data) {
  return request(`/v1/roles/${pathSegment(roleId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteRole(roleId) {
  return request(`/v1/roles/${pathSegment(roleId)}`, {
    method: "DELETE",
  });
}

export function listRolePermissions(roleId) {
  return request(`/v1/roles/${pathSegment(roleId)}/permissions`);
}

export function createRolePermission(roleId, data) {
  return request(`/v1/roles/${pathSegment(roleId)}/permissions`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function deleteRolePermission(roleId, permissionId) {
  return request(
    `/v1/roles/${pathSegment(roleId)}/permissions/${pathSegment(permissionId)}`,
    {
      method: "DELETE",
    },
  );
}

export function assignRole(roleId, data) {
  return request(`/v1/roles/${pathSegment(roleId)}/assign`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function listRoleAssignments(roleId) {
  return request(`/v1/roles/${pathSegment(roleId)}/assign`);
}

export function revokeRole(roleId, assignmentId) {
  return request(
    `/v1/roles/${pathSegment(roleId)}/assign/${pathSegment(assignmentId)}`,
    {
      method: "DELETE",
    },
  );
}

// Settings / Sign-in Experience
export function getSignInExperience() {
  return request("/v1/sign-in-experience");
}

export function resolveSignInExperience(applicationId) {
  const qs = applicationId
    ? `?application_id=${encodeURIComponent(applicationId)}`
    : "";
  return request(`/v1/sign-in-experience/resolve${qs}`);
}

export function resolvePublicSignInExperience(params = {}) {
  const qs = new URLSearchParams();
  if (params.application_id) qs.set("application_id", params.application_id);
  if (params.authorization_id)
    qs.set("authorization_id", params.authorization_id);
  const suffix = qs.toString() ? `?${qs.toString()}` : "";
  return request(`/v1/public/sign-in-experience/resolve${suffix}`);
}

export function updateSignInExperience(data) {
  return request("/v1/sign-in-experience", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function getCustomUiStatus() {
  return request("/v1/sign-in-experience/custom-ui-assets");
}

export function deleteCustomUiAssets() {
  return request("/v1/sign-in-experience/custom-ui-assets", {
    method: "DELETE",
  });
}

export function getAuthConfig() {
  return request("/v1/auth-config");
}

export function getAuthConfigRuntimeConsistency() {
  return request("/v1/auth-config/runtime-consistency");
}

export function updateAuthConfig(data) {
  return request("/v1/auth-config", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

// Compatibility check
export function getCompatibilityReport() {
  return request("/v1/compatibility/supabase");
}

export function getCustomAccessTokenHookStatus() {
  return request("/v1/auth-hooks/custom-access-token/status");
}

export function getCustomAccessTokenHookConfig() {
  return request("/v1/auth-hooks/custom-access-token/config");
}

export function updateCustomAccessTokenHookConfig(hookConfig) {
  return request("/v1/auth-hooks/custom-access-token/config", {
    method: "PATCH",
    body: JSON.stringify(hookConfig),
  });
}

export function verifyCustomAccessTokenHook() {
  return request("/v1/auth-hooks/custom-access-token/verify", {
    method: "POST",
  });
}

export function getBeforeUserCreatedHookStatus() {
  return request("/v1/auth-hooks/before-user-created/status");
}

export function verifyBeforeUserCreatedHook() {
  return request("/v1/auth-hooks/before-user-created/verify", {
    method: "POST",
  });
}

// Tenant config
export function listTenantConfigs(type) {
  const qs = type ? `?type=${encodeURIComponent(type)}` : "";
  return request(`/v1/tenant-config${qs}`);
}

export function upsertTenantConfig(type, key, data) {
  return request(
    `/v1/tenant-config/${encodeURIComponent(type)}/${encodeURIComponent(key)}`,
    {
      method: "PUT",
      body: JSON.stringify(data),
    },
  );
}

export function deleteTenantConfig(type, key) {
  return request(
    `/v1/tenant-config/${encodeURIComponent(type)}/${encodeURIComponent(key)}`,
    { method: "DELETE" },
  );
}

export function checkTenantDomain(domain) {
  return request(
    `/v1/tenant-config/domain/${encodeURIComponent(domain)}/check`,
    { method: "POST" },
  );
}

// Webhooks
export function listWebhooks() {
  return request("/v1/webhooks");
}

export function createWebhook(data) {
  return request("/v1/webhooks", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function getWebhook(webhookId) {
  return request(`/v1/webhooks/${pathSegment(webhookId)}`);
}

export function updateWebhook(webhookId, data) {
  return request(`/v1/webhooks/${pathSegment(webhookId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteWebhook(webhookId) {
  return request(`/v1/webhooks/${pathSegment(webhookId)}`, {
    method: "DELETE",
  });
}

export function rotateWebhookSecret(webhookId) {
  return request(`/v1/webhooks/${pathSegment(webhookId)}/rotate-secret`, {
    method: "POST",
  });
}

export function listWebhookLogs(webhookId, limit = 50) {
  const qs = new URLSearchParams();
  if (limit) qs.set("limit", String(limit));
  return request(
    `/v1/webhooks/${pathSegment(webhookId)}/logs${qs.toString() ? `?${qs.toString()}` : ""}`,
  );
}

export function testWebhook(webhookId) {
  return request(`/v1/webhooks/${pathSegment(webhookId)}/test`, {
    method: "POST",
  });
}

export function listWebhookEvents() {
  return request("/v1/webhooks/events");
}

export function listWebhookDeliveries(webhookId, params = {}) {
  return request(
    `/v1/webhooks/${pathSegment(webhookId)}/deliveries${queryString(params)}`,
  );
}

export function getWebhookDelivery(webhookId, deliveryId) {
  return request(
    `/v1/webhooks/${pathSegment(webhookId)}/deliveries/${pathSegment(deliveryId)}`,
  );
}

export function replayWebhookDelivery(webhookId, deliveryId) {
  return request(
    `/v1/webhooks/${pathSegment(webhookId)}/deliveries/${pathSegment(deliveryId)}/replay`,
    { method: "POST" },
  );
}

export function listAuditLogs(params = {}) {
  const qs = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      qs.set(key, String(value).trim());
    }
  }
  const query = qs.toString();
  return request(`/v1/audit${query ? `?${query}` : ""}`);
}

export function getAuditLog(logId) {
  return request(`/v1/audit/${pathSegment(logId)}`);
}

export function exportAuditLogs(params = {}) {
  return request("/v1/audit/export", {
    method: "POST",
    body: JSON.stringify(params),
  });
}

export function getAuditExport(exportId) {
  return request(`/v1/audit/export/${pathSegment(exportId)}`);
}

export function downloadAuditExport(exportId) {
  return adminApiBlob(`/v1/audit/export/${pathSegment(exportId)}/download`);
}

export function getAuditIntegrity() {
  return request("/v1/audit/integrity");
}

// Storage
export function listStorageBuckets() {
  return request("/v1/storage/buckets");
}

export function createStorageBucket(bucketId) {
  return request(`/v1/storage/buckets/${pathSegment(bucketId)}`, {
    method: "POST",
  });
}

export function uploadFile(bucketId, filePath, file, contentType) {
  return request(
    `/v1/storage/upload/${pathSegment(bucketId)}/${pathSegments(filePath)}`,
    {
      method: "POST",
      headers: { "Content-Type": contentType },
      body: file,
    },
  );
}

export function getSignedUrl(bucketId, filePath, expiresIn) {
  return request(
    `/v1/storage/sign-url/${pathSegment(bucketId)}/${pathSegments(filePath)}?expires=${expiresIn || 3600}`,
  );
}

export function deleteFile(bucketId, filePath) {
  return request(
    `/v1/storage/delete/${pathSegment(bucketId)}/${pathSegments(filePath)}`,
    { method: "DELETE" },
  );
}

export function uploadAvatar(userId, file, contentType) {
  return request(`/v1/storage/avatar/${pathSegment(userId)}`, {
    method: "POST",
    headers: { "Content-Type": contentType },
    body: file,
  });
}

export function uploadBranding(assetType, file, contentType) {
  return request(`/v1/storage/branding/${pathSegment(assetType)}`, {
    method: "POST",
    headers: { "Content-Type": contentType },
    body: file,
  });
}

export function getBrandingAsset(assetType) {
  return adminApiBlob(`/v1/storage/branding/${pathSegment(assetType)}`);
}

// Organization templates
export function listOrgTemplates() {
  return request("/v1/org-templates");
}

export function createOrgTemplate(data) {
  return request("/v1/org-templates", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function deleteOrgTemplate(templateId) {
  return request(`/v1/org-templates/${pathSegment(templateId)}`, {
    method: "DELETE",
  });
}

export function instantiateOrgTemplate(templateId, data) {
  return request(`/v1/org-templates/${pathSegment(templateId)}/instantiate`, {
    method: "POST",
    headers: {
      "Idempotency-Key":
        globalThis.crypto?.randomUUID?.() ||
        `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    },
    body: JSON.stringify(data),
  });
}

// Security and provisioning
export function getSecurityConfig() {
  return request("/v1/security-config");
}

export function updateSecurityConfig(data) {
  return request("/v1/security-config", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function getSecurityStatus() {
  return request("/v1/security-config/status");
}

export function getProvisioningStatus(projectRef) {
  return request(`/v1/provisioning/${pathSegment(projectRef)}`);
}

export function reconcileProject(projectRef) {
  return request(`/v1/provisioning/${pathSegment(projectRef)}/reconcile`, {
    method: "POST",
  });
}

export function listTenantMembers(params = {}) {
  return request(`/v1/tenant/members${queryString(params)}`);
}

export function listTenantInvitations(params = {}) {
  return request(`/v1/tenant/invitations${queryString(params)}`);
}

export function createTenantInvitation(data) {
  return request("/v1/tenant/invitations", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateTenantMember(memberId, data) {
  return request(`/v1/tenant/members/${pathSegment(memberId)}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function removeTenantMember(memberId) {
  return request(`/v1/tenant/members/${pathSegment(memberId)}`, {
    method: "DELETE",
  });
}

// Enterprise SSO: inbound GoTrue/SupaCloud connectors only.
export function listEnterpriseSSOConfigs() {
  return request("/v1/enterprise-sso");
}

export function getEnterpriseSSOConfig(configId) {
  return request(`/v1/enterprise-sso/${pathSegment(configId)}`);
}

export function createEnterpriseSSOConfig(data) {
  return request("/v1/enterprise-sso", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function updateEnterpriseSSOConfig(configId, data) {
  return request(`/v1/enterprise-sso/${pathSegment(configId)}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export function deleteEnterpriseSSOConfig(configId) {
  return request(`/v1/enterprise-sso/${pathSegment(configId)}`, {
    method: "DELETE",
  });
}
