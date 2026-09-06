# @supauth/sdk-typescript

TypeScript SDK for the SupaOAuth Management API and public sign-in experience APIs.

## Installation

```bash
npm install @supauth/sdk-typescript
# or
bun add @supauth/sdk-typescript
```

## Quick Start

```typescript
import { SupaOAuthClient } from '@supauth/sdk-typescript';

const client = new SupaOAuthClient({
  baseUrl: 'https://auth.your-domain.com',
  accessToken: '<your-admin-access-token>',
});

// Check service health
const health = await client.health();
console.log(health);

// List applications
const apps = await client.listApplications();

// Create an application
const app = await client.createApplication({
  name: 'My Web App',
  type: 'web',
  redirect_uris: ['https://your-domain.com/callback'],
});

// Resolve sign-in experience for a specific application
const experience = await client.resolvePublicSignInExperience({
  application_id: app.client_id,
});

// Get i18n phrases
const phrases = await client.getPublicPhrases('zh-CN');
```

## API Coverage

The SDK provides methods for all SupaOAuth Management API endpoints:

| Domain | Methods |
|---|---|
| Health / Project | `health()`, `getProject()` |
| Runtime | `getRuntimeHealth()`, `getOAuthServerStatus()`, `getDiscovery()`, `getJWKS()` |
| Applications | `listApplications()`, `createApplication()`, `getApplication()`, `updateApplication()`, `deleteApplication()`, `rotateApplicationSecret()`, `getApplicationConsentSettings()`, `updateApplicationConsentSettings()` |
| Application Bindings | `listApplicationBindings()`, `createApplicationBinding()`, `deleteApplicationBinding()`, `listApplicationScopes()` |
| Connectors | `listConnectors()`, `getConnector()`, `updateConnector()`, `testConnector()`, `getConnectorAuthorizationUri()`, `listConnectorFactories()`, `upsertConnectorFactory()` |
| API Resources | `listResources()`, `createResource()`, `getResource()`, `updateResource()`, `deleteResource()` |
| Scopes | `addScope()`, `removeScope()` |
| Users | `listUsers()`, `getUser()`, `updateUser()`, `suspendUser()`, `deleteUser()`, `resetUserMfa()` |
| Organizations | `listOrganizations()`, `createOrganization()`, `getOrganization()`, `updateOrganization()`, `deleteOrganization()`, `addOrganizationMember()`, `removeOrganizationMember()`, `updateOrganizationMemberRole()`, `listOrganizationInvitations()`, `createOrganizationInvitation()`, `acceptOrganizationInvitation()`, `revokeOrganizationInvitation()`, `getOrganizationJitSettings()`, `updateOrganizationJitSettings()`, `listOrganizationApplications()`, `bindOrganizationApplication()`, `removeOrganizationApplication()` |
| Roles | `listRoles()`, `createRole()`, `getRole()`, `updateRole()`, `deleteRole()` |
| Permissions | `listRolePermissions()`, `createRolePermission()`, `deleteRolePermission()`, `assignRole()`, `revokeRole()`, `getOrgRoleAssignments()` |
| Sign-in Experience | `getSignInExperience()`, `resolveSignInExperience()`, `resolvePublicSignInExperience()`, `getPublicPhrases()`, `updateSignInExperience()`, `getApplicationSignInExperience()`, `updateApplicationSignInExperience()`, `deleteApplicationSignInExperience()` |
| Auth Config | `getAuthConfig()`, `updateAuthConfig()` |
| Organization Templates | `listOrgTemplates()`, `createOrgTemplate()`, `instantiateOrgTemplate()` |
| Webhooks | `listWebhooks()`, `createWebhook()`, `getWebhook()`, `updateWebhook()`, `deleteWebhook()`, `rotateWebhookSecret()`, `listWebhookLogs()`, `testWebhook()`, `replayWebhookDelivery(webhookId, deliveryId)`, `listWebhookEvents()` |
| Audit | `listAuditLogs()` |
| Sync | `syncUserMetadata()`, `syncOrgMetadata()` |
| Tenant Config | `listTenantConfigs()`, `getTenantConfig()`, `upsertTenantConfig()`, `deleteTenantConfig()`, `checkTenantDomain()` |
| Enterprise SSO | `listEnterpriseSSOConfigs()`, `createEnterpriseSSOConfig()` |
| Security / Provisioning | `getSecurityStatus()`, `getProvisioningStatus()`, `reconcileProject()`, `getCompatibilityReport()` |
| Auth Hooks | `getAuthHookRegistrationGuide()` |
| Admin Tools | `compileAuthorizationPlan()`, `getAuthorizationCompilerDemo()`, `generateRLSMigration()`, `getRLSMigrationDemo()` |

## Error Handling

```typescript
import { SupaOAuthClient, SupaOAuthAPIError } from '@supauth/sdk-typescript';

try {
  await client.deleteApplication('nonexistent-id');
} catch (err) {
  if (err instanceof SupaOAuthAPIError) {
    console.log(`Status: ${err.status}`);
    console.log(`Path: ${err.path}`);
    console.log(`Body: ${err.body}`);
  }
}
```

## Token Management

```typescript
// Initialize without token
const client = new SupaOAuthClient({ baseUrl: 'https://auth.your-domain.com' });

// Set token after login
client.setAccessToken('eyJhbGci...');

// Clear token
client.setAccessToken(null);
```

## License

MIT
