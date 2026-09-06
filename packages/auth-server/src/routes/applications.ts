// Application management routes with OpenAPI annotations

import { Elysia } from 'elysia';
import { getConfig } from '../config/index.js';
import { getSupaCloudAdapter, getSupaCloudAdapterForProject } from '../supacloud/adapter.js';
import * as bindingRepo from '../repositories/bindings.js';
import * as auditRepo from '../repositories/audit.js';
import * as webhookDelivery from '../repositories/webhook-delivery.js';
import * as appControlRepo from '../repositories/application-control.js';
import * as sieRepo from '../repositories/sign-in-experience.js';
import { ApiContractError, capabilityUnavailable, cursorResponse, pagedResponse } from '../utils/api-contract.js';
import { withoutSecrets } from '../utils/secrets.js';

const adapter = getSupaCloudAdapter();
const GOTRUE_OAUTH_GRANT_TYPES = ['authorization_code', 'refresh_token'] as const;
const grantTypesOpenApiSchema = {
  type: 'array',
  minItems: 1,
  items: { type: 'string', enum: [...GOTRUE_OAUTH_GRANT_TYPES] },
  description: "Stock GoTrue supports only 'authorization_code' and 'refresh_token' OAuth client grants",
};
const editableOAuthClientProperties = {
  redirect_uris: { type: 'array', minItems: 1, maxItems: 10, uniqueItems: true, items: { type: 'string' } },
  token_endpoint_auth_method: {
    type: 'string',
    enum: ['none', 'client_secret_basic', 'client_secret_post'],
  },
  grant_types: grantTypesOpenApiSchema,
  client_name: { type: 'string' },
  client_uri: { type: 'string' },
  logo_uri: { type: 'string' },
};
const createOAuthClientRequestBody = openApiRequestBody({
  type: 'object',
  required: ['redirect_uris'],
  properties: {
    ...editableOAuthClientProperties,
    client_type: { type: 'string', enum: ['public', 'confidential'] },
  },
});
const updateOAuthClientRequestBody = openApiRequestBody({
  type: 'object',
  minProperties: 1,
  properties: {
    ...editableOAuthClientProperties,
  },
});

function openApiRequestBody(schema: Record<string, unknown>) {
  return { required: true, content: { 'application/json': { schema } } };
}

function oauthClientInput(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiContractError(400, 'invalid_request_body', 'OAuth client request body must be a JSON object');
  }
  return body as Record<string, unknown>;
}

function assertSupportedGrantTypes(grantTypes: unknown): asserts grantTypes is string[] {
  if (!Array.isArray(grantTypes) || grantTypes.some((grantType) => typeof grantType !== 'string')) {
    throw invalidGrantTypes();
  }
  const unsupportedGrantTypes = grantTypes.filter(
    (grantType) => !GOTRUE_OAUTH_GRANT_TYPES.includes(grantType as typeof GOTRUE_OAUTH_GRANT_TYPES[number]),
  );
  if (unsupportedGrantTypes.length > 0) throw invalidGrantTypes(unsupportedGrantTypes);
}

function invalidGrantTypes(unsupportedGrantTypes: string[] = []) {
  return new ApiContractError(
    400,
    'unsupported_grant_type',
    "grant_types must only contain 'authorization_code' and/or 'refresh_token' for stock GoTrue",
    { allowed_grant_types: [...GOTRUE_OAUTH_GRANT_TYPES], unsupported_grant_types: unsupportedGrantTypes },
  );
}

function validateCreateGrantTypes(input: Record<string, unknown>) {
  if (!Object.hasOwn(input, 'grant_types')) return;
  const grantTypes = input.grant_types;
  assertSupportedGrantTypes(grantTypes);
  if (grantTypes.length === 0) throw invalidGrantTypes();
}

function invalidRedirectUris() {
  return new ApiContractError(
    400,
    'invalid_redirect_uris',
    'redirect_uris must contain 1 to 10 unique URI strings',
  );
}

function validateRedirectUriList(redirectUris: unknown) {
  if (!Array.isArray(redirectUris)
    || redirectUris.length < 1
    || redirectUris.length > 10
    || redirectUris.some(uri => typeof uri !== 'string')
    || new Set(redirectUris).size !== redirectUris.length) {
    throw invalidRedirectUris();
  }
}

function validateCreateRedirectUris(input: Record<string, unknown>) {
  if (!Object.hasOwn(input, 'redirect_uris')) throw invalidRedirectUris();
  validateRedirectUriList(input.redirect_uris);
}

function validateUpdateRedirectUris(input: Record<string, unknown>) {
  if (Object.hasOwn(input, 'redirect_uris')) validateRedirectUriList(input.redirect_uris);
}

function validateUpdateGrantTypes(input: Record<string, unknown>) {
  if (!Object.hasOwn(input, 'grant_types')) return;
  const grantTypes = input.grant_types;
  assertSupportedGrantTypes(grantTypes);
  if (grantTypes.length === 0) throw invalidGrantTypes();
}

function oauthClientAdapter() {
  const oauthProjectRef = getConfig().oauthAuthorizationProjectRef;
  return oauthProjectRef ? getSupaCloudAdapterForProject(oauthProjectRef) : adapter;
}

async function audit(eventType: string, resourceType: string, resourceId: string, details?: Record<string, unknown>) {
  await auditRepo.logAudit({ eventType, resourceType, resourceId, actorType: 'admin', details });
}

async function fireWebhook(eventType: string, payload: Record<string, unknown>) {
  await webhookDelivery.dispatchEvent(webhookDelivery.buildEvent(eventType, payload));
}

export const applicationRoutes = new Elysia({ prefix: '/v1/applications' })
  .get('/', async ({ query }) => {
    const res = await oauthClientAdapter().listOAuthClients();
    await audit('application.list', 'application', 'all');
    return withoutSecrets(pagedResponse(res, { page: query.page, limit: query.limit }));
  }, {
    detail: { summary: 'List OAuth applications', tags: ['Applications'] },
  })

  .post('/', async ({ body }) => {
    const input = oauthClientInput(body);
    validateCreateRedirectUris(input);
    validateCreateGrantTypes(input);
    const created = await oauthClientAdapter().createOAuthClient(input);
    const clientId = String((created as Record<string, unknown>).client_id);
    await audit('application.create', 'application', clientId, { name: input.client_name });
    await fireWebhook('application.created', { client_id: clientId });
    return created;
  }, {
    detail: {
      summary: 'Create OAuth application',
      tags: ['Applications'],
      requestBody: createOAuthClientRequestBody,
    },
  })

  .get('/:appId', async ({ params }) => withoutSecrets(
    await oauthClientAdapter().getOAuthClient(params.appId),
  ), {
    detail: { summary: 'Get application by ID', tags: ['Applications'] },
  })

  .put('/:appId', async ({ params, body }) => {
    const input = oauthClientInput(body);
    validateUpdateRedirectUris(input);
    validateUpdateGrantTypes(input);
    const updated = await oauthClientAdapter().updateOAuthClient(params.appId, input);
    await audit('application.update', 'application', params.appId);
    await fireWebhook('application.updated', { client_id: params.appId });
    return withoutSecrets(updated);
  }, {
    detail: {
      summary: 'Update application',
      tags: ['Applications'],
      requestBody: updateOAuthClientRequestBody,
    },
  })

  .delete('/:appId', async ({ params }) => {
    await oauthClientAdapter().deleteOAuthClient(params.appId);
    await audit('application.delete', 'application', params.appId);
    await fireWebhook('application.deleted', { client_id: params.appId });
  }, {
    detail: { summary: 'Delete application', tags: ['Applications'] },
  })

  .post('/:appId/rotate-secret', async ({ params }) => {
    const result = await oauthClientAdapter().regenerateClientSecret(params.appId);
    await audit('application.rotate_secret', 'application', params.appId);
    return result;
  }, {
    detail: { summary: 'Rotate client secret', tags: ['Applications'] },
  })

  .get('/:appId/secrets', async ({ params }) => {
    throw capabilityUnavailable('oauth_client_secret_lifecycle', `Per-client secret lists are unavailable for ${params.appId}`);
  }, {
    detail: { hide: true },
  })

  .post('/:appId/secrets', async ({ params }) => {
    throw capabilityUnavailable('oauth_client_secret_lifecycle', `Additional client secrets are unavailable for ${params.appId}`);
  }, {
    detail: { hide: true },
  })

  .post('/:appId/secrets/:secretId/disable', async ({ params }) => {
    throw capabilityUnavailable('oauth_client_secret_lifecycle', `Secret ${params.secretId} cannot be disabled independently`);
  }, {
    detail: { hide: true },
  })

  .delete('/:appId/secrets/:secretId', async ({ params }) => {
    throw capabilityUnavailable('oauth_client_secret_lifecycle', `Secret ${params.secretId} cannot be deleted independently`);
  }, {
    detail: { hide: true },
  })

  .get('/:appId/consent', async ({ params }) => {
    const settings = await appControlRepo.getApplicationConsentSettings(params.appId);
    return settings || {
      applicationId: params.appId,
      userScopes: [],
      organizationScopes: [],
      allowedOrganizationIds: [],
      requireExplicitConsent: true,
      customData: {},
    };
  }, {
    detail: { summary: 'Get application consent configuration', tags: ['Applications', 'Consent'] },
  })

  .put('/:appId/consent', async ({ params, body }) => {
    const data = body as {
      user_scopes?: string[];
      organization_scopes?: string[];
      allowed_organization_ids?: string[];
      require_explicit_consent?: boolean;
      custom_data?: Record<string, unknown>;
    };
    return appControlRepo.upsertApplicationConsentSettings(params.appId, {
      userScopes: data.user_scopes,
      organizationScopes: data.organization_scopes,
      allowedOrganizationIds: data.allowed_organization_ids,
      requireExplicitConsent: data.require_explicit_consent,
      customData: data.custom_data,
    });
  }, {
    detail: { summary: 'Update application consent configuration', tags: ['Applications', 'Consent'] },
  })

  .get('/:appId/access-control', async ({ params }) => {
    const settings = await appControlRepo.getApplicationConsentSettings(params.appId);
    return settings || {
      applicationId: params.appId,
      userScopes: [],
      organizationScopes: [],
      allowedOrganizationIds: [],
      requireExplicitConsent: true,
      customData: {},
    };
  }, {
    detail: { summary: 'Get application access-control rules', tags: ['Applications'] },
  })

  .put('/:appId/access-control', async ({ params, body }) => {
    const input = body as {
      user_scopes?: string[];
      organization_scopes?: string[];
      allowed_organization_ids?: string[];
      require_explicit_consent?: boolean;
      custom_data?: Record<string, unknown>;
    };
    return appControlRepo.upsertApplicationConsentSettings(params.appId, {
      userScopes: input.user_scopes,
      organizationScopes: input.organization_scopes,
      allowedOrganizationIds: input.allowed_organization_ids,
      requireExplicitConsent: input.require_explicit_consent,
      customData: input.custom_data,
    });
  }, {
    detail: { summary: 'Update application access-control rules', tags: ['Applications'] },
  })

  .get('/:appId/sign-in-experience', async ({ params }) => {
    const experience = await sieRepo.getApplicationSignInExperience(params.appId);
    return experience || {
      application_id: params.appId,
      enabled: false,
      branding: {
        logo_url: null,
        favicon_url: null,
        primary_color: null,
        page_title: null,
        background_url: null,
        button_label: null,
        custom_css: null,
      },
    };
  }, {
    detail: { summary: 'Get application sign-in experience overrides', tags: ['Applications', 'Sign-in Experience'] },
  })

  .put('/:appId/sign-in-experience', async ({ params, body }) => {
    const data = body as Parameters<typeof sieRepo.upsertApplicationSignInExperience>[1];
    const saved = await sieRepo.upsertApplicationSignInExperience(params.appId, data);
    await audit('application.sign_in_experience.update', 'application', params.appId, { enabled: saved.enabled });
    return saved;
  }, {
    detail: { summary: 'Update application sign-in experience overrides', tags: ['Applications', 'Sign-in Experience'] },
  })

  .delete('/:appId/sign-in-experience', async ({ params }) => {
    await sieRepo.deleteApplicationSignInExperience(params.appId);
    await audit('application.sign_in_experience.delete', 'application', params.appId);
    return new Response(null, { status: 204 });
  }, {
    detail: { summary: 'Delete application sign-in experience overrides', tags: ['Applications', 'Sign-in Experience'] },
  })

  // ─── Application-Resource/Scope bindings ───
  .get('/:appId/bindings', async ({ params }) => {
    const bindings = await bindingRepo.listApplicationBindings(params.appId);
    return { items: bindings, total: bindings.length };
  }, {
    detail: { summary: 'List application resource/scope bindings', tags: ['Applications', 'Bindings'] },
  })

  .post('/:appId/bindings', async ({ params, body }) => {
    const data = body as { resource_id: string; scope_id?: string };
    let binding;
    try {
      binding = await bindingRepo.createBinding({
        applicationId: params.appId,
        resourceId: data.resource_id,
        scopeId: data.scope_id,
      });
    } catch (error) {
      if (error instanceof bindingRepo.BindingIntegrityError) {
        throw new ApiContractError(
          404,
          error.code,
          error.message,
          { resource_id: data.resource_id, scope_id: data.scope_id },
        );
      }
      throw error;
    }
    await audit('binding.create', 'binding', binding.id, { app_id: params.appId });
    return binding;
  }, {
    detail: { summary: 'Create application binding', tags: ['Applications', 'Bindings'] },
  })

  .delete('/:appId/bindings/:bindingId', async ({ params }) => {
    const deleted = await bindingRepo.deleteBinding(params.appId, params.bindingId);
    if (!deleted) {
      throw new ApiContractError(404, 'binding_not_found', 'Application binding was not found');
    }
    await audit('binding.delete', 'binding', params.bindingId);
  }, {
    detail: { summary: 'Delete application binding', tags: ['Applications', 'Bindings'] },
  })

  .get('/:appId/scopes', async ({ params }) => {
    const scopes = await bindingRepo.listApplicationScopes(params.appId);
    return { items: scopes, total: scopes.length };
  }, {
    detail: { summary: 'List application scopes', tags: ['Applications', 'Bindings'] },
  })

  .get('/:appId/roles', async ({ params }) => {
    return pagedResponse(await adapter.listApplicationRoleAssignments(params.appId));
  }, {
    detail: { summary: 'List role assignments for an application', tags: ['Applications', 'RBAC'] },
  })

  .get('/:appId/logs', async ({ params, query }) => {
    const logs = await adapter.queryAuditLogs({
      resource_type: 'application',
      resource_id: params.appId,
      limit: query.limit,
      cursor: query.cursor,
    });
    return cursorResponse(logs, { limit: query.limit });
  }, {
    detail: { summary: 'List audit logs for an application', tags: ['Applications', 'Audit'] },
  })

  .get('/:appId/organizations', async ({ params }) => {
    return pagedResponse(await adapter.listApplicationOrganizations(params.appId));
  }, {
    detail: { summary: 'List organizations with application access', tags: ['Applications', 'Organizations'] },
  });
