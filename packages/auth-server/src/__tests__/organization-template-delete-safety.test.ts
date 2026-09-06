import { beforeEach, describe, expect, it, mock } from 'bun:test';
import { readFileSync } from 'node:fs';
import { Elysia } from 'elysia';
import { observabilityMiddleware } from '../middleware/index.js';
import { ApiContractError } from '../utils/api-contract.js';
import {
  organizationTemplateCreateInput,
  organizationTemplateUpdateInput,
} from '../routes/org-template-input.js';

const deleteTemplate = mock(async (): Promise<'deleted' | 'protected' | 'not_found'> => 'deleted');
const createTemplate = mock(async () => ({ id: 'template-new', name: 'New template' }));
const updateTemplate = mock(async () => ({ id: 'template-one' } as { id: string } | undefined));
const instantiateFromTemplate = mock(async (): Promise<{
  org: { id: string };
  rolesCreated: number;
  replayed?: boolean;
}> => ({
  org: { id: 'org-one' },
  rolesCreated: 0,
}));
const logAudit = mock(async () => ({}));
const dispatchEvent = mock(async () => undefined);

mock.module('../repositories/organization-templates.js', () => ({
  listTemplates: mock(async () => []),
  getDefaultTemplate: mock(async () => null),
  getTemplate: mock(async () => null),
  createTemplate,
  updateTemplate,
  deleteTemplate,
  instantiateFromTemplate,
}));
mock.module('../repositories/audit.js', () => ({ logAudit }));
mock.module('../repositories/webhook-delivery.js', () => ({
  buildEvent: mock(() => ({})),
  dispatchEvent,
}));

const { orgTemplateRoutes } = await import('../routes/org-templates.js');
const app = new Elysia().use(observabilityMiddleware).use(orgTemplateRoutes);

function templateMutationRequest(method: 'POST' | 'PUT', body: unknown) {
  const path = method === 'POST'
    ? '/v1/org-templates/'
    : '/v1/org-templates/template-one';
  return new Request(`http://localhost${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('organization template deletion safety', () => {
  beforeEach(() => {
    createTemplate.mockClear();
    updateTemplate.mockClear();
    instantiateFromTemplate.mockClear();
    deleteTemplate.mockClear();
    deleteTemplate.mockResolvedValue('deleted');
    logAudit.mockClear();
    dispatchEvent.mockClear();
  });

  it.each([
    ['POST', { name: 'Invalid roles', template_roles: ['not-a-role'] }],
    ['POST', { name: 'Invalid scopes', template_scopes: [null] }],
    ['POST', { name: ' ', template_roles: [] }],
    ['POST', { template_roles: [], template_scopes: [] }],
    ['POST', { name: 'Unknown field', template_roles: [], unexpected: true }],
    ['POST', { name: 'Invalid default', is_default: 'yes' }],
    ['POST', { name: 'x'.repeat(256) }],
    ['POST', { name: 'Blank permission', template_roles: [{ name: 'reader', permissions: [''] }] }],
    ['PUT', { template_roles: [{ name: 'reader', permissions: [42] }] }],
    ['PUT', { name: 'x'.repeat(256) }],
    ['PUT', { template_roles: [{ name: 'reader', permissions: ['   '] }] }],
    ['PUT', {}],
    ['PUT', { template_scopes: [{ name: '', description: 'Empty name' }] }],
    ['PUT', { name: '' }],
    ['PUT', { description: null }],
  ] as const)('rejects malformed %s input before side effects', async (method, body) => {
    const response = await app.handle(templateMutationRequest(method, body));
    const responseBody = await response.json() as {
      error?: { code?: string };
    };

    expect(response.status).toBe(400);
    expect(responseBody.error?.code).toBe('invalid_organization_template');
    expect(createTemplate).not.toHaveBeenCalled();
    expect(updateTemplate).not.toHaveBeenCalled();
    expect(logAudit).not.toHaveBeenCalled();
    expect(dispatchEvent).not.toHaveBeenCalled();
  });

  it.each([
    ['create', organizationTemplateCreateInput, { name: 'x'.repeat(256) }],
    ['create', organizationTemplateCreateInput, {
      name: 'Blank permission',
      template_roles: [{ name: 'reader', permissions: [' '] }],
    }],
    ['update', organizationTemplateUpdateInput, { name: 'x'.repeat(256) }],
    ['update', organizationTemplateUpdateInput, {
      template_roles: [{ name: 'reader', permissions: ['\t'] }],
    }],
    ['update', organizationTemplateUpdateInput, {}],
  ] as const)('rejects invalid %s input in the pure contract parser', (_operation, parseInput, body) => {
    expect(() => parseInput(body)).toThrow(ApiContractError);
  });

  it('accepts organization template names at the 255-character boundary', () => {
    const maximumLengthName = 'x'.repeat(255);

    expect(organizationTemplateCreateInput({ name: maximumLengthName }).name).toBe(maximumLengthName);
    expect(organizationTemplateUpdateInput({ name: maximumLengthName }).name).toBe(maximumLengthName);
  });

  it('forwards validated create and update payloads', async () => {
    const templateRoles = [{ name: 'owner', permissions: ['organizations.manage'] }];
    const templateScopes = [{ name: 'resource.read', description: 'Read resources' }];
    const createResponse = await app.handle(templateMutationRequest('POST', {
      name: 'Standard organization',
      description: 'Standard roles',
      template_roles: templateRoles,
      template_scopes: templateScopes,
      is_default: false,
    }));
    const updateResponse = await app.handle(templateMutationRequest('PUT', {
      description: 'Updated description',
      template_roles: templateRoles,
    }));

    expect(createResponse.status).toBe(200);
    expect(updateResponse.status).toBe(200);
    expect(createTemplate).toHaveBeenCalledWith({
      name: 'Standard organization',
      description: 'Standard roles',
      templateRoles,
      templateScopes,
      isDefault: false,
    });
    expect(updateTemplate).toHaveBeenCalledWith('template-one', {
      name: undefined,
      description: 'Updated description',
      templateRoles,
      templateScopes: undefined,
      isDefault: undefined,
    });
    expect(logAudit).toHaveBeenCalledTimes(2);
    expect(dispatchEvent).toHaveBeenCalledTimes(1);
  });

  it('returns 404 and skips audit when updating a missing template', async () => {
    updateTemplate.mockResolvedValueOnce(undefined);

    const response = await app.handle(templateMutationRequest('PUT', {
      description: 'Missing template',
    }));

    expect(response.status).toBe(404);
    expect(await response.text()).toBe('Not found');
    expect(logAudit).not.toHaveBeenCalled();
  });

  it('does not repeat audit or webhook side effects when an instantiation is replayed', async () => {
    instantiateFromTemplate.mockResolvedValueOnce({
      org: { id: 'org-one' },
      rolesCreated: 1,
      replayed: true,
    });

    const response = await app.handle(new Request(
      'http://localhost/v1/org-templates/template-one/instantiate',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'idempotency-key': 'template-request-one',
        },
        body: JSON.stringify({
          name: 'Existing organization',
          creator_user_id: 'user-one',
        }),
      },
    ));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      org: { id: 'org-one' },
      rolesCreated: 1,
    });
    expect(logAudit).not.toHaveBeenCalled();
    expect(dispatchEvent).not.toHaveBeenCalled();
  });

  it('returns a friendly conflict and skips side effects for the default template', async () => {
    deleteTemplate.mockResolvedValueOnce('protected');

    const response = await app.handle(new Request(
      'http://localhost/v1/org-templates/template-default',
      { method: 'DELETE' },
    ));
    const responseBody = await response.json() as Record<string, unknown>;

    expect(response.status).toBe(409);
    expect(responseBody.code).toBe('default_organization_template_protected');
    expect(responseBody.message).toBe('The default organization template cannot be deleted.');
    expect(logAudit).not.toHaveBeenCalled();
  });

  it('distinguishes missing templates from successful deletion', async () => {
    deleteTemplate.mockResolvedValueOnce('not_found');
    const missingResponse = await app.handle(new Request(
      'http://localhost/v1/org-templates/template-missing',
      { method: 'DELETE' },
    ));

    expect(missingResponse.status).toBe(404);
    expect(logAudit).not.toHaveBeenCalled();

    const deletedResponse = await app.handle(new Request(
      'http://localhost/v1/org-templates/template-one',
      { method: 'DELETE' },
    ));

    expect(deletedResponse.status).toBe(200);
    expect(logAudit).toHaveBeenCalledTimes(1);
  });

  it('uses an atomic non-default predicate at the repository boundary', () => {
    const repositorySource = readFileSync(
      new URL('../repositories/organization-templates.ts', import.meta.url),
      'utf8',
    );

    expect(repositorySource).toContain('eq(organizationTemplates.isDefault, false)');
    expect(repositorySource).toContain('.returning({ id: organizationTemplates.id })');
  });

  it('keeps default writes serialized and remote instantiation compensatable', () => {
    const repositorySource = readFileSync(
      new URL('../repositories/organization-templates.ts', import.meta.url),
      'utf8',
    );

    expect(repositorySource).toContain('db.transaction');
    expect(repositorySource).toContain('pg_advisory_xact_lock');
    expect(repositorySource).toContain('ORGANIZATION_TEMPLATE_DEFAULT_UNIQUE_INDEX_SQL');
    expect(repositorySource).toContain('adapter.deleteRole');
    expect(repositorySource).toContain('adapter.deleteOrganization');
  });

  it('keeps resource and binding mutations scoped to their parent identities', () => {
    const resourcesSource = readFileSync(
      new URL('../repositories/resources.ts', import.meta.url),
      'utf8',
    );
    const bindingsSource = readFileSync(
      new URL('../repositories/bindings.ts', import.meta.url),
      'utf8',
    );

    expect(resourcesSource).toContain('db.transaction');
    expect(resourcesSource).toContain('eq(scopes.resourceId, resourceId)');
    expect(bindingsSource).toContain('eq(scopes.resourceId, data.resourceId)');
    expect(bindingsSource).toContain('eq(applicationBindings.applicationId, applicationId)');
  });
});
