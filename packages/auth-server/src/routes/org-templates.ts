// Organization template routes (P0-18) with OpenAPI annotations

import { Elysia } from 'elysia';
import * as templateRepo from '../repositories/organization-templates.js';
import * as auditRepo from '../repositories/audit.js';
import * as webhookDelivery from '../repositories/webhook-delivery.js';
import { organizationTemplateCreateInput, organizationTemplateUpdateInput } from './org-template-input.js';

async function audit(eventType: string, resourceType: string, resourceId: string, details?: Record<string, unknown>) {
  await auditRepo.logAudit({ eventType, resourceType, resourceId, actorType: 'admin', details });
}

async function fireWebhook(eventType: string, data: Record<string, unknown>) {
  await webhookDelivery.dispatchEvent(webhookDelivery.buildEvent(eventType, data));
}

export const orgTemplateRoutes = new Elysia({ prefix: '/v1/org-templates' })
  .get('/', async () => {
    const items = await templateRepo.listTemplates();
    return { items, total: items.length };
  }, {
    detail: { summary: 'List organization templates', tags: ['Organizations', 'Org Templates'] },
  })

  .get('/default', async () => {
    const template = await templateRepo.getDefaultTemplate();
    if (!template) return new Response('No default template found', { status: 404 });
    return template;
  }, {
    detail: { summary: 'Get the default organization template', tags: ['Organizations', 'Org Templates'] },
  })

  .get('/:templateId', async ({ params }) => {
    const template = await templateRepo.getTemplate(params.templateId);
    if (!template) return new Response('Not found', { status: 404 });
    return template;
  }, {
    detail: { summary: 'Get organization template by ID', tags: ['Organizations', 'Org Templates'] },
  })

  .post('/', async ({ body }) => {
    const templateInput = organizationTemplateCreateInput(body);
    const template = await templateRepo.createTemplate({
      name: templateInput.name,
      description: templateInput.description,
      templateRoles: templateInput.template_roles,
      templateScopes: templateInput.template_scopes,
      isDefault: templateInput.is_default,
    });
    await audit('org_template.create', 'org_template', template.id, { name: template.name });
    await fireWebhook('org_template.created', { template_id: template.id, name: template.name });
    return template;
  }, {
    detail: { summary: 'Create organization template', tags: ['Organizations', 'Org Templates'] },
  })

  .put('/:templateId', async ({ params, body }) => {
    const templateInput = organizationTemplateUpdateInput(body);
    const updated = await templateRepo.updateTemplate(params.templateId, {
      name: templateInput.name,
      description: templateInput.description,
      templateRoles: templateInput.template_roles,
      templateScopes: templateInput.template_scopes,
      isDefault: templateInput.is_default,
    });
    if (!updated) return new Response('Not found', { status: 404 });
    await audit('org_template.update', 'org_template', params.templateId);
    return updated;
  }, {
    detail: { summary: 'Update organization template', tags: ['Organizations', 'Org Templates'] },
  })

  .delete('/:templateId', async ({ params, set }) => {
    const deletion = await templateRepo.deleteTemplate(params.templateId);
    if (deletion === 'protected') {
      set.status = 409;
      return {
        message: 'The default organization template cannot be deleted.',
        code: 'default_organization_template_protected',
      };
    }
    if (deletion === 'not_found') {
      set.status = 404;
      return { message: 'Organization template not found.', code: 'not_found' };
    }
    await audit('org_template.delete', 'org_template', params.templateId);
  }, {
    detail: { summary: 'Delete organization template', tags: ['Organizations', 'Org Templates'] },
  })

  // ─── Instantiate org from template ───
  .post('/:templateId/instantiate', async ({ params, body, request }) => {
    const data = body as { name: string; description?: string; creator_user_id: string };
    const result = await templateRepo.instantiateFromTemplate(params.templateId, {
      name: data.name,
      description: data.description,
      creatorUserId: data.creator_user_id,
    }, {
      idempotencyKey: request.headers.get('idempotency-key') || request.headers.get('x-request-id') || undefined,
    });
    const { replayed, ...response } = result;
    if (!replayed) {
      await audit('org_template.instantiate', 'organization', result.org.id, {
        template_id: params.templateId,
        org_name: data.name,
        roles_created: result.rolesCreated,
      });
      await fireWebhook('organization.created_from_template', {
        org_id: result.org.id,
        template_id: params.templateId,
      });
    }
    return response;
  }, {
    detail: {
      summary: 'Create organization from template',
      description: 'Creates an org with auto-generated roles and permissions from the template. Creator is added as owner with all template roles assigned.',
      tags: ['Organizations', 'Org Templates'],
    },
  });
