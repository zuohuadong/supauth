// Application-Resource/Scope bindings repository

import { and, eq } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { apiResources, applicationBindings, scopes } from '../db/schema.js';

export class BindingIntegrityError extends Error {
  constructor(
    readonly code: 'resource_not_found' | 'scope_not_found',
    message: string,
  ) {
    super(message);
    this.name = 'BindingIntegrityError';
  }
}

/** List all bindings for an application */
export async function listApplicationBindings(applicationId: string) {
  const db = getDb();
  const bindings = await db.select().from(applicationBindings)
    .where(eq(applicationBindings.applicationId, applicationId))
    .orderBy(applicationBindings.createdAt);
  return bindings;
}

/** List all scopes available to an application (through bindings) */
export async function listApplicationScopes(applicationId: string) {
  const db = getDb();
  const bindings = await db.select({
    binding: applicationBindings,
    scope: scopes,
  }).from(applicationBindings)
    .leftJoin(scopes, eq(applicationBindings.scopeId, scopes.id))
    .where(eq(applicationBindings.applicationId, applicationId));

  return bindings.map(b => ({
    bindingId: b.binding.id,
    resourceId: b.binding.resourceId,
    scope: b.scope || null,
  }));
}

/** Bind an application to a resource (optionally with a specific scope) */
export async function createBinding(data: {
  applicationId: string;
  resourceId: string;
  scopeId?: string;
}) {
  const db = getDb();
  const [resource] = await db.select({ id: apiResources.id })
    .from(apiResources)
    .where(eq(apiResources.id, data.resourceId))
    .limit(1);
  if (!resource) {
    throw new BindingIntegrityError('resource_not_found', 'API resource was not found');
  }

  if (data.scopeId) {
    const [scope] = await db.select({ id: scopes.id })
      .from(scopes)
      .where(and(
        eq(scopes.id, data.scopeId),
        eq(scopes.resourceId, data.resourceId),
      ))
      .limit(1);
    if (!scope) {
      throw new BindingIntegrityError('scope_not_found', 'Scope was not found under this API resource');
    }
  }

  const [binding] = await db.insert(applicationBindings).values({
    applicationId: data.applicationId,
    resourceId: data.resourceId,
    scopeId: data.scopeId || null,
  }).returning();
  return binding;
}

/** Remove a binding */
export async function deleteBinding(applicationId: string, bindingId: string): Promise<boolean> {
  const db = getDb();
  const [deleted] = await db.delete(applicationBindings).where(and(
    eq(applicationBindings.id, bindingId),
    eq(applicationBindings.applicationId, applicationId),
  )).returning({ id: applicationBindings.id });
  return Boolean(deleted);
}

/** Remove all bindings for an application */
export async function deleteApplicationBindings(applicationId: string) {
  const db = getDb();
  await db.delete(applicationBindings).where(eq(applicationBindings.applicationId, applicationId));
}
