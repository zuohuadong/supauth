// API Resources and Scopes repository — backed by SupaCloud Postgres

import { and, eq, notExists } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { apiResources, applicationBindings, scopes } from '../db/schema.js';

export async function listResources() {
  const db = getDb();
  const resources = await db.select().from(apiResources).orderBy(apiResources.createdAt);
  // Attach scopes for each resource
  const allScopes = await db.select().from(scopes);
  return resources.map(r => ({
    ...r,
    scopes: allScopes.filter(s => s.resourceId === r.id),
  }));
}

export async function getResource(id: string) {
  const db = getDb();
  const resource = await db.select().from(apiResources).where(eq(apiResources.id, id)).limit(1);
  if (!resource[0]) return null;
  const resourceScopes = await db.select().from(scopes).where(eq(scopes.resourceId, id));
  return { ...resource[0], scopes: resourceScopes };
}

export async function createResource(data: { name: string; indicator: string; description?: string; scopes?: { name: string; description?: string }[] }) {
  const db = getDb();
  return db.transaction(async (transaction) => {
    const [resource] = await transaction.insert(apiResources).values({
      name: data.name,
      indicator: data.indicator,
      description: data.description || null,
    }).returning();

    const createdScopes: typeof scopes.$inferSelect[] = [];
    if (data.scopes?.length) {
      const scopeRows = await transaction.insert(scopes).values(
        data.scopes.map(s => ({
          name: s.name,
          description: s.description || null,
          resourceId: resource.id,
        }))
      ).returning();
      createdScopes.push(...scopeRows);
    }

    return { ...resource, scopes: createdScopes };
  });
}

export async function updateResource(id: string, data: { name?: string; indicator?: string; description?: string }) {
  const db = getDb();
  const [updated] = await db.update(apiResources).set({
    ...data,
    updatedAt: new Date(),
  }).where(eq(apiResources.id, id)).returning();
  return updated;
}

export async function deleteResource(id: string) {
  const db = getDb();
  // Scopes cascade delete
  await db.delete(apiResources).where(eq(apiResources.id, id));
}

export async function addScope(resourceId: string, data: { name: string; description?: string }) {
  const db = getDb();
  const [scope] = await db.insert(scopes).values({
    name: data.name,
    description: data.description || null,
    resourceId,
  }).returning();
  return scope;
}

export async function removeScope(resourceId: string, scopeId: string): Promise<'deleted' | 'not_found' | 'in_use'> {
  const db = getDb();
  const [deleted] = await db.delete(scopes).where(and(
    eq(scopes.id, scopeId),
    eq(scopes.resourceId, resourceId),
    notExists(
      db.select({ id: applicationBindings.id })
        .from(applicationBindings)
        .where(eq(applicationBindings.scopeId, scopeId)),
    ),
  )).returning({ id: scopes.id });
  if (deleted) return 'deleted';

  const [scope] = await db.select({ id: scopes.id }).from(scopes).where(and(
    eq(scopes.id, scopeId),
    eq(scopes.resourceId, resourceId),
  )).limit(1);
  if (!scope) return 'not_found';
  return 'in_use';
}

export async function updateScope(scopeId: string, data: { name?: string; description?: string }) {
  const db = getDb();
  const [scope] = await db.update(scopes).set(data).where(eq(scopes.id, scopeId)).returning();
  return scope;
}

export async function resourceBindings(resourceId: string) {
  const db = getDb();
  return db.select().from(applicationBindings).where(eq(applicationBindings.resourceId, resourceId));
}

export async function scopeHasBindings(scopeId: string): Promise<boolean> {
  const db = getDb();
  const bindings = await db.select({ id: applicationBindings.id })
    .from(applicationBindings)
    .where(eq(applicationBindings.scopeId, scopeId))
    .limit(1);
  return bindings.length > 0;
}
