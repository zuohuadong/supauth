// Account provisioning and claiming repository.
// GoTrue keeps auth.users.id as the identity primary key; external_id is the
// tenant-owned anchor used for imports, sync, and self-service account claims.

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { and, eq, inArray, isNotNull, isNull, lte, sql } from 'drizzle-orm';
import { getDb } from '../db/index.js';
import { accountProvisioningRecords } from '../db/schema.js';
import { runtimeEnv } from '../config/platform-env.js';
import { logAudit } from './audit.js';

const PASSWORD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%';
const ENCRYPTION_VERSION = 'v1';
const CLAIM_PROOF_HASH_VERSION = 'v1';
const CLAIM_PASSWORD_HASH_VERSION = 'v1';
const CLAIM_LEASE_MS = 120_000;
const CLAIMABLE_SOURCE_STATUSES = ['active', '正常'];

type AccountClaimState = 'ready' | 'pending' | 'password_applied' | 'password_update_unknown' | 'claimed';
type AccountProvisioningRow = typeof accountProvisioningRecords.$inferSelect;

export interface AccountProvisioningImportRecord {
  external_id: string;
  external_type?: string;
  display_name: string;
  email: string;
  user_id?: string | null;
  initial_password?: string;
  source_status?: string;
  profile?: Record<string, unknown>;
  import_batch?: string | null;
  metadata?: Record<string, unknown>;
  generate_initial_password?: boolean;
  claim_proof?: string;
}

export interface AccountClaimInput {
  externalId: string;
  displayName: string;
  externalType?: string;
  ip?: string;
  userAgent?: string;
  passwordMode?: AccountClaimPasswordMode;
  claimProof?: string;
  newPassword?: string;
  updatePassword?: (target: AccountClaimPasswordUpdateTarget, password: string) => Promise<void>;
  isDefinitivePasswordRejection?: (error: unknown) => boolean;
}

type PasswordAccountClaimInput = AccountClaimInput & {
  newPassword: string;
  updatePassword: NonNullable<AccountClaimInput['updatePassword']>;
};

export type AccountClaimPasswordMode = 'show_initial_password' | 'set_on_claim';

export interface AccountClaimPasswordUpdateTarget {
  userId: string;
  email: string;
  externalId: string;
  externalType: string;
}

export type AccountClaimResult =
  | { status: 'claimed'; email: string; initialPassword: string }
  | { status: 'claimed'; email: string; passwordSet: true }
  | { status: 'unavailable' };

export function normalizeDisplayName(value: string): string {
  return value.normalize('NFKC').replace(/\s+/g, '').toLowerCase();
}

export function normalizeExternalId(value: string): string {
  const normalized = value.normalize('NFKC').trim();
  if (/^\d+$/.test(normalized)) {
    return normalized.replace(/^0+(?=\d)/, '');
  }
  return normalized;
}

export function externalIdLookupCandidates(value: string): string[] {
  const normalized = value.normalize('NFKC').trim();
  const canonical = normalizeExternalId(normalized);
  const candidates = new Set([canonical, normalized]);
  if (/^\d+$/.test(canonical) && canonical.length < 4) {
    candidates.add(canonical.padStart(4, '0'));
  }
  return [...candidates].filter(Boolean);
}

function claimSecret(): string {
  const secret = runtimeEnv('ACCOUNT_CLAIM_SECRET')
    || runtimeEnv('ADMIN_TOKEN')
    || runtimeEnv('SUPACLOUD_MASTER_TOKEN')
    || runtimeEnv('SUPACLOUD_INTERNAL_TOKEN')
    || '';
  if (secret.length < 16) {
    throw new Error('ACCOUNT_CLAIM_SECRET, ADMIN_TOKEN, or SUPACLOUD_MASTER_TOKEN is required for account claim password encryption');
  }
  return secret;
}

function keyFromSecret(secret: string): Buffer {
  return createHash('sha256').update(secret).digest();
}

export function hashAccountClaimProof(proof: string): string {
  const digest = createHash('sha256').update(proof, 'utf8').digest('base64url');
  return `${CLAIM_PROOF_HASH_VERSION}:${digest}`;
}

function hashClaimPassword(password: string): string {
  const digest = createHmac('sha256', keyFromSecret(claimSecret()))
    .update(password, 'utf8')
    .digest('base64url');
  return `${CLAIM_PASSWORD_HASH_VERSION}:${digest}`;
}

function importedClaimProofHash(proof?: string): string | null {
  if (proof === undefined) return null;
  const normalized = proof.trim();
  const byteLength = Buffer.byteLength(normalized, 'utf8');
  if (byteLength < 32 || byteLength > 512) {
    throw new Error('claim_proof must contain between 32 and 512 bytes');
  }
  return hashAccountClaimProof(normalized);
}

export function encryptInitialPassword(password: string, secret = claimSecret()): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyFromSecret(secret), iv);
  const encrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [ENCRYPTION_VERSION, iv.toString('base64url'), tag.toString('base64url'), encrypted.toString('base64url')].join(':');
}

export function decryptInitialPassword(payload: string, secret = claimSecret()): string {
  const [version, ivRaw, tagRaw, encryptedRaw] = payload.split(':');
  if (version !== ENCRYPTION_VERSION || !ivRaw || !tagRaw || !encryptedRaw) {
    throw new Error('Unsupported account claim password payload');
  }
  const decipher = createDecipheriv('aes-256-gcm', keyFromSecret(secret), Buffer.from(ivRaw, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagRaw, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedRaw, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function generateInitialPassword(length = 12): string {
  const bytes = randomBytes(length);
  let password = '';
  for (const byte of bytes) password += PASSWORD_ALPHABET[byte % PASSWORD_ALPHABET.length];
  return password;
}

function accountProvisioningClaimState(existing?: AccountProvisioningRow): AccountClaimState {
  if (existing?.initialPasswordClaimed) return 'claimed';
  return (existing?.claimState || 'ready') as AccountClaimState;
}

function importedInitialPassword(
  record: AccountProvisioningImportRecord,
  existing: AccountProvisioningRow | undefined,
  claimState: AccountClaimState,
) {
  if (claimState !== 'ready') return undefined;
  if (record.initial_password) return record.initial_password;
  const shouldGenerate = record.generate_initial_password !== false;
  return shouldGenerate && !existing?.initialPasswordEncrypted ? generateInitialPassword() : null;
}

function importedEncryptedPassword(
  initialPassword: string | null | undefined,
  existing: AccountProvisioningRow | undefined,
  claimState: AccountClaimState,
) {
  if (claimState === 'claimed') return null;
  if (claimState !== 'ready') return existing?.initialPasswordEncrypted || null;
  return initialPassword ? encryptInitialPassword(initialPassword) : existing?.initialPasswordEncrypted || null;
}

function importedProvisioningProofHash(
  record: AccountProvisioningImportRecord,
  existing: AccountProvisioningRow | undefined,
  claimState: AccountClaimState,
) {
  if (claimState === 'claimed') return null;
  if (claimState !== 'ready') return existing?.claimProofHash || null;
  return importedClaimProofHash(record.claim_proof) || existing?.claimProofHash || null;
}

export async function upsertAccountProvisioningRecord(record: AccountProvisioningImportRecord) {
  const db = getDb();
  const externalId = normalizeExternalId(record.external_id);
  const externalType = record.external_type || 'generic';
  const normalizedDisplayName = normalizeDisplayName(record.display_name);
  const sourceStatus = record.source_status || 'active';

  if (!externalId) throw new Error('external_id is required');
  if (!normalizedDisplayName) throw new Error('display_name is required');
  if (!record.email) throw new Error('email is required');

  const existingRows = await db.select().from(accountProvisioningRecords)
    .where(and(
      eq(accountProvisioningRecords.externalId, externalId),
      eq(accountProvisioningRecords.externalType, externalType),
    ))
    .limit(1);
  const existing = existingRows[0];
  const claimState = accountProvisioningClaimState(existing);
  const initialPassword = importedInitialPassword(record, existing, claimState);
  const encryptedPassword = importedEncryptedPassword(initialPassword, existing, claimState);
  const claimProofHash = importedProvisioningProofHash(record, existing, claimState);

  const provisioningValues = {
    externalId,
    externalType,
    displayName: record.display_name.trim(),
    normalizedDisplayName,
    email: record.email.trim().toLowerCase(),
    userId: record.user_id || existing?.userId || null,
    initialPasswordEncrypted: encryptedPassword,
    claimProofHash,
    sourceStatus,
    profile: record.profile || {},
    importBatch: record.import_batch || null,
    metadata: record.metadata || {},
    updatedAt: new Date(),
  };

  const [saved] = existing
    ? await db.update(accountProvisioningRecords).set(provisioningValues)
      .where(eq(accountProvisioningRecords.id, existing.id))
      .returning()
    : await db.insert(accountProvisioningRecords).values({
      ...provisioningValues,
      initialPasswordClaimed: false,
      claimCount: 0,
      claimState: 'ready',
      claimMode: null,
      claimPasswordHash: null,
      claimOperationId: null,
      claimLeaseExpiresAt: null,
    }).returning();

  return { record: saved, initialPassword };
}

export async function findAccountProvisioningRecord(input: {
  externalId: string;
  displayName: string;
  externalType?: string;
}) {
  const db = getDb();
  const rows = await db.select().from(accountProvisioningRecords)
    .where(and(
      inArray(accountProvisioningRecords.externalId, externalIdLookupCandidates(input.externalId)),
      eq(accountProvisioningRecords.externalType, input.externalType || 'generic'),
      eq(accountProvisioningRecords.normalizedDisplayName, normalizeDisplayName(input.displayName)),
    ))
    .limit(1);
  return rows[0] || null;
}

interface AccountClaimReservation {
  record: AccountProvisioningRow;
  operationId: string;
  proofHash: string;
  passwordMode: AccountClaimPasswordMode;
  passwordHash: string | null;
  passwordApplied: boolean;
}

interface AccountClaimReservationPlan {
  currentState: AccountClaimState;
  nextState: Extract<AccountClaimState, 'pending' | 'password_applied'>;
  operationId: string;
  passwordHash: string | null;
  now: Date;
  leaseExpiresAt: Date;
}

async function findAccountByClaimProof(input: AccountClaimInput, proofHash: string) {
  const db = getDb();
  const rows = await db.select().from(accountProvisioningRecords).where(and(
    inArray(accountProvisioningRecords.externalId, externalIdLookupCandidates(input.externalId)),
    eq(accountProvisioningRecords.externalType, input.externalType || 'generic'),
    eq(accountProvisioningRecords.normalizedDisplayName, normalizeDisplayName(input.displayName)),
    eq(accountProvisioningRecords.claimProofHash, proofHash),
  )).limit(1);
  return rows[0] || null;
}

function storedClaimState(record: AccountProvisioningRow): AccountClaimState {
  if (record.initialPasswordClaimed) return 'claimed';
  return record.claimState as AccountClaimState;
}

function sourceStatusAllowsClaim(sourceStatus: string): boolean {
  return CLAIMABLE_SOURCE_STATUSES.includes(sourceStatus);
}

function retryMatches(
  record: AccountProvisioningRow,
  passwordMode: AccountClaimPasswordMode,
  passwordHash: string | null,
  now: Date,
): boolean {
  if (!record.claimLeaseExpiresAt || record.claimLeaseExpiresAt > now) return false;
  if (record.claimMode !== passwordMode) return false;
  if (record.claimState === 'pending') return passwordMode === 'show_initial_password';
  return record.claimState === 'password_applied'
    && passwordMode === 'set_on_claim'
    && record.claimPasswordHash === passwordHash;
}

function accountClaimReservationPlan(
  record: AccountProvisioningRow,
  passwordMode: AccountClaimPasswordMode,
  passwordHash: string | null,
): AccountClaimReservationPlan | null {
  const state = storedClaimState(record);
  const now = new Date();
  const isRetry = state === 'pending' || state === 'password_applied';
  if (state !== 'ready' && !isRetry) return null;
  if (isRetry && !retryMatches(record, passwordMode, passwordHash, now)) return null;
  return {
    currentState: state,
    nextState: state === 'password_applied' ? 'password_applied' : 'pending',
    operationId: randomUUID(),
    passwordHash,
    now,
    leaseExpiresAt: new Date(now.getTime() + CLAIM_LEASE_MS),
  };
}

function reservationStateCondition(
  plan: AccountClaimReservationPlan,
  passwordMode: AccountClaimPasswordMode,
) {
  if (plan.currentState === 'ready') {
    return and(
      eq(accountProvisioningRecords.claimState, 'ready'),
      isNull(accountProvisioningRecords.claimMode),
      isNull(accountProvisioningRecords.claimPasswordHash),
      isNull(accountProvisioningRecords.claimOperationId),
    );
  }
  const retryCondition = and(
    eq(accountProvisioningRecords.claimState, plan.currentState),
    lte(accountProvisioningRecords.claimLeaseExpiresAt, plan.now),
    eq(accountProvisioningRecords.claimMode, passwordMode),
    isNotNull(accountProvisioningRecords.claimOperationId),
  );
  if (plan.currentState !== 'password_applied') {
    return and(retryCondition, isNull(accountProvisioningRecords.claimPasswordHash));
  }
  return plan.passwordHash
    ? and(retryCondition, eq(accountProvisioningRecords.claimPasswordHash, plan.passwordHash))
    : sql`false`;
}

function reservationUpdateValues(
  plan: AccountClaimReservationPlan,
  passwordMode: AccountClaimPasswordMode,
) {
  return {
    claimState: plan.nextState,
    claimMode: passwordMode,
    claimPasswordHash: plan.passwordHash,
    claimOperationId: plan.operationId,
    claimLeaseExpiresAt: plan.leaseExpiresAt,
    updatedAt: plan.now,
  };
}

async function persistAccountClaimReservation(
  record: AccountProvisioningRow,
  proofHash: string,
  passwordMode: AccountClaimPasswordMode,
  plan: AccountClaimReservationPlan,
) {
  const [reserved] = await getDb().update(accountProvisioningRecords).set(
    reservationUpdateValues(plan, passwordMode),
  ).where(and(
    eq(accountProvisioningRecords.id, record.id),
    eq(accountProvisioningRecords.claimProofHash, proofHash),
    eq(accountProvisioningRecords.initialPasswordClaimed, false),
    inArray(accountProvisioningRecords.sourceStatus, CLAIMABLE_SOURCE_STATUSES),
    isNotNull(accountProvisioningRecords.initialPasswordEncrypted),
    passwordMode === 'set_on_claim' ? isNotNull(accountProvisioningRecords.userId) : undefined,
    reservationStateCondition(plan, passwordMode),
  )).returning();
  return reserved || null;
}

async function reserveAccountClaim(
  record: AccountProvisioningRow,
  proofHash: string,
  passwordMode: AccountClaimPasswordMode,
  passwordHash: string | null,
): Promise<AccountClaimReservation | null> {
  const plan = accountClaimReservationPlan(record, passwordMode, passwordHash);
  if (!plan) return null;
  const reserved = await persistAccountClaimReservation(record, proofHash, passwordMode, plan);
  const reservationIsUsable = reserved
    && sourceStatusAllowsClaim(reserved.sourceStatus)
    && Boolean(reserved.initialPasswordEncrypted)
    && (passwordMode !== 'set_on_claim' || Boolean(reserved.userId));
  return reservationIsUsable ? {
    record: reserved,
    operationId: plan.operationId,
    proofHash,
    passwordMode,
    passwordHash,
    passwordApplied: plan.nextState === 'password_applied',
  } : null;
}

function reservationOwnershipCondition(
  reservation: AccountClaimReservation,
  expectedState: Extract<AccountClaimState, 'pending' | 'password_applied'>,
) {
  return and(
    eq(accountProvisioningRecords.id, reservation.record.id),
    eq(accountProvisioningRecords.initialPasswordClaimed, false),
    eq(accountProvisioningRecords.claimProofHash, reservation.proofHash),
    eq(accountProvisioningRecords.claimState, expectedState),
    eq(accountProvisioningRecords.claimMode, reservation.passwordMode),
    eq(accountProvisioningRecords.claimOperationId, reservation.operationId),
    reservation.passwordHash === null
      ? isNull(accountProvisioningRecords.claimPasswordHash)
      : eq(accountProvisioningRecords.claimPasswordHash, reservation.passwordHash),
  );
}

async function releasePasswordReservation(reservation: AccountClaimReservation): Promise<void> {
  await getDb().update(accountProvisioningRecords).set({
    claimState: 'ready',
    claimMode: null,
    claimPasswordHash: null,
    claimOperationId: null,
    claimLeaseExpiresAt: null,
    updatedAt: new Date(),
  }).where(reservationOwnershipCondition(reservation, 'pending'));
}

async function markClaimPasswordApplied(reservation: AccountClaimReservation): Promise<void> {
  const [applied] = await getDb().update(accountProvisioningRecords).set({
    claimState: 'password_applied',
    updatedAt: new Date(),
  }).where(reservationOwnershipCondition(reservation, 'pending')).returning();
  if (!applied) throw new Error('Account claim password reservation was lost');
}

async function markClaimPasswordUpdateUnknown(reservation: AccountClaimReservation): Promise<void> {
  const [unknown] = await getDb().update(accountProvisioningRecords).set({
    claimState: 'password_update_unknown',
    claimLeaseExpiresAt: null,
    updatedAt: new Date(),
  }).where(reservationOwnershipCondition(reservation, 'pending')).returning();
  if (!unknown) throw new Error('Account claim password recovery state was lost');
}

function finalizedClaimValues() {
  return {
    initialPasswordClaimed: true,
    initialPasswordEncrypted: null,
    claimedAt: new Date(),
    claimCount: sql`${accountProvisioningRecords.claimCount} + 1`,
    claimProofHash: null,
    claimState: 'claimed',
    claimMode: null,
    claimPasswordHash: null,
    claimOperationId: null,
    claimLeaseExpiresAt: null,
    updatedAt: new Date(),
  } as const;
}

async function finalizeAccountClaim(
  reservation: AccountClaimReservation,
  expectedState: Extract<AccountClaimState, 'pending' | 'password_applied'>,
): Promise<void> {
  const [claimed] = await getDb().update(accountProvisioningRecords).set(finalizedClaimValues())
    .where(reservationOwnershipCondition(reservation, expectedState))
    .returning();
  if (!claimed) throw new Error('Account claim reservation was lost');
}

async function auditAccountClaim(
  reservation: AccountClaimReservation,
  input: AccountClaimInput,
  passwordMode: AccountClaimPasswordMode,
): Promise<void> {
  const record = reservation.record;
  await logAudit({
    eventType: 'account_provisioning.claimed',
    actorId: record.userId || record.email,
    actorType: 'user',
    resourceType: 'account_provisioning_record',
    resourceId: `${record.externalType}:${record.externalId}`,
    details: {
      email: record.email,
      ip: input.ip || null,
      user_agent: input.userAgent || null,
      password_mode: passwordMode,
    },
  });
}

async function applyReservedPassword(
  reservation: AccountClaimReservation,
  input: PasswordAccountClaimInput,
): Promise<void> {
  if (reservation.passwordApplied) return;
  const record = reservation.record;
  try {
    await input.updatePassword({
      userId: record.userId!,
      email: record.email,
      externalId: record.externalId,
      externalType: record.externalType,
    }, input.newPassword);
  } catch (error) {
    if (input.isDefinitivePasswordRejection?.(error)) {
      await releasePasswordReservation(reservation);
    } else {
      await markClaimPasswordUpdateUnknown(reservation);
    }
    throw error;
  }
  await markClaimPasswordApplied(reservation);
}

async function completePasswordClaim(
  reservation: AccountClaimReservation,
  input: PasswordAccountClaimInput,
): Promise<AccountClaimResult> {
  await applyReservedPassword(reservation, input);
  await auditAccountClaim(reservation, input, 'set_on_claim');
  await finalizeAccountClaim(reservation, 'password_applied');
  return { status: 'claimed', email: reservation.record.email, passwordSet: true };
}

async function completeInitialPasswordClaim(
  reservation: AccountClaimReservation,
  input: AccountClaimInput,
): Promise<AccountClaimResult> {
  const encryptedPassword = reservation.record.initialPasswordEncrypted;
  if (!encryptedPassword) return { status: 'unavailable' };
  const initialPassword = decryptInitialPassword(encryptedPassword);
  await auditAccountClaim(reservation, input, 'show_initial_password');
  await finalizeAccountClaim(reservation, 'pending');
  return { status: 'claimed', email: reservation.record.email, initialPassword };
}

export async function claimAccount(input: AccountClaimInput): Promise<AccountClaimResult> {
  const claimProof = input.claimProof?.trim();
  if (!claimProof) return { status: 'unavailable' };
  const passwordMode = input.passwordMode || 'show_initial_password';
  const passwordClaimInput = passwordMode === 'set_on_claim' && input.newPassword && input.updatePassword
    ? { ...input, newPassword: input.newPassword, updatePassword: input.updatePassword }
    : null;
  if (passwordMode === 'set_on_claim' && !passwordClaimInput) {
    return { status: 'unavailable' };
  }

  const proofHash = hashAccountClaimProof(claimProof);
  const record = await findAccountByClaimProof(input, proofHash);
  if (!record || !sourceStatusAllowsClaim(record.sourceStatus)) return { status: 'unavailable' };
  if (!record.initialPasswordEncrypted || (passwordMode === 'set_on_claim' && !record.userId)) {
    return { status: 'unavailable' };
  }

  const passwordHash = passwordClaimInput ? hashClaimPassword(passwordClaimInput.newPassword) : null;
  const reservation = await reserveAccountClaim(record, proofHash, passwordMode, passwordHash);
  if (!reservation) return { status: 'unavailable' };
  return passwordClaimInput
    ? completePasswordClaim(reservation, passwordClaimInput)
    : completeInitialPasswordClaim(reservation, input);
}

export async function listAccountProvisioningRecords(limit = 100, offset = 0) {
  const db = getDb();
  return db.select({
    id: accountProvisioningRecords.id,
    externalId: accountProvisioningRecords.externalId,
    externalType: accountProvisioningRecords.externalType,
    displayName: accountProvisioningRecords.displayName,
    email: accountProvisioningRecords.email,
    userId: accountProvisioningRecords.userId,
    initialPasswordClaimed: accountProvisioningRecords.initialPasswordClaimed,
    claimedAt: accountProvisioningRecords.claimedAt,
    claimState: accountProvisioningRecords.claimState,
    claimMode: accountProvisioningRecords.claimMode,
    claimOperationId: accountProvisioningRecords.claimOperationId,
    claimLeaseExpiresAt: accountProvisioningRecords.claimLeaseExpiresAt,
    sourceStatus: accountProvisioningRecords.sourceStatus,
    profile: accountProvisioningRecords.profile,
    importBatch: accountProvisioningRecords.importBatch,
    createdAt: accountProvisioningRecords.createdAt,
    updatedAt: accountProvisioningRecords.updatedAt,
  }).from(accountProvisioningRecords).limit(limit).offset(offset);
}

// ─── Employee status sync queries ───────────────────────────────────────

/** Find a provisioning record by external_id alone (no display_name needed). */
export async function findRecordByExternalId(externalId: string, externalType = 'employee') {
  const db = getDb();
  const rows = await db.select().from(accountProvisioningRecords)
    .where(and(
      eq(accountProvisioningRecords.externalId, normalizeExternalId(externalId)),
      eq(accountProvisioningRecords.externalType, externalType),
    ))
    .limit(1);
  return rows[0] || null;
}

/** Update just the source_status of a provisioning record. */
export async function updateRecordSourceStatus(id: string, sourceStatus: string) {
  const db = getDb();
  const [updated] = await db.update(accountProvisioningRecords).set({
    sourceStatus,
    updatedAt: new Date(),
  }).where(eq(accountProvisioningRecords.id, id)).returning();
  return updated;
}

/** List records whose source_status differs from the provided map, or whose
 *  display_name / email has changed. Returns all records if no since date. */
export async function listRecordsForSync(options?: {
  externalType?: string;
  since?: Date;
  limit?: number;
  offset?: number;
}) {
  const db = getDb();
  const type = options?.externalType || 'employee';
  let query = db.select().from(accountProvisioningRecords)
    .where(eq(accountProvisioningRecords.externalType, type));

  // If since date provided, only return records updated after that date
  if (options?.since) {
    query = db.select().from(accountProvisioningRecords)
      .where(and(
        eq(accountProvisioningRecords.externalType, type),
        sql`${accountProvisioningRecords.updatedAt} > ${options.since}`,
      ));
  }

  return query
    .limit(Math.min(options?.limit || 500, 1000))
    .offset(options?.offset || 0);
}

/** Count provisioning records by source_status. */
export async function countBySourceStatus(externalType = 'employee') {
  const db = getDb();
  const rows = await db.select({
    sourceStatus: accountProvisioningRecords.sourceStatus,
    count: sql<number>`count(*)::int`,
  }).from(accountProvisioningRecords)
    .where(eq(accountProvisioningRecords.externalType, externalType))
    .groupBy(accountProvisioningRecords.sourceStatus);
  const result: Record<string, number> = {};
  for (const row of rows) result[row.sourceStatus] = row.count;
  return result;
}
