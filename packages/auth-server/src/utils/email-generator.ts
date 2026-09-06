// Email generator — converts Chinese display names to pinyin-based email addresses
// with duplicate-suffix logic: zhangsan@example.com / zhangsan.0231@example.com

import { pinyin } from 'pinyin-pro';
import { runtimeEnv } from '../config/platform-env.js';

export interface EmailGeneratorOptions {
  domain: string;
  /** Separator between name and disambiguation suffix (default: '.') */
  suffixSeparator: string;
  /** Min digits for numeric suffix (default: 4) */
  suffixMinDigits: number;
}

const DEFAULT_OPTIONS: EmailGeneratorOptions = {
  domain: runtimeEnv('SUPAUTH_ACCOUNT_PROVISIONING_EMAIL_DOMAIN')
    || runtimeEnv('ACCOUNT_PROVISIONING_EMAIL_DOMAIN')
    || 'example.com',
  suffixSeparator: '.',
  suffixMinDigits: 4,
};

/**
 * Convert a Chinese (or mixed) display name to a pinyin base slug.
 * E.g. "张三" → "zhangsan", "王小明" → "wangxiaoming"
 * Non-CJK characters are lowercased and kept as-is.
 */
export function nameToPinyinBase(displayName: string): string {
  // Get pinyin for each character; non-CJK chars pass through
  const parts = pinyin(displayName, { toneType: 'none', type: 'array' });
  // Join consecutive pinyin syllables, keep non-CJK chars as-is
  let result = '';
  let lastWasPinyin = false;
  for (const part of parts) {
    if (part && /^[a-zA-Z]+$/.test(part)) {
      if (lastWasPinyin) {
        result += part.toLowerCase();
      } else {
        result += part.toLowerCase();
      }
      lastWasPinyin = true;
    } else {
      // Non-pinyin character (number, symbol, etc.)
      const lower = part.toLowerCase().replace(/[^a-z0-9]/g, '');
      result += lower;
      lastWasPinyin = false;
    }
  }
  return result || 'user';
}

/**
 * Format a numeric suffix with zero-padding.
 * E.g. formatSuffix(231, 4) → "0231"
 */
export function formatSuffix(value: number | string, minDigits: number): string {
  const num = typeof value === 'string' ? parseInt(value, 10) : value;
  if (isNaN(num)) return String(value);
  return String(num).padStart(minDigits, '0');
}

/**
 * Generate a unique email for a display name, avoiding collisions with existing emails.
 *
 * Strategy:
 * 1. First try: base@domain (e.g. zhangsan@example.com)
 * 2. If collision: try base.suffix@domain using external_id tail (e.g. zhangsan.0231@example.com)
 * 3. If still collides: increment suffix numerically
 *
 * @param displayName - The employee's display name (e.g. "张三")
 * @param existingEmails - Set of already-taken email local parts (before @domain)
 * @param externalId - The employee's unique ID, used for disambiguation suffix
 * @param options - Email generation options
 */
export function generateUniqueEmail(
  displayName: string,
  existingEmails: Set<string>,
  externalId: string,
  options?: Partial<EmailGeneratorOptions>,
): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const base = nameToPinyinBase(displayName);
  const domain = opts.domain;

  // Try the clean base first
  if (!existingEmails.has(base)) {
    return `${base}@${domain}`;
  }

  // Collision: derive suffix from external_id tail
  const idSuffix = externalId.length >= opts.suffixMinDigits
    ? externalId.slice(-opts.suffixMinDigits)
    : externalId.padStart(opts.suffixMinDigits, '0');

  const suffixed = `${base}${opts.suffixSeparator}${idSuffix}`;
  if (!existingEmails.has(suffixed)) {
    return `${suffixed}@${domain}`;
  }

  // Still collides: increment numerically from 1
  for (let i = 1; i <= 9999; i++) {
    const candidate = `${base}${opts.suffixSeparator}${String(i).padStart(opts.suffixMinDigits, '0')}`;
    if (!existingEmails.has(candidate)) {
      return `${candidate}@${domain}`;
    }
  }

  // Fallback: use full external_id
  return `${base}${opts.suffixSeparator}${externalId}@${domain}`;
}

/**
 * Batch-generate unique emails for a list of import records.
 * Returns a Map from normalizedExternalId to the assigned email.
 * Handles intra-batch dedup correctly.
 */
export function batchGenerateEmails(
  records: Array<{ display_name: string; external_id: string; email?: string }>,
  existingEmails: Set<string>,
  options?: Partial<EmailGeneratorOptions>,
): Map<string, string> {
  const result = new Map<string, string>();
  const usedLocals = new Set(existingEmails);
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Group by pinyin base to handle intra-batch duplicates
  const byBase = new Map<string, Array<{ display_name: string; external_id: string; index: number }>>();
  const indexed = records.map((r, i) => ({ ...r, index: i }));

  for (const record of indexed) {
    // If email is already provided, use it
    if (record.email && record.email.trim()) {
      const localPart = record.email.trim().toLowerCase().split('@')[0];
      usedLocals.add(localPart);
      result.set(normalizeExtId(record.external_id), record.email.trim().toLowerCase());
      continue;
    }
    const base = nameToPinyinBase(record.display_name);
    if (!byBase.has(base)) byBase.set(base, []);
    byBase.get(base)!.push({ display_name: record.display_name, external_id: record.external_id, index: record.index });
  }

  for (const [base, group] of byBase) {
    if (group.length === 1 && !usedLocals.has(base)) {
      // Simple case: no collision
      usedLocals.add(base);
      result.set(normalizeExtId(group[0].external_id), `${base}@${opts.domain}`);
    } else {
      // Multiple records with same base, or base already taken
      for (const entry of group) {
        const email = generateUniqueEmail(entry.display_name, usedLocals, entry.external_id, opts);
        const localPart = email.split('@')[0];
        usedLocals.add(localPart);
        result.set(normalizeExtId(entry.external_id), email);
      }
    }
  }

  return result;
}

function normalizeExtId(id: string): string {
  return id.normalize('NFKC').trim();
}
