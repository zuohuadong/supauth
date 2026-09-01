import { describe, expect, it } from 'bun:test';
import {
  assertCan,
  AuthorizationForbiddenError,
  AuthorizationUnavailableError,
  can,
  canAll,
  canAny,
  decide,
  permission,
  resolveAuthorization,
  type AuthorizationRequest,
} from './index.js';

const request: AuthorizationRequest = {
  principal: { kind: 'user', issuer: 'https://auth.example.test', subject: 'user-1' },
  applicationId: 'billing-api',
  domain: { type: 'organization', id: 'org-1' },
};

describe('@supauth/authorization-core', () => {
  it('resolves exactly once and decides only from current effective grants', async () => {
    let calls = 0;
    const context = await resolveAuthorization(request, async receivedRequest => {
      calls += 1;
      expect(receivedRequest).toEqual({
        principal: { kind: 'user', issuer: 'https://auth.example.test', subject: 'user-1' },
        applicationId: 'billing-api',
        domain: { type: 'organization', id: 'org-1' },
      });
      expect(Object.isFrozen(receivedRequest)).toBe(true);
      expect(Object.isFrozen(receivedRequest.principal)).toBe(true);
      expect(Object.isFrozen(receivedRequest.domain)).toBe(true);
      // @ts-expect-error The runtime guard backs the public readonly contract.
      expect(() => { receivedRequest.applicationId = 'reporting-api'; }).toThrow();
      return ['invoice:read', 'invoice:update'];
    });

    expect(calls).toBe(1);
    expect(decide(context, permission('invoice:read'))).toMatchObject({ allowed: true, reason: 'granted' });
    expect(can(context, permission('invoice:delete'))).toBe(false);
    expect(canAny(context, [permission('invoice:delete'), permission('invoice:update')])).toBe(true);
    expect(canAll(context, [permission('invoice:read'), permission('invoice:update')])).toBe(true);
    expect(canAll(context, [])).toBe(false);
  });

  it('denies when the current effective grant set is empty', async () => {
    const context = await resolveAuthorization(request, async () => []);
    expect(decide(context, permission('invoice:read'))).toEqual({
      allowed: false,
      reason: 'missing_permission',
      permission: permission('invoice:read'),
    });
    expect(() => assertCan(context, permission('invoice:read'))).toThrow(AuthorizationForbiddenError);
  });

  it('keeps resolver failures in the 503 error class', async () => {
    await expect(resolveAuthorization(request, async () => {
      throw new Error('database offline');
    })).rejects.toMatchObject({ status: 503, code: 'authorization_unavailable' });
  });

  it('maps malformed resolutions to 503 and freezes effective permissions', async () => {
    await expect(resolveAuthorization(request, async () => ['invoice:*']))
      .rejects.toMatchObject({ status: 503, code: 'authorization_unavailable' });
    await expect(resolveAuthorization(request, async () => [42 as unknown as string]))
      .rejects.toBeInstanceOf(AuthorizationUnavailableError);
    await expect(resolveAuthorization(request, async () => null as unknown as string[]))
      .rejects.toBeInstanceOf(AuthorizationUnavailableError);

    const context = await resolveAuthorization(request, async () => ['invoice:read', 'invoice:read']);
    expect(context.permissions).toEqual([permission('invoice:read')]);
    expect(Object.isFrozen(context.permissions)).toBe(true);
    expect(() => (context.permissions as unknown as string[]).push('invoice:delete')).toThrow();
  });

  it('accepts only canonical resource:action permissions', () => {
    expect(String(permission('invoice:read'))).toBe('invoice:read');
    for (const invalid of ['invoice.read', 'invoice:*', '*:read', 'invoice:read:own', 'Invoice:read']) {
      expect(() => permission(invalid)).toThrow(TypeError);
    }
  });
});
