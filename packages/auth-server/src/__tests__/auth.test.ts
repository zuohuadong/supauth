import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { Elysia } from 'elysia';
import { principalHasAction, requiredAdminAction } from '../auth/admin-permissions.js';

const getSecurityConfig = mock(async () => null);
mock.module('../repositories/security-config.js', () => ({ getSecurityConfig }));

const {
  ADMIN_SSO_ALLOWLIST_ERROR_MESSAGE,
  ADMIN_SSO_DOMAIN_ALLOWLIST_ERROR_MESSAGE,
  adminPrincipalFromSession,
  adminSessionFromPayload,
  adminAuthorizationFailureResponse,
  adminPermissionFailureResponse,
  projectedAdminClaimStrings,
  resolveSsoAllowlistConfigurationError,
  resolveSsoAdminAccess,
  resolveSsoAudiences,
  verifyAdminBearer,
  authRoutes,
} = await import('../auth/index.js');
const { parseAdminSsoRequireAal2 } = await import('../auth/admin-sso-aal2-policy.js');
const { loadConfig } = await import('../config/index.js');

describe('Auth module — exported functions', () => {
  beforeEach(() => {
    process.env.ADMIN_TOKEN = 'test-admin-token';
    process.env.ADMIN_AUTH_MODE = 'auto';
    process.env.NODE_ENV = 'test';
    delete process.env.ADMIN_SSO_ISSUER;
    delete process.env.ADMIN_SSO_CLIENT_ID;
    delete process.env.ADMIN_SSO_JWKS_URI;
    delete process.env.ADMIN_SSO_REQUIRE_AAL2;
    delete process.env.ADMIN_SSO_ALLOWED_EMAILS;
    delete process.env.ADMIN_SSO_ALLOWED_DOMAINS;
    process.env.PROJECT_REF = 'project-one';
    loadConfig();
  });

  describe('verifyAdminBearer', () => {
    it('returns unauthenticated when no authorization header', async () => {
      const result = await verifyAdminBearer({});
      expect(result).toEqual({ status: 'unauthenticated' });
    });

    it('returns unauthenticated when authorization header has no Bearer prefix', async () => {
      const result = await verifyAdminBearer({ authorization: 'Basic abc123' });
      expect(result).toEqual({ status: 'unauthenticated' });
    });

    it('returns unauthenticated when Bearer token is not a known session or SSO token', async () => {
      const result = await verifyAdminBearer({ authorization: 'Bearer unknown-token' });
      expect(result).toEqual({ status: 'unauthenticated' });
    });

    it('returns unauthenticated for empty Bearer token', async () => {
      const result = await verifyAdminBearer({ authorization: 'Bearer ' });
      expect(result).toEqual({ status: 'unauthenticated' });
    });
  });

  it('accepts the Function-scoped admin token alias', async () => {
    const previousToken = process.env.ADMIN_TOKEN;
    const previousScopedToken = process.env.EDGEFN_SUPAUTH_ADMIN_TOKEN;
    try {
      delete process.env.ADMIN_TOKEN;
      process.env.EDGEFN_SUPAUTH_ADMIN_TOKEN = 'scoped-admin-token';

      const response = await authRoutes.handle(new Request('http://localhost/v1/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: 'scoped-admin-token' }),
      }));

      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ success: true });
    } finally {
      if (previousToken === undefined) delete process.env.ADMIN_TOKEN;
      else process.env.ADMIN_TOKEN = previousToken;
      if (previousScopedToken === undefined) delete process.env.EDGEFN_SUPAUTH_ADMIN_TOKEN;
      else process.env.EDGEFN_SUPAUTH_ADMIN_TOKEN = previousScopedToken;
    }
  });
});

describe('Auth module — project-scoped schema v2 claims', () => {
  beforeEach(() => {
    delete process.env.SUPACLOUD_AUTH_AUTHORITY_REF;
    delete process.env.SUPAUTH_OAUTH_AUTHORIZATION_PROJECT_REF;
    process.env.PROJECT_REF = 'project-one';
    loadConfig();
  });

  it('prefers the SupaCloud auth authority ref for the existing authority setting', () => {
    process.env.SUPACLOUD_AUTH_AUTHORITY_REF = 'authority-project';
    process.env.SUPAUTH_OAUTH_AUTHORIZATION_PROJECT_REF = 'legacy-authority-project';

    expect(loadConfig().oauthAuthorizationProjectRef).toBe('authority-project');
  });

  it('reads roles and permissions only from the configured project', () => {
    const payload = {
      app_metadata: {
        supaoauth: {
          schema_version: 2,
          projects: {
            'project-one': { roles: ['admin'], permissions: ['users.read'] },
            'project-two': { roles: ['owner'], permissions: ['users.manage'] },
          },
        },
      },
    };

    expect(projectedAdminClaimStrings(payload, 'roles')).toEqual(['admin']);
    expect(projectedAdminClaimStrings(payload, 'permissions')).toEqual(['users.read']);
  });

  it('fails closed for root-level v1 claims and missing project entries', () => {
    const rootV1 = { app_metadata: { supaoauth: { roles: ['admin'], permissions: ['*'] } } };
    const missingProject = {
      app_metadata: {
        supaoauth: {
          schema_version: 2,
          projects: { 'project-two': { roles: ['owner'], permissions: ['*'] } },
        },
      },
    };

    expect(projectedAdminClaimStrings(rootV1, 'roles')).toEqual([]);
    expect(projectedAdminClaimStrings(missingProject, 'permissions')).toEqual([]);
  });

  it('fails closed for unavailable and field-truncated project projections', () => {
    const payload = {
      app_metadata: {
        supaoauth: {
          schema_version: 2,
          projects: {
            'project-one': {
              roles: ['must-not-pass'],
              permissions: ['must-not-pass'],
              projection_unavailable: true,
              roles_truncated: true,
              permissions_truncated: true,
            },
          },
        },
      },
    };

    expect(projectedAdminClaimStrings(payload, 'roles')).toEqual([]);
    expect(projectedAdminClaimStrings(payload, 'permissions')).toEqual([]);
  });

  it('fails closed for malformed or oversized project projection lists', () => {
    const payload = {
      app_metadata: {
        supaoauth: {
          schema_version: 2,
          projects: {
            'project-one': {
              roles: ['admin', 'admin'],
              permissions: Array.from({ length: 257 }, (_, index) => `permission-${index}`),
            },
          },
        },
      },
    };

    expect(projectedAdminClaimStrings(payload, 'roles')).toEqual([]);
    expect(projectedAdminClaimStrings(payload, 'permissions')).toEqual([]);
  });

  it('does not turn invalid, missing, or unavailable project projections into wildcard access', () => {
    const payloads = [
      { app_metadata: { supaoauth: { roles: ['admin'], permissions: ['*'] } } },
      { app_metadata: { supaoauth: { schema_version: 2, projects: {} } } },
      {
        app_metadata: {
          supaoauth: {
            schema_version: 2,
            projects: { 'project-one': { projection_unavailable: true } },
          },
        },
      },
    ];

    for (const payload of payloads) {
      const session = adminSessionFromPayload(payload);
      const principal = adminPrincipalFromSession(session);
      expect(principal.authorization_source).toBe('rbac_projection');
      expect(principal.roles).toEqual([]);
      expect(principal.permissions).toEqual([]);
    }
  });

  it('keeps explicit allowlist wildcard semantics for tokens without a SupaOAuth namespace', () => {
    const session = adminSessionFromPayload({ app_metadata: { provider: 'email' } });
    const principal = adminPrincipalFromSession(session);

    expect(principal.authorization_source).toBe('admin_allowlist');
    expect(principal.permissions).toEqual(['*']);
  });
});

describe('Auth module — SSO audience resolution', () => {
  it('uses the OIDC client id as the generic default audience', () => {
    expect(resolveSsoAudiences({
      issuer: 'https://idp.example.test',
      clientId: 'admin-client',
    })).toEqual(['admin-client']);
  });

  it('accepts GoTrue access-token audience for hosted auth issuers', () => {
    expect(resolveSsoAudiences({
      issuer: 'https://auth.example.test/auth/v1',
      clientId: 'admin-client',
    })).toEqual(['admin-client', 'authenticated']);
  });

  it('keeps explicit non-client audiences strict', () => {
    expect(resolveSsoAudiences({
      configuredAudience: 'supaoauth-admin-api',
      issuer: 'https://auth.example.test/auth/v1',
      clientId: 'admin-client',
    })).toEqual(['supaoauth-admin-api']);
  });

  it('treats legacy client-id audience config as compatible with GoTrue access tokens', () => {
    expect(resolveSsoAudiences({
      configuredAudience: 'admin-client',
      issuer: 'https://auth.example.test/auth/v1',
      clientId: 'admin-client',
    })).toEqual(['admin-client', 'authenticated']);
  });
});

describe('Auth module — SSO administrator allowlist', () => {
  const verifiedSession = {
    id: 'user-1',
    email: 'member@example.test',
    name: 'Member',
    role: 'admin',
    authenticated: true,
  };

  it('fails closed with an explicit configuration error when enabled without an allowlist', () => {
    expect(resolveSsoAllowlistConfigurationError({
      enabled: true,
      emails: [],
      domains: [],
    })).toBe(ADMIN_SSO_ALLOWLIST_ERROR_MESSAGE);
  });

  it('does not affect token mode or a configured exact email allowlist', () => {
    expect(resolveSsoAllowlistConfigurationError({
      enabled: false,
      emails: [],
      domains: [],
    })).toBeNull();
    expect(resolveSsoAllowlistConfigurationError({
      enabled: true,
      emails: ['admin@example.test'],
      domains: [],
    })).toBeNull();
    expect(resolveSsoAllowlistConfigurationError({
      enabled: true,
      emails: [],
      domains: ['example.test'],
    })).toBe(ADMIN_SSO_DOMAIN_ALLOWLIST_ERROR_MESSAGE);
    expect(resolveSsoAllowlistConfigurationError({
      enabled: true,
      emails: ['admin@example.test'],
      domains: ['example.test'],
    })).toBe(ADMIN_SSO_DOMAIN_ALLOWLIST_ERROR_MESSAGE);
  });

  it('classifies a verified user outside the allowlist as forbidden', () => {
    expect(resolveSsoAdminAccess({ aal: 'aal2' }, verifiedSession, {
      emails: ['admin@example.test'],
      domains: ['trusted.example.test'],
    })).toEqual({ status: 'forbidden', reason: 'admin_access_forbidden' });
  });

  it('does not expose the MFA enrollment path to an AAL1 user outside the allowlist', () => {
    expect(resolveSsoAdminAccess({ aal: 'aal1' }, verifiedSession, {
      emails: ['admin@example.test'],
      domains: [],
    })).toEqual({ status: 'forbidden', reason: 'admin_access_forbidden' });
  });

  it('accepts a verified user whose email is explicitly allowed', () => {
    expect(resolveSsoAdminAccess({ aal: 'aal2' }, verifiedSession, {
      emails: ['member@example.test'],
      domains: [],
    })).toEqual({ status: 'authenticated', session: verifiedSession });
  });

  it('requires an exact lowercase aal2 claim only when the server policy is explicitly enabled', () => {
    for (const aal of ['aal1', 'AAL2', undefined, 2, null]) {
      expect(resolveSsoAdminAccess({ aal }, verifiedSession, {
        emails: ['member@example.test'],
        domains: [],
      }, { requireAal2: true })).toEqual({ status: 'forbidden', reason: 'admin_mfa_required' });
    }
  });

  it('allows an exact-email administrator at aal1 when AAL2 policy is disabled', () => {
    expect(resolveSsoAdminAccess({ aal: 'aal1' }, verifiedSession, {
      emails: ['member@example.test'],
      domains: [],
    }, { requireAal2: false })).toEqual({ status: 'authenticated', session: verifiedSession });
  });

  it('enables AAL2 only for an explicit true environment value and rejects invalid values', () => {
    for (const value of [undefined, '', 'false', ' FALSE ']) {
      expect(parseAdminSsoRequireAal2(value)).toBe(false);
    }
    for (const value of ['true', ' TRUE ']) {
      expect(parseAdminSsoRequireAal2(value)).toBe(true);
    }
    for (const value of ['0', 'yes', 'invalid']) {
      expect(() => parseAdminSsoRequireAal2(value)).toThrow('ADMIN_SSO_REQUIRE_AAL2');
    }
  });

  it('does not authorize a legacy domain allowlist', () => {
    expect(resolveSsoAdminAccess({ aal: 'aal2' }, verifiedSession, {
      emails: [],
      domains: ['example.test'],
    })).toEqual({ status: 'forbidden', reason: 'admin_access_forbidden' });
  });

  it('returns a structured 403 response for a forbidden admin identity', async () => {
    const response = await adminAuthorizationFailureResponse({
      status: 'forbidden',
      reason: 'admin_access_forbidden',
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      success: false,
      error: {
        code: 'admin_access_forbidden',
        message: '当前账号没有访问管理控制台的权限。',
      },
    });
  });

  it('returns an actionable structured 403 response when MFA is required', async () => {
    const response = await adminAuthorizationFailureResponse({
      status: 'forbidden',
      reason: 'admin_mfa_required',
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({
      success: false,
      error: {
        code: 'admin_mfa_required',
        required_aal: 'aal2',
        message: '管理员必须完成双因素认证。请在管理后台的 MFA 绑定页面完成 GoTrue TOTP 验证。',
      },
    });
  });
});

describe('Auth module — guard and route structure', () => {
  it('exports adminAuthGuard as Elysia instance', async () => {
    const { adminAuthGuard } = await import('../auth/index.js');
    expect(adminAuthGuard).toBeDefined();
    // Elysia instances have a fetch method or similar
    expect(typeof adminAuthGuard.fetch).toBe('function');
  });

  it('exports authRoutes as Elysia instance', async () => {
    const { authRoutes } = await import('../auth/index.js');
    expect(authRoutes).toBeDefined();
    expect(typeof authRoutes.fetch).toBe('function');
  });

  it('keeps auth-config protected while leaving auth routes public', async () => {
    const { adminAuthGuard } = await import('../auth/index.js');
    const app = new Elysia()
      .use(adminAuthGuard)
      .get('/v1/auth/login', () => 'public auth')
      .get('/v1/auth-config', () => 'protected auth config')
      .get('/v1/auth-config/runtime-consistency', () => 'protected runtime consistency');

    const authRoute = await app.handle(new Request('http://localhost/v1/auth/login'));
    expect(authRoute.status).toBe(200);

    const authConfig = await app.handle(new Request('http://localhost/v1/auth-config'));
    expect(authConfig.status).toBe(401);

    const runtimeConsistency = await app.handle(new Request('http://localhost/v1/auth-config/runtime-consistency'));
    expect(runtimeConsistency.status).toBe(401);
  });

  it('keeps the Admin SPA runtime SSO config public', async () => {
    const { adminAuthGuard } = await import('../auth/index.js');
    const app = new Elysia()
      .use(adminAuthGuard)
      .get('/v1/public/admin-sso-config', () => ({ enabled: true }));

    const response = await app.handle(new Request('http://localhost/v1/public/admin-sso-config'));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ enabled: true });
  });

  it('accepts the case-insensitive Bearer scheme from OAuth token responses', async () => {
    process.env.ADMIN_TOKEN = 'request-scoped-admin-token';
    const { adminAuthGuard, authRoutes } = await import('../auth/index.js');
    const app = new Elysia()
      .use(authRoutes)
      .use(adminAuthGuard)
      .get('/v1/users/principal-probe', ({ adminPrincipal }) => adminPrincipal);

    const login = await app.handle(new Request('http://localhost/v1/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'request-scoped-admin-token' }),
    }));
    const loginPayload = await login.json() as { token: string };
    const response = await app.handle(new Request('http://localhost/v1/users/principal-probe', {
      headers: { authorization: `bearer ${loginPayload.token}`, 'x-request-id': 'principal-request' },
    }));
    const principal = await response.json() as { id: string; authorization_source: string; permissions: string[] };

    expect(response.status).toBe(200);
    expect(principal.id).toBe('admin');
    expect(principal.authorization_source).toBe('development_token');
    expect(principal.permissions).toEqual(['*']);
  });

  it('returns the required action and request correlation in permission failures', async () => {
    const response = adminPermissionFailureResponse('users.manage', 'permission-request');
    const payload = await response.json() as {
      error: { code: string; correlation_id: string; details: { required_action: string } };
    };

    expect(response.status).toBe(403);
    expect(payload.error.code).toBe('insufficient_permissions');
    expect(payload.error.correlation_id).toBe('permission-request');
    expect(payload.error.details.required_action).toBe('users.manage');
  });
});

describe('Auth module — management action permissions', () => {
  it('maps sensitive actions to platform collaborator capability names', () => {
    expect(requiredAdminAction('GET', '/v1/organizations')).toBe('organizations.read');
    expect(requiredAdminAction('PATCH', '/v1/organizations/org-one')).toBe('organizations.manage');
    expect(requiredAdminAction('POST', '/v1/audit/export')).toBe('audit.export');
    expect(requiredAdminAction('GET', '/v1/audit/export/export-one/download')).toBe('audit.export');
    expect(requiredAdminAction('GET', '/v1/audit/log-one')).toBe('audit.read_sensitive');
    expect(requiredAdminAction('POST', '/v1/webhooks/wh-one/deliveries/del-one/replay')).toBe('webhooks.replay');
    expect(requiredAdminAction('GET', '/v1/tenant/members')).toBe('tenant.members.read');
    expect(requiredAdminAction('DELETE', '/v1/tenant/members/member-one')).toBe('tenant.members.manage');
    expect(requiredAdminAction('POST', '/v1/organizations/org-one/invitations')).toBe('organizations.members.manage');
    expect(requiredAdminAction('PATCH', '/v1/organizations/org-one/jit')).toBe('organizations.settings.manage');
    expect(requiredAdminAction('GET', '/v1/enterprise-sso')).toBe('connectors.read');
    expect(requiredAdminAction('PATCH', '/v1/auth-hooks/config')).toBe('security.manage');
    expect(requiredAdminAction('GET', '/v1/tenant-config')).toBe('tenant_config.read');
    expect(requiredAdminAction('POST', '/v1/unmapped-management-route')).toBe('operations.manage');
    expect(requiredAdminAction('GET', '/not-management')).toBeNull();
  });

  it('does not let webhooks.manage implicitly grant exact replay permission', () => {
    expect(principalHasAction({
      id: 'admin-one',
      email: 'admin@example.test',
      name: 'Admin',
      roles: ['admin'],
      permissions: ['webhooks.manage'],
      authorization_source: 'rbac_projection',
    }, 'webhooks.replay')).toBe(false);
  });
});
