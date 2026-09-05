// Security configuration routes (P0-19) with OpenAPI annotations

import { Elysia } from 'elysia';
import { currentAdminRequestContext } from '../auth/request-context.js';
import { runtimeEnv } from '../config/platform-env.js';
import * as secRepo from '../repositories/security-config.js';
import * as auditRepo from '../repositories/audit.js';
import { validatedSecurityConfigUpdate } from './security-config-input.js';

async function audit(eventType: string, resourceType: string, resourceId: string, details?: Record<string, unknown>) {
  await auditRepo.logAudit({ eventType, resourceType, resourceId, actorType: 'admin', details });
}

export const securityConfigRoutes = new Elysia({ prefix: '/v1/security-config' })
  .get('/', async () => {
    const config = await secRepo.getSecurityConfig();
    if (!config) return new Response('Security config not found. Run migration first.', { status: 404 });
    return config;
  }, {
    detail: { summary: 'Get security configuration', tags: ['Security'] },
  })

  .put('/', async ({ body }) => {
    const principal = currentAdminRequestContext()?.principal;
    const update = validatedSecurityConfigUpdate(body, {
      currentAdminEmail: principal?.email,
      authorizationSource: principal?.authorization_source,
      runtimeEnvironment: runtimeEnv('NODE_ENV') || 'development',
    });
    const updatedConfig = await secRepo.updateSecurityConfig(update);
    await audit('security_config.update', 'security_config', updatedConfig.id, update);
    return updatedConfig;
  }, {
    detail: { summary: 'Update security configuration', tags: ['Security'] },
  })

  .get('/status', async () => {
    const config = await secRepo.getSecurityConfig();
    const tokenAuthAllowed = secRepo.isTokenAuthAllowed(config);

    return {
      admin_auth_mode: config?.adminAuthMode || 'auto',
      token_auth_allowed: tokenAuthAllowed,
      rate_limit_rpm: config?.rateLimitRpm || 300,
      brute_force_protection: config?.bruteForceProtection ?? true,
      enforce_https: config?.enforceHttps ?? true,
      warning_codes: [
        ...(tokenAuthAllowed ? ['admin_token_enabled'] : []),
        ...(!config ? ['security_config_missing'] : []),
      ],
      warnings: [
        ...(tokenAuthAllowed ? ['ADMIN_TOKEN auth is enabled — disable in production by setting admin_auth_mode=sso'] : []),
        ...(!config ? ['Security config not initialized — run migration'] : []),
      ],
    };
  }, {
    detail: { summary: 'Get security status summary', tags: ['Security'] },
  });
