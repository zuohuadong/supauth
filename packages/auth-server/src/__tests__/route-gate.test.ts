// P0-29: Route/domain integration gate tests

import { describe, it, expect, mock } from 'bun:test';

describe('P0-29: Route Gate', () => {
  const publicLookup = async () => [{ address: '93.184.216.34', family: 4 as const }];

  it('runIntegrationGate returns expected structure', async () => {
    // Mock fetch to simulate healthy responses
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/auth/v1/health')) {
        return Promise.resolve(new Response('{"code":200,"status":"ok"}', { status: 200 }));
      }
      if (url.includes('/rest/v1/')) {
        return Promise.resolve(new Response('[]', { status: 200 }));
      }
      if (url.includes('/storage/v1/bucket')) {
        return Promise.resolve(new Response('[]', { status: 200 }));
      }
      if (url.includes('/realtime/v1/websocket')) {
        return Promise.resolve(new Response('ok', { status: 426 }));
      }
      if (url.includes('/functions/v1/')) {
        return Promise.resolve(new Response('not found', { status: 404 }));
      }
      if (url.includes('/api/v1/health')) {
        return Promise.resolve(new Response('{"status":"ok"}', { status: 200 }));
      }
      if (url.includes('/api/swagger')) {
        return Promise.resolve(new Response('<html></html>', { status: 200 }));
      }
      if (url.includes('/admin')) {
        return Promise.resolve(new Response('ok', { status: 200 }));
      }
      if (url.includes('/api/v1/applications')) {
        return Promise.resolve(new Response('{"error":"unauthorized"}', { status: 401 }));
      }
      return Promise.resolve(new Response('ok', { status: 200 }));
    }) as unknown as typeof fetch;

    // Dynamically import to use mocked fetch
    const { runIntegrationGate } = await import('../routes/route-gate.js');

    const result = await runIntegrationGate(
      'test-project-12345',
      'http://admin.test',
      'http://runtime.test',
      ['https://business.test'],
      { lookup: publicLookup },
    );

    expect(result).toHaveProperty('timestamp');
    expect(result).toHaveProperty('projectRef');
    expect(result).toHaveProperty('routes');
    expect(result).toHaveProperty('domainAudit');
    expect(result).toHaveProperty('envAudit');
    expect(result).toHaveProperty('allPassed');
    expect(result).toHaveProperty('conflicts');
    expect(result.projectRef).toBe('test-project-12345');
    expect(Array.isArray(result.routes)).toBe(true);
    expect(Array.isArray(result.domainAudit)).toBe(true);
    expect(Array.isArray(result.conflicts)).toBe(true);
    expect(result.envAudit.supauthUrl).toBe('http://admin.test');
    expect(result.envAudit.runtimeUrl).toBe('http://runtime.test');
    expect(result.envAudit.extraDomains).toEqual(['https://business.test']);
    expect(result.domainAudit.some(domain => domain.domain === 'business.test')).toBe(true);

    globalThis.fetch = originalFetch;
  });

  it('detects upstream failures as conflicts', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes('/auth/v1/health')) {
        return Promise.resolve(new Response('ok', { status: 200 }));
      }
      if (url.includes('/rest/v1/')) {
        return Promise.resolve(new Response('upstream error', { status: 502 }));
      }
      if (url.includes('/storage/v1/bucket')) {
        return Promise.resolve(new Response('[]', { status: 200 }));
      }
      if (url.includes('/api/v1/health')) {
        return Promise.resolve(new Response('ok', { status: 200 }));
      }
      return Promise.resolve(new Response('ok', { status: 200 }));
    }) as unknown as typeof fetch;

    const { runIntegrationGate } = await import('../routes/route-gate.js');

    const result = await runIntegrationGate(
      'test-project-conflict',
      'http://admin.test',
      'http://runtime.test',
      [],
      { lookup: publicLookup },
    );

    expect(result.allPassed).toBe(false);
    expect(result.conflicts.length).toBeGreaterThan(0);
    expect(result.conflicts.some(c => c.includes('upstream error') || c.includes('502'))).toBe(true);

    globalThis.fetch = originalFetch;
  });

  it('normalizes trailing slashes in target URLs', async () => {
    const originalFetch = globalThis.fetch;
    const seenUrls: string[] = [];
    globalThis.fetch = mock((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      seenUrls.push(url);
      return Promise.resolve(new Response('ok', { status: url.includes('/v1/applications') ? 401 : 200 }));
    }) as unknown as typeof fetch;

    const { runIntegrationGate } = await import('../routes/route-gate.js');
    const result = await runIntegrationGate(
      'test-project-normalized',
      'http://admin.test/',
      'http://runtime.test/',
      [],
      { lookup: publicLookup },
    );

    expect(result.envAudit.supauthUrl).toBe('http://admin.test');
    expect(result.envAudit.runtimeUrl).toBe('http://runtime.test');
    expect(seenUrls.every(url => !url.includes('test//'))).toBe(true);
    expect(seenUrls.some(url => url.includes('/oauth/authorize'))).toBe(true);
    expect(seenUrls.some(url => url.includes('/v1/oauth/authorize'))).toBe(false);
    expect(seenUrls.some(url => url.includes('/api/v1/health'))).toBe(true);
    expect(seenUrls.some(url => url.includes('/v1/sign-in-experience/public'))).toBe(false);

    globalThis.fetch = originalFetch;
  });

  it('rejects private and loopback targets before any fetch', async () => {
    const { validateRouteGateTarget } = await import('../routes/route-gate.js');

    await expect(validateRouteGateTarget('http://127.0.0.1')).rejects.toThrow('resolves to');
    await expect(validateRouteGateTarget('http://10.0.0.1')).rejects.toThrow('resolves to');
    await expect(validateRouteGateTarget('http://[::1]')).rejects.toThrow('resolves to');
    await expect(validateRouteGateTarget(
      'https://public-looking.test',
      async () => [{ address: '169.254.169.254', family: 4 as const }],
    )).rejects.toThrow('resolves to');
  });

  it('rejects credentials, query strings, and non-http schemes', async () => {
    const { validateRouteGateTarget } = await import('../routes/route-gate.js');
    const lookup = async () => [{ address: '93.184.216.34', family: 4 as const }];

    await expect(validateRouteGateTarget('https://user:pass@example.test', lookup)).rejects.toThrow('without credentials');
    await expect(validateRouteGateTarget('https://example.test/?token=secret', lookup)).rejects.toThrow('query or fragment');
    await expect(validateRouteGateTarget('file:///etc/passwd', lookup)).rejects.toThrow('http(s)');
  });

  it('ignores request-supplied target overrides and uses registered environment targets', async () => {
    const { resolveRouteGateInput } = await import('../routes/route-gate.js');
    const names = [
      'SUPAOAUTH_ROUTE_GATE_ADMIN_URL',
      'SUPAOAUTH_ROUTE_GATE_RUNTIME_URL',
      'SUPAOAUTH_ROUTE_GATE_DOMAINS',
    ] as const;
    const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
    try {
      process.env.SUPAOAUTH_ROUTE_GATE_ADMIN_URL = 'https://registered-admin.test';
      process.env.SUPAOAUTH_ROUTE_GATE_RUNTIME_URL = 'https://registered-runtime.test';
      process.env.SUPAOAUTH_ROUTE_GATE_DOMAINS = 'https://registered-business.test';

      expect(resolveRouteGateInput({
        supauth_url: 'http://127.0.0.1:9',
        runtime_url: 'http://169.254.169.254',
        domains: 'http://10.0.0.1',
        project_ref: 'registered-project',
      })).toEqual({
        projectRef: 'registered-project',
        supauthUrl: 'https://registered-admin.test',
        runtimeUrl: 'https://registered-runtime.test',
        extraDomains: ['https://registered-business.test'],
      });
    } finally {
      for (const name of names) {
        if (previous[name] === undefined) delete process.env[name];
        else process.env[name] = previous[name];
      }
    }
  });

  it('does not follow redirects to private or cross-origin targets', async () => {
    const originalFetch = globalThis.fetch;
    const seenUrls: string[] = [];
    globalThis.fetch = mock((input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      seenUrls.push(url);
      return Promise.resolve(new Response('', {
        status: 302,
        headers: { location: 'http://169.254.169.254/latest/meta-data/' },
      }));
    }) as unknown as typeof fetch;

    try {
      const { runIntegrationGate } = await import('../routes/route-gate.js');
      const result = await runIntegrationGate(
        'test-project-redirect',
        'https://admin.test',
        'https://runtime.test',
        [],
        { lookup: publicLookup },
      );

      expect(result.allPassed).toBe(false);
      expect(seenUrls.length).toBeGreaterThan(0);
      expect(seenUrls.every(url => !url.includes('169.254.169.254'))).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
