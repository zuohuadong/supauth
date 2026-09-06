import { describe, it, expect, afterEach, mock } from 'bun:test';
import { Elysia } from 'elysia';
import { withRequestContext } from '../auth/request-context.js';

describe('Observability — getCurrentRequestId', () => {
  it('returns undefined when no request is active', async () => {
    const { getCurrentRequestId } = await import('../middleware/index.js');
    expect(getCurrentRequestId()).toBeUndefined();
  });

  it('returns the request ID from async-local context', async () => {
    const { getCurrentRequestId } = await import('../middleware/index.js');
    await withRequestContext({ requestId: 'test-req-123' }, async () => {
      await Promise.resolve();
      expect(getCurrentRequestId()).toBe('test-req-123');
    });
    expect(getCurrentRequestId()).toBeUndefined();
  });

  it('keeps concurrent request IDs isolated', async () => {
    const { getCurrentRequestId } = await import('../middleware/index.js');
    const observed = await Promise.all([
      withRequestContext({ requestId: 'request-a' }, async () => {
        await new Promise(resolve => setTimeout(resolve, 5));
        return getCurrentRequestId();
      }),
      withRequestContext({ requestId: 'request-b' }, async () => {
        await Promise.resolve();
        return getCurrentRequestId();
      }),
    ]);
    expect(observed).toEqual(['request-a', 'request-b']);
  });
});

describe('Observability — middleware structure', () => {
  it('exports observabilityMiddleware as Elysia instance', async () => {
    const { observabilityMiddleware } = await import('../middleware/index.js');
    expect(observabilityMiddleware).toBeDefined();
    expect(typeof observabilityMiddleware.fetch).toBe('function');
  });
});

describe('Observability — request ID format', () => {
  it('generates 16-character hex string', () => {
    // Replicate the generateRequestId logic
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    const id = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    expect(id).toHaveLength(16);
    expect(id).toMatch(/^[0-9a-f]{16}$/);
  });

  it('generates unique IDs across calls', () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const bytes = crypto.getRandomValues(new Uint8Array(8));
      ids.add(Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    }
    // 100 random IDs should all be unique
    expect(ids.size).toBe(100);
  });
});

describe('Observability — URL privacy', () => {
  afterEach(() => {
    mock.restore();
    delete process.env.LOG_LEVEL;
  });

  it('does not log OAuth query or fragment components', async () => {
    process.env.LOG_LEVEL = 'debug';
    const { observabilityMiddleware } = await import('../middleware/index.js');
    const info = mock(() => {});
    const originalLog = console.log;
    console.log = info;
    try {
      const app = new Elysia()
        .use(observabilityMiddleware)
        .get('/oauth/callback', () => ({ ok: true }));
      const response = await app.handle(new Request(
        'https://auth.example.test/oauth/callback?code=secret-code&state=secret-state',
      ));

      expect(response.status).toBe(200);
      const entry = JSON.stringify(info.mock.calls);
      expect(entry).toContain('https://auth.example.test/oauth/callback');
      expect(entry).not.toContain('secret-code');
      expect(entry).not.toContain('secret-state');
    } finally {
      console.log = originalLog;
    }
  });
});
