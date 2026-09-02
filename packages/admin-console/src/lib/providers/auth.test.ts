// Bun runs this module directly; the Svelte check does not include Bun's test globals.
// @ts-nocheck
import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import {
  buildAdminEndSessionUrl,
  initializeAdminAuthProvider,
  prepareAdminAuthCallbackRetry,
  resetAdminAuthRuntimeForTests,
} from './auth';

const originalFetch = globalThis.fetch;

function deferredRequest() {
  let resolveRequest;
  const promise = new Promise((resolve) => {
    resolveRequest = resolve;
  });
  return { promise, resolve: resolveRequest };
}

async function waitFor(predicate, message) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await Promise.resolve();
  }
  throw new Error(message);
}

beforeEach(() => {
  resetAdminAuthRuntimeForTests();
});

afterEach(() => {
  resetAdminAuthRuntimeForTests();
  globalThis.fetch = originalFetch;
});

describe('admin SSO runtime config', () => {
  test('builds the hosted end-session navigation with the current ID token', () => {
    expect(buildAdminEndSessionUrl({
      endpoint: 'https://auth.example.test/logout',
      clientId: 'admin-client',
      idToken: 'header.payload.signature',
      postLogoutRedirectUri: 'https://auth.example.test/admin/login',
    })).toBe(
      'https://auth.example.test/logout?client_id=admin-client&id_token_hint=header.payload.signature&post_logout_redirect_uri=https%3A%2F%2Fauth.example.test%2Fadmin%2Flogin',
    );
  });

  test('preserves an unavailable config endpoint as a structured initialization failure', async () => {
    const fetcher = mock(async () => Response.json({
      code: 'upstream_unavailable',
      message: 'SupaCloud unavailable',
    }, { status: 503 }));
    globalThis.fetch = fetcher;

    await expect(initializeAdminAuthProvider()).rejects.toMatchObject({
      statusCode: 503,
      code: 'upstream_unavailable',
    });
    const requestUrl = new URL(String(fetcher.mock.calls[0][0]), 'http://localhost');
    expect(requestUrl.pathname).toBe('/api/v1/public/admin-sso-config');

    const recoveryFetcher = mock(async () => Response.json({ enabled: false }));
    globalThis.fetch = recoveryFetcher;
    await expect(initializeAdminAuthProvider()).resolves.toBeDefined();
    expect(recoveryFetcher).toHaveBeenCalledTimes(1);
  });

  test('uses the BFF principal as the authorization source', async () => {
    const fetcher = mock(async (request: RequestInfo | URL) => {
      const requestUrl = new URL(String(request), 'http://localhost');
      if (requestUrl.pathname === '/api/v1/public/admin-sso-config') {
        return Response.json({ enabled: false });
      }
      if (requestUrl.pathname === '/api/v1/auth/identity') {
        return Response.json({
          id: 'admin-1',
          roles: ['auditor'],
          permissions: ['audit.read', 'audit.export'],
          authorization_source: 'rbac_projection',
        });
      }
      return Response.json({ code: 'not_found', message: 'Not found' }, { status: 404 });
    });
    globalThis.fetch = fetcher;

    const provider = await initializeAdminAuthProvider();
    await expect(provider.getPermissions?.()).resolves.toEqual({
      roles: ['auditor'],
      permissions: ['audit.read', 'audit.export'],
      authorization_source: 'rbac_projection',
    });
  });

  test('does not share caller cancellation with an immediate remount', async () => {
    const firstResponse = deferredRequest();
    const firstCaller = new AbortController();
    let configRequests = 0;
    globalThis.fetch = mock(async () => {
      configRequests += 1;
      if (configRequests === 1) return firstResponse.promise;
      return Response.json({ enabled: false });
    });

    const cancelledAttempt = initializeAdminAuthProvider({ signal: firstCaller.signal });
    await waitFor(() => configRequests === 1, 'first runtime config request did not start');
    firstCaller.abort();
    const remountedAttempt = initializeAdminAuthProvider({
      signal: new AbortController().signal,
    });
    firstResponse.resolve(Response.json({ enabled: false }));

    await expect(cancelledAttempt).rejects.toMatchObject({ code: 'request_aborted' });
    await expect(remountedAttempt).resolves.toBeDefined();
    expect(configRequests).toBe(2);
  });

  test('shares a pending callback exchange with a replacement check', async () => {
    const originalWindow = globalThis.window;
    const OriginalRequest = globalThis.Request;
    const callbackState = 'callback-state';
    const storageValues = new Map([
      ['supaoauth_admin_sso_state', callbackState],
      ['supaoauth_admin_sso_pkce_verifier', 'callback-verifier'],
    ]);
    const tokenResponse = deferredRequest();
    let tokenRequests = 0;
    const adminHistoryState = { svelteKitIndex: 7 };
    let replacedHistoryState;
    let currentHref = `https://admin.example.test/admin?code=issued-code&state=${callbackState}`;
    const location = {
      get href() { return currentHref; },
      set href(value) { currentHref = new URL(String(value), currentHref).href; },
      get origin() { return new URL(currentHref).origin; },
      get pathname() { return new URL(currentHref).pathname; },
      assign(value) { currentHref = new URL(String(value), currentHref).href; },
    };
    globalThis.window = {
      document: {},
      navigator: {
        locks: {
          request: async (_name, optionsOrOperation, operation) => (
            operation ?? optionsOrOperation
          )(),
        },
      },
      location,
      history: {
        state: adminHistoryState,
        replaceState: (state, _title, nextUrl) => {
          replacedHistoryState = state;
          currentHref = new URL(String(nextUrl), currentHref).href;
        },
      },
      sessionStorage: {
        getItem: (key) => storageValues.get(key) ?? null,
        setItem: (key, value) => storageValues.set(key, value),
        removeItem: (key) => storageValues.delete(key),
      },
    };
    globalThis.Request = class BrowserRequest extends OriginalRequest {
      constructor(input, init) {
        super(typeof input === 'string' && input.startsWith('/')
          ? new URL(input, location.href)
          : input, init);
      }
    };
    globalThis.fetch = mock(async (input) => {
      const requestUrl = new URL(
        input instanceof Request ? input.url : String(input),
        location.href,
      );
      if (requestUrl.pathname === '/api/v1/public/admin-sso-config') {
        return Response.json({
          enabled: true,
          issuer: 'https://issuer.example.test',
          client_id: 'admin-client',
          redirect_uri: 'https://admin.example.test/admin',
        });
      }
      if (requestUrl.pathname === '/.well-known/openid-configuration') {
        return Response.json({
          authorization_endpoint: 'https://issuer.example.test/oauth/authorize',
          token_endpoint: 'https://issuer.example.test/oauth/token',
          userinfo_endpoint: 'https://issuer.example.test/userinfo',
        });
      }
      if (requestUrl.pathname === '/oauth/token') {
        tokenRequests += 1;
        return tokenResponse.promise;
      }
      if (requestUrl.pathname === '/api/v1/auth/identity') {
        return Response.json({ id: 'admin-1' });
      }
      return Response.json({ code: 'not_found' }, { status: 404 });
    });

    try {
      const provider = await initializeAdminAuthProvider({
        signal: new AbortController().signal,
      });
      const cancelledCaller = new AbortController();
      const cancelledCheck = provider.check({ signal: cancelledCaller.signal });
      await waitFor(() => tokenRequests === 1, 'callback token exchange did not start');
      cancelledCaller.abort();
      await expect(cancelledCheck).rejects.toMatchObject({ code: 'request_aborted' });

      const replacementCheck = provider.check({
        signal: new AbortController().signal,
      });
      await Promise.resolve();
      expect(tokenRequests).toBe(1);
      tokenResponse.resolve(Response.json({
        access_token: 'safe-access-token',
        refresh_token: 'safe-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
      }));

      await expect(replacementCheck).resolves.toEqual({ authenticated: true });
      expect(tokenRequests).toBe(1);
      expect(JSON.parse(storageValues.get('supaoauth_admin_sso_tokens'))).toMatchObject({
        access_token: 'safe-access-token',
      });

      storageValues.delete('supaoauth_admin_sso_tokens');
      storageValues.set('supaoauth_admin_sso_state', 'newer-state');
      storageValues.set('supaoauth_admin_sso_pkce_verifier', 'newer-verifier');
      currentHref = `https://admin.example.test/admin?code=stale-code&state=${callbackState}&view=members#permissions`;
      await expect(provider.check({})).resolves.toMatchObject({
        authenticated: false,
        error: { message: 'State mismatch' },
      });
      expect(tokenRequests).toBe(1);

      currentHref = `https://admin.example.test/admin?code=stale-code&state=${callbackState}&view=members&error=invalid_request&error_description=private-upstream-detail#permissions`;
      const cancelledBeforeCleanup = new AbortController();
      cancelledBeforeCleanup.abort();
      await expect(prepareAdminAuthCallbackRetry({ signal: cancelledBeforeCleanup.signal }))
        .rejects.toMatchObject({ name: 'AbortError' });
      expect(currentHref).toContain('code=stale-code');
      expect(storageValues.get('supaoauth_admin_sso_state')).toBe('newer-state');

      const cancelledDuringCleanup = new AbortController();
      const retryStorage = globalThis.window.sessionStorage;
      const removeStorageItem = retryStorage.removeItem;
      retryStorage.removeItem = (key) => {
        removeStorageItem(key);
        if (key === 'supaoauth_admin_sso_state') cancelledDuringCleanup.abort();
      };
      try {
        await prepareAdminAuthCallbackRetry({ signal: cancelledDuringCleanup.signal });
      } finally {
        retryStorage.removeItem = removeStorageItem;
      }
      expect(cancelledDuringCleanup.signal.aborted).toBe(true);
      expect(currentHref).toBe('https://admin.example.test/admin?view=members#permissions');
      expect(storageValues.has('supaoauth_admin_sso_state')).toBe(false);
      expect(storageValues.has('supaoauth_admin_sso_pkce_verifier')).toBe(false);

      const rebuiltProvider = await initializeAdminAuthProvider({
        signal: new AbortController().signal,
      });
      expect(rebuiltProvider).not.toBe(provider);
      await expect(rebuiltProvider.check({})).resolves.toMatchObject({ authenticated: false });
      const loginSignal = new AbortController().signal;
      const freshLogin = await rebuiltProvider.login({ signal: loginSignal });
      expect(freshLogin).toMatchObject({ success: true });
      await freshLogin.commitRedirect(loginSignal);
      const freshState = storageValues.get('supaoauth_admin_sso_state');
      const freshVerifier = storageValues.get('supaoauth_admin_sso_pkce_verifier');
      expect(freshState).toBeTruthy();
      expect(freshVerifier).toBeTruthy();
      expect(freshState).not.toBe(callbackState);
      expect(freshState).not.toBe('newer-state');

      currentHref = 'https://admin.example.test/admin?state=page-state&error_description=visible&view=members#permissions';
      await prepareAdminAuthCallbackRetry({ signal: new AbortController().signal });
      expect(currentHref).toBe(
        'https://admin.example.test/admin?state=page-state&error_description=visible&view=members#permissions',
      );
      expect(storageValues.get('supaoauth_admin_sso_state')).toBe(freshState);
      expect(storageValues.get('supaoauth_admin_sso_pkce_verifier')).toBe(freshVerifier);
      await expect(initializeAdminAuthProvider({
        signal: new AbortController().signal,
      })).resolves.toBe(rebuiltProvider);

      const navigationLock = deferredRequest();
      let navigationLockRequested = false;
      globalThis.window.navigator.locks.request = async (_name, optionsOrOperation, operation) => {
        navigationLockRequested = true;
        await navigationLock.promise;
        return (operation ?? optionsOrOperation)();
      };
      currentHref = `https://admin.example.test/admin?code=stale-code&state=${freshState}&view=members#permissions`;
      const navigationRetry = prepareAdminAuthCallbackRetry({
        signal: new AbortController().signal,
      });
      await waitFor(() => navigationLockRequested, 'callback retry did not wait for the auth lock');
      currentHref = 'https://admin.example.test/admin/users?view=active#details';
      navigationLock.resolve();
      await navigationRetry;
      expect(currentHref).toBe('https://admin.example.test/admin/users?view=active#details');
      expect(storageValues.get('supaoauth_admin_sso_state')).toBe(freshState);
      expect(storageValues.get('supaoauth_admin_sso_pkce_verifier')).toBe(freshVerifier);
      await expect(initializeAdminAuthProvider({
        signal: new AbortController().signal,
      })).resolves.toBe(rebuiltProvider);

      const abortedLock = deferredRequest();
      const queuedAbort = new AbortController();
      let queuedLockSignal;
      globalThis.window.navigator.locks.request = async (_name, options, operation) => {
        queuedLockSignal = options.signal;
        await abortedLock.promise;
        options.signal.throwIfAborted();
        return operation();
      };
      currentHref = `https://admin.example.test/admin?error=access_denied&state=${freshState}&view=members#permissions`;
      const abortedRetry = prepareAdminAuthCallbackRetry({ signal: queuedAbort.signal });
      await waitFor(() => queuedLockSignal === queuedAbort.signal, 'callback retry did not pass its abort signal to Web Locks');
      queuedAbort.abort();
      abortedLock.resolve();
      await expect(abortedRetry).rejects.toMatchObject({ name: 'AbortError' });
      expect(currentHref).toBe(
        `https://admin.example.test/admin?error=access_denied&state=${freshState}&view=members#permissions`,
      );
      expect(storageValues.get('supaoauth_admin_sso_state')).toBe(freshState);
      expect(storageValues.get('supaoauth_admin_sso_pkce_verifier')).toBe(freshVerifier);

      globalThis.window.navigator.locks.request = async (_name, optionsOrOperation, operation) => (
        operation ?? optionsOrOperation
      )();
      currentHref = `https://admin.example.test/admin?error=access_denied&error_description=private-detail&error_uri=https%3A%2F%2Fissuer.example.test%2Ferrors%2Fdenied&error_code=provider_denied&state=${freshState}&iss=https%3A%2F%2Fissuer.example.test&session_state=session-123&view=members#permissions`;
      await prepareAdminAuthCallbackRetry({ signal: new AbortController().signal });
      expect(currentHref).toBe('https://admin.example.test/admin?view=members#permissions');
      expect(replacedHistoryState).toBe(adminHistoryState);
      expect(storageValues.has('supaoauth_admin_sso_state')).toBe(false);
      expect(storageValues.has('supaoauth_admin_sso_pkce_verifier')).toBe(false);
    } finally {
      globalThis.Request = OriginalRequest;
      globalThis.window = originalWindow;
    }
  });
});
