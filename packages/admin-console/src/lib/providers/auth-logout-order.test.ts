// Bun runs this module directly; the Svelte check does not include Bun's test globals.
// @ts-nocheck
import { afterEach, beforeEach, expect, test } from 'bun:test';
import { resetAdminAuthRuntimeForTests } from './auth.js';

function deferredRequest() {
  let resolveRequest;
  const promise = new Promise((resolve) => {
    resolveRequest = resolve;
  });
  return { promise, resolve: resolveRequest };
}

async function waitFor(predicate, message) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error(message);
}

beforeEach(() => {
  resetAdminAuthRuntimeForTests();
});

afterEach(() => {
  resetAdminAuthRuntimeForTests();
});

test('invalidates a callback exchange before remote logout can complete', async () => {
  const originalFetch = globalThis.fetch;
  const OriginalRequest = globalThis.Request;
  const originalWindow = globalThis.window;
  const callbackState = 'logout-order-state';
  const callbackHref = `https://admin.example.test/admin?code=logout-order-code&state=${callbackState}`;
  const storageValues = new Map([
    ['supaoauth_admin_sso_state', callbackState],
    ['supaoauth_admin_sso_pkce_verifier', 'logout-order-verifier'],
    ['supaoauth_admin_sso_tokens', JSON.stringify({
      access_token: 'existing-access-token',
      refresh_token: 'existing-refresh-token',
      id_token: 'existing-id-token',
      token_type: 'Bearer',
      expires_at: Math.floor(Date.now() / 1000) + 3_600,
    })],
  ]);
  const tokenResponse = deferredRequest();
  const remoteLogoutResponse = deferredRequest();
  let tokenRequests = 0;
  let logoutRequests = 0;
  const identityAuthorization = [];
  let currentHref = callbackHref;
  const location = {
    get href() { return currentHref; },
    set href(value) { currentHref = new URL(String(value), currentHref).href; },
    get origin() { return new URL(currentHref).origin; },
    get pathname() { return new URL(currentHref).pathname; },
    assign(value) { currentHref = new URL(String(value), currentHref).href; },
  };
  globalThis.window = {
    document: {},
    navigator: { locks: { request: async (_name, operation) => operation() } },
    location,
    history: {
      replaceState: (_state, _title, nextUrl) => {
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
  globalThis.fetch = async (input, init = {}) => {
    const requestUrl = new URL(
      input && typeof input === 'object' && 'url' in input ? input.url : String(input),
      location.href,
    );
    if (requestUrl.pathname === '/api/v1/public/admin-sso-config') {
      return Response.json({
        enabled: true,
        issuer: 'https://issuer.example.test',
        client_id: 'admin-client',
        redirect_uri: 'https://admin.example.test/admin',
        post_logout_redirect_uri: 'https://admin.example.test/admin/login',
        end_session_endpoint: 'https://admin.example.test/logout',
      });
    }
    if (requestUrl.pathname === '/.well-known/openid-configuration') {
      return Response.json({
        authorization_endpoint: 'https://issuer.example.test/oauth/authorize',
        token_endpoint: 'https://issuer.example.test/oauth/token',
        userinfo_endpoint: 'https://issuer.example.test/userinfo',
        end_session_endpoint: 'https://issuer.example.test/oauth/logout',
      });
    }
    if (requestUrl.pathname === '/oauth/token') {
      tokenRequests += 1;
      return tokenResponse.promise;
    }
    if (requestUrl.pathname === '/api/v1/auth/logout') {
      logoutRequests += 1;
      return remoteLogoutResponse.promise;
    }
    if (requestUrl.pathname === '/api/v1/auth/identity') {
      const headers = input && typeof input === 'object' && 'headers' in input
        ? input.headers
        : new Headers(init.headers);
      identityAuthorization.push(new Headers(headers).get('Authorization'));
      return Response.json({ id: 'admin-1' });
    }
    return Response.json({ code: 'not_found' }, { status: 404 });
  };

  try {
    const authModule = await import('./auth.js');
    const provider = await authModule.initializeAdminAuthProvider({
      signal: new AbortController().signal,
    });
    const callbackCheck = provider.check({ signal: new AbortController().signal });
    await waitFor(() => tokenRequests === 1, 'callback exchange did not start');

    const logout = provider.logout({});
    await waitFor(() => logoutRequests === 1, 'remote logout did not start');
    tokenResponse.resolve(Response.json({
      access_token: 'must-never-be-persisted-after-logout-starts',
      refresh_token: 'must-never-be-persisted-after-logout-starts',
      token_type: 'Bearer',
      expires_in: 3600,
    }));
    await callbackCheck;
    const transientSession = storageValues.has('supaoauth_admin_sso_tokens');
    const concurrentCheck = await provider.check({ signal: new AbortController().signal });
    const locationBeforeRemoteLogout = currentHref;
    remoteLogoutResponse.resolve(new Response(null, { status: 204 }));
    const logoutResult = await logout;
    const finalSession = storageValues.has('supaoauth_admin_sso_tokens');
    const completedLogoutUrl = new URL(currentHref);

    expect({
      transientSession,
      concurrentAuthenticated: concurrentCheck.authenticated,
      bearerUsedDuringLogout: identityAuthorization.some((header) =>
        header?.includes('must-never-be-persisted')),
      locationBeforeRemoteLogout,
      finalSession,
      logoutResult,
      completedLogoutOrigin: completedLogoutUrl.origin,
      completedLogoutPath: completedLogoutUrl.pathname,
      completedIdTokenHint: completedLogoutUrl.searchParams.get('id_token_hint'),
    }).toEqual({
      transientSession: false,
      concurrentAuthenticated: false,
      bearerUsedDuringLogout: false,
      locationBeforeRemoteLogout: callbackHref,
      finalSession: false,
      logoutResult: { success: true },
      completedLogoutOrigin: 'https://admin.example.test',
      completedLogoutPath: '/logout',
      completedIdTokenHint: 'existing-id-token',
    });
  } finally {
    remoteLogoutResponse.resolve(new Response(null, { status: 204 }));
    globalThis.fetch = originalFetch;
    globalThis.Request = OriginalRequest;
    globalThis.window = originalWindow;
  }
});
