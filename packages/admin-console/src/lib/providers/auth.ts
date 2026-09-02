// SupaOAuth AuthProvider for @svadmin/core.
// Production uses @svadmin/sso OIDC PKCE; development can keep ADMIN_TOKEN login.

import type { AuthProvider, Identity, AuthActionResult, CheckResult } from '@svadmin/core';
import {
  createSSOAuthProvider,
  generateChallenge,
  generateState,
  generateVerifier,
  type SSOAuthProvider,
  type TokenStorage,
} from '@svadmin/sso';
import {
  AdminApiError,
  adminApiRequest,
  runBoundedAdminRequest,
  setAdminAuthenticatedFetch,
} from '../admin-api';
import { adminCheckFailure } from '../admin-auth-result';
import {
  createAdminMfaStepUp,
  createAdminSsoStorage,
  type AdminMfaStepUp,
  type AdminMfaStepUpState,
  type AdminTotpEnrollment,
} from '../admin-mfa-step-up';
import { requireAdminAuthenticatedFetch } from '../admin-sso-capability';
import {
  clearStoredAdminToken,
  setAdminAccessTokenProvider,
  setStoredAdminToken,
} from '../auth-token';

interface AdminSsoConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  endSessionEndpoint: string;
}

interface RuntimeAdminSsoConfigResponse {
  enabled?: boolean;
  issuer?: string;
  client_id?: string;
  redirect_uri?: string;
  post_logout_redirect_uri?: string;
  end_session_endpoint?: string;
}

interface AdminEndSessionInput {
  endpoint: string;
  clientId: string;
  idToken: string;
  postLogoutRedirectUri: string;
}

interface AdminPrincipalPermissions {
  roles: string[];
  permissions: string[];
  authorization_source: string;
}

interface AdminAuthInitializationOptions {
  signal?: AbortSignal;
}

interface AdminOidcDiscovery extends Record<string, unknown> {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
}

interface DeferredAdminLoginResult extends AuthActionResult {
  commitRedirect: (signal: AbortSignal) => Promise<void>;
  rollbackRedirect: () => Promise<void>;
}

interface PreparedAdminLogin {
  discovery: AdminOidcDiscovery;
  loginResult: DeferredAdminLoginResult;
}

interface AdminLoginMaterial {
  config: AdminSsoConfig;
  storage: TokenStorage;
  discovery: AdminOidcDiscovery;
  state: string;
  verifier: string;
  challenge: string;
}

const ADMIN_SSO_STORAGE_KEY = 'supaoauth_admin_sso';
// SSO callback 读取这两个 storageKey 派生键；真实 callback 回归用于锁定升级兼容性。
const ADMIN_SSO_LOGIN_KEYS = {
  verifier: `${ADMIN_SSO_STORAGE_KEY}_pkce_verifier`,
  state: `${ADMIN_SSO_STORAGE_KEY}_state`,
} as const;
const ADMIN_OAUTH_CALLBACK_PARAMS = [
  'code',
  'state',
  'error',
  'error_description',
  'error_uri',
  'error_code',
  'iss',
  'session_state',
] as const;
const ADMIN_SSO_AUTH_LOCK = `${ADMIN_SSO_STORAGE_KEY}:auth`;

const COMPILED_SSO_CONFIG = normalizeAdminSsoConfig({
  issuer: import.meta.env.VITE_ADMIN_SSO_ISSUER || import.meta.env.VITE_SSO_ISSUER || '',
  client_id: import.meta.env.VITE_ADMIN_SSO_CLIENT_ID || import.meta.env.VITE_SSO_CLIENT_ID || '',
  redirect_uri: import.meta.env.VITE_ADMIN_SSO_REDIRECT_URI || defaultRedirectUri(),
  post_logout_redirect_uri: import.meta.env.VITE_ADMIN_SSO_POST_LOGOUT_REDIRECT_URI || defaultLoginUri(),
});
let runtimeSsoConfigPromise: Promise<AdminSsoConfig | null> | null = null;
let currentSsoProvider: SSOAuthProvider | null = null;
let currentAdminMfaStepUp: AdminMfaStepUp | null = null;
export let adminSsoEnabled = Boolean(COMPILED_SSO_CONFIG);

function defaultRedirectUri(): string {
  if (typeof window === 'undefined') return '/admin';
  return `${window.location.origin}/admin`;
}

function defaultLoginUri(): string {
  if (typeof window === 'undefined') return '/admin/login';
  return `${window.location.origin}/admin/login`;
}

function defaultLogoutUri(): string {
  if (typeof window === 'undefined') return '/logout';
  return `${window.location.origin}/logout`;
}

export function buildAdminEndSessionUrl(input: AdminEndSessionInput): string {
  const browserOrigin = typeof window === 'undefined' ? 'http://localhost' : window.location.origin;
  const logoutUrl = new URL(input.endpoint, browserOrigin);
  if (!['http:', 'https:'].includes(logoutUrl.protocol) || logoutUrl.username || logoutUrl.password) {
    throw new TypeError('Admin end-session endpoint must be an http(s) URL without credentials');
  }
  logoutUrl.searchParams.set('client_id', input.clientId);
  logoutUrl.searchParams.set('id_token_hint', input.idToken);
  logoutUrl.searchParams.set('post_logout_redirect_uri', input.postLogoutRedirectUri);
  return logoutUrl.toString();
}

function normalizeAdminSsoConfig(config: RuntimeAdminSsoConfigResponse): AdminSsoConfig | null {
  if (!config.enabled && !(config.issuer && config.client_id)) return null;
  const issuer = (config.issuer || '').replace(/\/+$/, '');
  const clientId = config.client_id || '';
  if (!issuer || !clientId) return null;

  return {
    issuer,
    clientId,
    redirectUri: config.redirect_uri || defaultRedirectUri(),
    postLogoutRedirectUri: config.post_logout_redirect_uri || defaultLoginUri(),
    endSessionEndpoint: config.end_session_endpoint || defaultLogoutUri(),
  };
}

async function loadRuntimeAdminSsoConfig(
  options: AdminAuthInitializationOptions = {},
): Promise<AdminSsoConfig | null> {
  if (COMPILED_SSO_CONFIG) return COMPILED_SSO_CONFIG;
  // 调用方的取消只属于当前挂载；共享它会把旧页面的 Abort 泄漏给新页面。
  if (options.signal) return requestRuntimeAdminSsoConfig(options.signal);
  if (runtimeSsoConfigPromise) return runtimeSsoConfigPromise;

  const pendingConfig = requestRuntimeAdminSsoConfig(options.signal);
  runtimeSsoConfigPromise = pendingConfig;
  try {
    return await pendingConfig;
  } catch (error) {
    // 此处刻意比较 Promise 身份；await 会比较结果值并破坏过期请求保护。
    if (Object.is(runtimeSsoConfigPromise, pendingConfig)) runtimeSsoConfigPromise = null;
    throw error;
  }
}

async function requestRuntimeAdminSsoConfig(
  signal?: AbortSignal,
): Promise<AdminSsoConfig | null> {
  const response = await adminApiRequest('/v1/public/admin-sso-config', { signal });
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    throw new AdminApiError(
      'Admin SSO config returned an invalid response',
      502,
      'invalid_upstream_response',
      response,
    );
  }
  return normalizeAdminSsoConfig(response as RuntimeAdminSsoConfigResponse);
}

function isStringArray(candidate: unknown): candidate is string[] {
  return Array.isArray(candidate) && candidate.every((entry) => typeof entry === 'string');
}

function adminCheckSignal(params: Record<string, unknown>): AbortSignal | undefined {
  const candidate = params.signal;
  return typeof AbortSignal !== 'undefined' && candidate instanceof AbortSignal
    ? candidate
    : undefined;
}

function abortSignal(params: Record<string, unknown>): AbortSignal {
  return adminCheckSignal(params) ?? new AbortController().signal;
}

function adminAuthErrorCode(error: unknown): string | null {
  if (!error || typeof error !== 'object') return null;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : null;
}

function adminOidcEndpoint(endpointCandidate: unknown): string | null {
  if (typeof endpointCandidate !== 'string' || !endpointCandidate) return null;
  try {
    const endpoint = new URL(endpointCandidate);
    return ['http:', 'https:'].includes(endpoint.protocol) && !endpoint.username && !endpoint.password
      ? endpoint.href
      : null;
  } catch {
    return null;
  }
}

function requiredAdminOidcEndpoint(endpointCandidate: unknown): string {
  const endpoint = adminOidcEndpoint(endpointCandidate);
  if (endpoint) return endpoint;
  throw new AdminApiError(
    'Admin OIDC discovery is missing a valid endpoint',
    502,
    'invalid_discovery_document',
  );
}

function readAdminOidcDiscovery(discoveryPayload: unknown): AdminOidcDiscovery {
  if (!discoveryPayload || typeof discoveryPayload !== 'object' || Array.isArray(discoveryPayload)) {
    throw new AdminApiError(
      'Admin OIDC discovery returned an invalid response',
      502,
      'invalid_discovery_document',
    );
  }
  const discovery = discoveryPayload as Record<string, unknown>;
  return {
    ...discovery,
    authorization_endpoint: requiredAdminOidcEndpoint(discovery.authorization_endpoint),
    token_endpoint: requiredAdminOidcEndpoint(discovery.token_endpoint),
    userinfo_endpoint: requiredAdminOidcEndpoint(discovery.userinfo_endpoint),
  };
}

async function readAdminOidcResponse(response: Response): Promise<unknown> {
  if (!response.ok) {
    throw new AdminApiError(
      'Admin OIDC discovery failed',
      response.status,
      'oidc_discovery_failed',
    );
  }
  try {
    return await response.json();
  } catch {
    throw new AdminApiError(
      'Admin OIDC discovery returned invalid JSON',
      502,
      'invalid_discovery_document',
    );
  }
}

async function loadAdminOidcDiscovery(
  issuer: string,
  signal: AbortSignal,
): Promise<AdminOidcDiscovery> {
  signal.throwIfAborted();
  const response = await globalThis.fetch(
    `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`,
    { signal },
  );
  const discoveryPayload = await readAdminOidcResponse(response);
  signal.throwIfAborted();
  return readAdminOidcDiscovery(discoveryPayload);
}

function clearAdminLoginState(storage: TokenStorage, expectedState: string): void {
  if (storage.getItem(ADMIN_SSO_LOGIN_KEYS.state) !== expectedState) return;
  storage.removeItem(ADMIN_SSO_LOGIN_KEYS.verifier);
  storage.removeItem(ADMIN_SSO_LOGIN_KEYS.state);
}

function adminOAuthCallbackUrl(href: string): URL | null {
  const callbackUrl = new URL(href);
  return callbackUrl.searchParams.has('code') || callbackUrl.searchParams.has('error')
    ? callbackUrl
    : null;
}

function clearAdminOAuthCallbackUrl(callbackUrl: URL): void {
  for (const parameter of ADMIN_OAUTH_CALLBACK_PARAMS) {
    callbackUrl.searchParams.delete(parameter);
  }
  window.history.replaceState(
    window.history.state,
    '',
    `${callbackUrl.pathname}${callbackUrl.search}${callbackUrl.hash}`,
  );
}

function destroyCurrentAdminSsoRuntime(): void {
  currentSsoProvider?.destroy();
  currentSsoProvider = null;
  currentAdminMfaStepUp = null;
  setAdminAccessTokenProvider(null);
  setAdminAuthenticatedFetch(null);
}

export function resetAdminAuthRuntimeForTests(): void {
  runtimeSsoConfigPromise = null;
  destroyCurrentAdminSsoRuntime();
  adminSsoEnabled = Boolean(COMPILED_SSO_CONFIG);
  supaoauthAuthProvider = tokenAuthProvider;
}

async function withAdminSsoAuthLock<T>(
  operation: () => Promise<T> | T,
  signal?: AbortSignal,
): Promise<T> {
  const lock = typeof window === 'undefined' ? null : window.navigator?.locks;
  // 与 @svadmin/sso 保持一致：非浏览器探针使用进程内串行语义，真实浏览器必须有 Web Locks。
  if (typeof window !== 'undefined' && window.document === undefined) {
    return operation();
  }
  if (!lock) {
    throw new Error('Admin SSO login requires the browser Web Locks API');
  }
  return signal
    ? lock.request(ADMIN_SSO_AUTH_LOCK, { signal }, operation)
    : lock.request(ADMIN_SSO_AUTH_LOCK, operation);
}

export async function prepareAdminAuthCallbackRetry(
  options: AdminAuthInitializationOptions = {},
): Promise<void> {
  if (typeof window === 'undefined') return;
  const callbackHref = window.location.href;
  if (!adminOAuthCallbackUrl(callbackHref)) return;

  options.signal?.throwIfAborted();
  await withAdminSsoAuthLock(() => {
    options.signal?.throwIfAborted();
    if (window.location.href !== callbackHref) return;
    const callbackUrl = adminOAuthCallbackUrl(window.location.href);
    if (!callbackUrl) return;
    window.sessionStorage.removeItem(ADMIN_SSO_LOGIN_KEYS.state);
    window.sessionStorage.removeItem(ADMIN_SSO_LOGIN_KEYS.verifier);
    destroyCurrentAdminSsoRuntime();
    clearAdminOAuthCallbackUrl(callbackUrl);
  }, options.signal);
}

function buildAdminAuthorizeUrl(
  config: AdminSsoConfig,
  authorizationEndpoint: string,
  state: string,
  challenge: string,
): string {
  const authorizeUrl = new URL(authorizationEndpoint);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
  authorizeUrl.searchParams.set('scope', 'openid profile email');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  return authorizeUrl.href;
}

function writeAdminLoginState(
  storage: TokenStorage,
  state: string,
  verifier: string,
  signal: AbortSignal,
): void {
  signal.throwIfAborted();
  storage.setItem(ADMIN_SSO_LOGIN_KEYS.verifier, verifier);
  try {
    storage.setItem(ADMIN_SSO_LOGIN_KEYS.state, state);
  } catch (error) {
    if (storage.getItem(ADMIN_SSO_LOGIN_KEYS.verifier) === verifier) {
      storage.removeItem(ADMIN_SSO_LOGIN_KEYS.verifier);
    }
    throw error;
  }
}

function createAdminLoginCommit(
  storage: TokenStorage,
  state: string,
  verifier: string,
  rollbackRedirect: () => Promise<void>,
): (signal: AbortSignal) => Promise<void> {
  return async (signal) => {
    signal.throwIfAborted();
    await withAdminSsoAuthLock(() => writeAdminLoginState(storage, state, verifier, signal));
    if (!signal.aborted) return;
    await rollbackRedirect();
    signal.throwIfAborted();
  };
}

function preparedAdminLogin(material: AdminLoginMaterial): PreparedAdminLogin {
  const { config, storage, discovery, state, verifier, challenge } = material;
  const rollbackRedirect = () => withAdminSsoAuthLock(
    () => clearAdminLoginState(storage, state),
  );
  return {
    discovery,
    loginResult: {
      success: true,
      redirectTo: buildAdminAuthorizeUrl(config, discovery.authorization_endpoint, state, challenge),
      commitRedirect: createAdminLoginCommit(storage, state, verifier, rollbackRedirect),
      rollbackRedirect,
    },
  };
}

async function prepareAdminSsoLogin(
  config: AdminSsoConfig,
  storage: TokenStorage,
  signal: AbortSignal,
): Promise<PreparedAdminLogin> {
  signal.throwIfAborted();
  const state = generateState();
  const verifier = generateVerifier();
  const discovery = await loadAdminOidcDiscovery(config.issuer, signal);
  const challenge = await generateChallenge(verifier);
  signal.throwIfAborted();
  return preparedAdminLogin({ config, storage, discovery, state, verifier, challenge });
}

function adminPrincipalPermissions(identity: unknown): AdminPrincipalPermissions {
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new AdminApiError('Admin identity returned an invalid response', 502, 'invalid_upstream_response', identity);
  }
  const principal = identity as Record<string, unknown>;
  const roles = principal.roles;
  const permissions = principal.permissions;
  const authorizationSource = principal.authorization_source;
  if (
    !isStringArray(roles)
    || !isStringArray(permissions)
    || typeof authorizationSource !== 'string'
  ) {
    throw new AdminApiError('Admin identity is missing authorization data', 502, 'invalid_upstream_response', identity);
  }
  return { roles, permissions, authorization_source: authorizationSource };
}

async function getAdminPrincipalPermissions(): Promise<AdminPrincipalPermissions> {
  return adminPrincipalPermissions(await adminApiRequest('/v1/auth/identity'));
}

const tokenAuthProvider: AuthProvider = {
  login: async (params: Record<string, unknown>): Promise<AuthActionResult> => {
    try {
      const result = await adminApiRequest('/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          token: params.token || params.password,
          email: params.email,
          password: params.password,
        }),
      });
      const token = (result as { token?: string })?.token;
      if (token) {
        setStoredAdminToken(token);
        return { success: true, redirectTo: '/admin/dashboard' };
      }
      return { success: false, error: { message: 'Login failed' } };
    } catch (e) {
      return { success: false, error: { message: (e as Error).message } };
    }
  },

  logout: async (): Promise<AuthActionResult> => {
    let revokeError: unknown = null;
    try {
      await adminApiRequest('/v1/auth/logout', { method: 'POST' });
    } catch (error) {
      revokeError = error;
    }
    clearStoredAdminToken();
    if (revokeError) {
      return { success: false, error: { message: (revokeError as Error).message } };
    }
    return { success: true, redirectTo: '/admin/login' };
  },

  check: async (params = {}): Promise<CheckResult> => {
    try {
      await adminApiRequest('/v1/auth/identity', {
        signal: adminCheckSignal(params),
      });
      return { authenticated: true };
    } catch (error) {
      return adminCheckFailure(error);
    }
  },

  getIdentity: async (): Promise<Identity | null> => {
    try {
      const identity = await adminApiRequest('/v1/auth/identity');
      return identity as Identity;
    } catch {
      return null;
    }
  },

  getPermissions: async (): Promise<unknown> => {
    return getAdminPrincipalPermissions();
  },

  onError: async (error: unknown): Promise<{ redirectTo?: string; logout?: boolean }> => {
    const status = (error as { statusCode?: number })?.statusCode;
    if (status === 401) {
      return { redirectTo: '/admin/login', logout: true };
    }
    return {};
  },
};

export let supaoauthAuthProvider: AuthProvider = tokenAuthProvider;

function createSupaOAuthSSOProvider(config: AdminSsoConfig): AuthProvider {
  const storage = typeof window === 'undefined' ? null : createAdminSsoStorage(window.sessionStorage);
  const discoveryUrl = `${config.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
  let cachedDiscovery: AdminOidcDiscovery | null = null;
  let pendingSsoCheck: Promise<CheckResult> | null = null;
  const fetchSsoRequest = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const requestUrl = input instanceof Request ? input.url : String(input);
    if (cachedDiscovery && requestUrl === discoveryUrl) {
      return Response.json(cachedDiscovery);
    }
    return globalThis.fetch(input, init);
  };
  const ssoProvider: SSOAuthProvider = createSSOAuthProvider({
    issuer: config.issuer,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    postLogoutRedirectUri: config.postLogoutRedirectUri,
    // RP 导航由 wrapper 在远程 revoke 完成后统一提交，避免页面卸载中止请求。
    endSessionEndpoint: '',
    scopes: ['openid', 'profile', 'email'],
    storage: storage || 'session',
    storageKey: ADMIN_SSO_STORAGE_KEY,
    legacyStorageKey: 'svadmin_sso',
    autoRefresh: false,
    fetcher: fetchSsoRequest as typeof fetch,
  });
  const authenticatedFetch = requireAdminAuthenticatedFetch(ssoProvider);

  currentSsoProvider = ssoProvider;
  currentAdminMfaStepUp = storage ? createAdminMfaStepUp(config.issuer, ssoProvider, storage) : null;
  setAdminAccessTokenProvider(() => ssoProvider.getAccessToken());
  setAdminAuthenticatedFetch(authenticatedFetch);

  function sharedSsoCheck(): Promise<CheckResult> {
    if (pendingSsoCheck) return pendingSsoCheck;
    // 授权码只能兑换一次；外层超时后的重试必须等待同一次在途兑换。
    const currentCheck = Promise.resolve().then(() => ssoProvider.check());
    const sharedCheck = currentCheck.finally(() => {
      if (pendingSsoCheck === sharedCheck) pendingSsoCheck = null;
    });
    pendingSsoCheck = sharedCheck;
    return sharedCheck;
  }

  return {
    login: async (params): Promise<AuthActionResult> => {
      if (!storage || typeof window === 'undefined') {
        return {
          success: false,
          error: { message: 'Admin SSO login requires a browser environment' },
        };
      }
      const signal = abortSignal(params);
      try {
        const preparedLogin = await prepareAdminSsoLogin(config, storage, signal);
        cachedDiscovery = preparedLogin.discovery;
        return preparedLogin.loginResult;
      } catch (error) {
        if (signal.aborted) throw error;
        const code = adminAuthErrorCode(error);
        return {
          success: false,
          error: {
            message: error instanceof Error && error.message
              ? error.message
              : 'Admin SSO login preparation failed',
            ...(code ? { name: code } : {}),
          },
        };
      }
    },

    logout: async (): Promise<AuthActionResult> => {
      const currentSessionRequest = ssoProvider.getSession().catch(() => null);
      clearStoredAdminToken();
      // 先同步推进本地认证 generation；远程 revoke 挂起时旧 callback 也不能复活会话。
      const providerLogoutRequest = ssoProvider.logout({});
      const revokeRequest = adminApiRequest('/v1/auth/logout', { method: 'POST' })
        .then(() => null, (error: unknown) => error);
      const [currentSession, providerLogout, revokeError] = await Promise.all([
        currentSessionRequest,
        providerLogoutRequest,
        revokeRequest,
      ]);
      if (currentSession?.id_token && typeof window !== 'undefined') {
        window.location.assign(buildAdminEndSessionUrl({
          endpoint: config.endSessionEndpoint,
          clientId: config.clientId,
          idToken: currentSession.id_token,
          postLogoutRedirectUri: config.postLogoutRedirectUri,
        }));
        return { success: true };
      }
      if (revokeError) {
        return {
          success: false,
          error: { message: (revokeError as Error).message },
          redirectTo: providerLogout.redirectTo,
        };
      }
      return providerLogout;
    },

    check: async (params = {}): Promise<CheckResult> => {
      const signal = adminCheckSignal(params);
      const ssoCheck = await runBoundedAdminRequest(
        () => sharedSsoCheck(),
        { signal },
      );
      if (!ssoCheck.authenticated) {
        return { ...ssoCheck, redirectTo: ssoCheck.redirectTo || '/admin/login' };
      }

      try {
        await adminApiRequest('/v1/auth/identity', { signal });
        return { authenticated: true };
      } catch (error) {
        return adminCheckFailure(error);
      }
    },

    getIdentity: async (): Promise<Identity | null> => {
      try {
        const identity = await adminApiRequest('/v1/auth/identity');
        return identity as Identity;
      } catch {
        return ssoProvider.getIdentity();
      }
    },

    getPermissions: async (): Promise<unknown> => {
      return getAdminPrincipalPermissions();
    },

    onError: async (error: unknown): Promise<{ redirectTo?: string; logout?: boolean }> => {
      const status = (error as { statusCode?: number; status?: number })?.statusCode
        ?? (error as { status?: number })?.status;
      if (status === 403) return {};
      return ssoProvider.onError?.(error) ?? {};
    },
  };
}

export async function getAdminMfaStepUpState(
  options: AdminAuthInitializationOptions = {},
): Promise<AdminMfaStepUpState> {
  if (!currentAdminMfaStepUp) throw new Error('管理员 MFA 会话尚未初始化，请重新登录。');
  return runBoundedAdminRequest(
    () => currentAdminMfaStepUp!.state(),
    { signal: options.signal },
  );
}

export async function enrollAdminTotp(input: { friendlyName: string; issuer: string }): Promise<AdminTotpEnrollment> {
  if (!currentAdminMfaStepUp) throw new Error('管理员 MFA 会话尚未初始化，请重新登录。');
  return currentAdminMfaStepUp.enroll(input);
}

export async function verifyAdminMfaStepUp(input: { factorId: string; code: string }): Promise<void> {
  if (!currentAdminMfaStepUp) throw new Error('管理员 MFA 会话尚未初始化，请重新登录。');
  await currentAdminMfaStepUp.verify(input.factorId, input.code);
}

export async function initializeAdminAuthProvider(
  options: AdminAuthInitializationOptions = {},
): Promise<AuthProvider> {
  if (currentSsoProvider) return supaoauthAuthProvider;

  const ssoConfig = await loadRuntimeAdminSsoConfig(options);
  if (!ssoConfig) {
    adminSsoEnabled = false;
    setAdminAuthenticatedFetch(null);
    supaoauthAuthProvider = tokenAuthProvider;
    return supaoauthAuthProvider;
  }

  adminSsoEnabled = true;
  supaoauthAuthProvider = createSupaOAuthSSOProvider(ssoConfig);
  return supaoauthAuthProvider;
}
