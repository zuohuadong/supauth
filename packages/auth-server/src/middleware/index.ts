// Observability middleware — request ID, structured logs, audit correlation

import { Elysia } from 'elysia';
import { enterRequestContext, getCurrentRequestId } from '../auth/request-context.js';
import { SupaCloudApiError } from '../supacloud/adapter.js';
import { ApiContractError } from '../utils/api-contract.js';
import { runtimeEnv } from '../config/platform-env.js';

const securityResponseHeaders = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'content-security-policy': "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data: https:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
};

function applySecurityResponseHeaders(headers: Record<string, string | number> | Headers) {
  for (const [name, value] of Object.entries(securityResponseHeaders)) {
    if (headers instanceof Headers) {
      if (name === 'content-security-policy' && headers.has(name)) continue;
      headers.set(name, value);
      continue;
    }
    if (name === 'content-security-policy'
      && Object.keys(headers).some(headerName => headerName.toLowerCase() === name)) continue;
    headers[name] = value;
  }
}

function protectRawResponse(response: Response, requestId: string) {
  const headers = new Headers(response.headers);
  applySecurityResponseHeaders(headers);
  headers.set('x-request-id', requestId);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export function safeRequestUrl(request: Request): string {
  try {
    const url = new URL(request.url);
    return `${url.origin}${url.pathname}`;
  } catch {
    return request.url.split(/[?#]/, 1)[0] || '/';
  }
}

export function generateRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export const observabilityMiddleware = new Elysia({ name: 'observability' })
  .derive({ as: 'global' }, ({ request }) => {
    const requestId = request.headers.get('x-request-id') || generateRequestId();
    request.headers.set('x-request-id', requestId);
    if (!getCurrentRequestId()) enterRequestContext({ requestId });
    return { requestId, startTime: performance.now() };
  })
  .onAfterHandle({ as: 'global' }, ({ requestId, startTime, request, response, set }) => {
    const duration = performance.now() - (startTime ?? 0);
    applySecurityResponseHeaders(set.headers);
    set.headers['x-request-id'] = requestId;

    if (runtimeEnv('LOG_LEVEL') === 'debug') {
      console.log(JSON.stringify({
        level: 'info',
        msg: 'request',
        request_id: requestId,
        method: request.method,
        url: safeRequestUrl(request),
        duration_ms: Math.round(duration),
      }));
    }
    if (response instanceof Response) return protectRawResponse(response, requestId);
  })
  .onError({ as: 'global' }, ({ requestId, startTime, request, error, set }) => {
    const duration = performance.now() - (startTime ?? 0);
    applySecurityResponseHeaders(set.headers);
    set.headers['x-request-id'] = requestId;

    console.error(JSON.stringify({
      level: 'error',
      msg: 'request_error',
      request_id: requestId,
      method: request.method,
      url: safeRequestUrl(request),
      error: (error as Error).message,
      duration_ms: Math.round(duration),
    }));

    const normalizedError = normalizeApiError(
      error,
      requestId || request.headers.get('x-request-id') || 'unknown',
    );
    if (!normalizedError) return;
    set.status = normalizedError.status;
    return normalizedError.body;
  });

interface NormalizedApiError {
  status: number;
  body: Record<string, unknown>;
}

interface ApiErrorContract {
  status: number;
  code: string;
  message: string;
  correlationId: string;
  details?: Record<string, unknown>;
}

function normalizeApiError(error: unknown, correlationId: string): NormalizedApiError | null {
  if (error instanceof ApiContractError) {
    return errorBody({
      status: error.status,
      code: error.code,
      message: error.message,
      correlationId,
      details: error.details,
    });
  }
  return error instanceof SupaCloudApiError
    ? normalizeSupaCloudApiError(error, correlationId)
    : null;
}

function normalizeSupaCloudApiError(
  error: SupaCloudApiError,
  correlationId: string,
): NormalizedApiError {
  if (isStructuredValidationError(error)) {
    return errorBody({
      status: error.status,
      code: 'validation_error',
      message: 'Request validation failed',
      correlationId,
      details: { path: error.path },
    });
  }
  const unavailable = error.status >= 500;
  return errorBody({
    status: error.status === 501 || error.status === 404
      ? error.status
      : unavailable ? 503 : error.status,
    code: error.status === 501
      ? 'capability_unavailable'
      : error.status === 404 ? 'not_found' : 'supacloud_upstream_error',
    message: unavailable ? 'SupaCloud Management API is unavailable' : error.body,
    correlationId,
    details: { path: error.path },
  });
}

function parsedErrorRecord(body: string): Record<string, unknown> | null {
  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch (parseError) {
    if (parseError instanceof SyntaxError) return null;
    throw parseError;
  }
  return payload && typeof payload === 'object' && !Array.isArray(payload)
    ? payload as Record<string, unknown>
    : null;
}

function isStructuredValidationError(error: SupaCloudApiError): boolean {
  if (error.status !== 400 && error.status !== 422) return false;
  const payload = parsedErrorRecord(error.body);
  if (!payload) return false;
  const nestedError = payload.error && typeof payload.error === 'object'
    && !Array.isArray(payload.error)
    ? payload.error as Record<string, unknown>
    : null;
  return [payload.code, nestedError?.code].some(
    code => typeof code === 'string' && code.toLowerCase() === 'validation_error',
  );
}

function errorBody(contract: ApiErrorContract): NormalizedApiError {
  return {
    status: contract.status,
    body: {
      success: false,
      error: {
        code: contract.code,
        message: contract.message,
        correlation_id: contract.correlationId,
        ...(contract.details ? { details: contract.details } : {}),
      },
    },
  };
}

export { getCurrentRequestId } from '../auth/request-context.js';
