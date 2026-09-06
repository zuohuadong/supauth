// P0-29: SupaOAuth route/domain integration gate
// Validates that all expected routes are reachable on the target
// SupaCloud stack and no Supabase standard paths are broken.

import { Elysia } from 'elysia';
import { lookup as dnsLookup } from 'node:dns/promises';
import { getConfig } from '../config/index.js';
import { runtimeEnv } from '../config/platform-env.js';

export interface RouteProbe {
  name: string;
  path: string;
  method: string;
  expectedStatus: number[];
  actualStatus: number | null;
  ok: boolean;
  error?: string;
  responseSnippet?: string;
}

export interface DomainAudit {
  domain: string;
  functionReachable: boolean;
  apiReachable: boolean;
  authReachable: boolean;
  tlsValid: boolean;
  error?: string;
}

export interface IntegrationGateResult {
  timestamp: string;
  projectRef: string;
  routes: RouteProbe[];
  domainAudit: DomainAudit[];
  envAudit: {
    supacloudApiUrl: string;
    oauthRuntimeUrl: string;
    runtimeMode: string;
    corsOrigins: string[];
    supauthUrl: string;
    runtimeUrl: string;
    extraDomains: string[];
  };
  allPassed: boolean;
  conflicts: string[];
}

/**
 * Probe a single HTTP endpoint.
 */
async function probeRoute(
  baseUrl: string,
  name: string,
  path: string,
  method: string = 'GET',
  expectedStatus: number[] = [200],
  headers: Record<string, string> = {},
  lookup: AddressLookup = defaultAddressLookup,
): Promise<RouteProbe> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await safeFetch(`${baseUrl}${path}`, {
      method,
      headers,
      signal: controller.signal,
    }, lookup);
    const body = await res.text().catch(() => '');
    const ok = expectedStatus.includes(res.status) &&
      !body.includes('no Route matched with those values');
    return {
      name,
      path,
      method,
      expectedStatus,
      actualStatus: res.status,
      ok,
      error: ok ? undefined : body.slice(0, 200),
    };
  } catch (e) {
    return {
      name,
      path,
      method,
      expectedStatus,
      actualStatus: null,
      ok: false,
      error: e instanceof Error ? e.message : String(e),
    };
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

type ResolvedAddress = { address: string; family: 4 | 6 };
type AddressLookup = (hostname: string) => Promise<readonly ResolvedAddress[]>;

const defaultAddressLookup: AddressLookup = async (hostname) => (
  await dnsLookup(hostname, { all: true, verbatim: true })
).map(({ address, family }) => ({ address, family: family as 4 | 6 }));

function ipv4Parts(address: string): number[] | null {
  const parts = address.split('.');
  if (parts.length !== 4 || parts.some(part => !/^\d{1,3}$/.test(part))) return null;
  const numbers = parts.map(Number);
  return numbers.every(part => part >= 0 && part <= 255) ? numbers : null;
}

function inIpv4Range(address: string, network: readonly number[], prefix: number): boolean {
  const parts = ipv4Parts(address);
  if (!parts) return false;
  let remaining = prefix;
  for (let index = 0; index < network.length; index++) {
    const bits = Math.min(remaining, 8);
    const mask = 0xff << (8 - bits) & 0xff;
    if ((parts[index]! & mask) !== (network[index]! & mask)) return false;
    remaining -= bits;
    if (remaining <= 0) return true;
  }
  return true;
}

function ipv4IsBlocked(address: string): boolean {
  return ([
    [[0, 0, 0, 0], 8],
    [[10, 0, 0, 0], 8],
    [[100, 64, 0, 0], 10],
    [[127, 0, 0, 0], 8],
    [[169, 254, 0, 0], 16],
    [[172, 16, 0, 0], 12],
    [[192, 0, 0, 0], 24],
    [[192, 0, 2, 0], 24],
    [[192, 168, 0, 0], 16],
    [[198, 18, 0, 0], 15],
    [[198, 51, 100, 0], 24],
    [[203, 0, 113, 0], 24],
    [[224, 0, 0, 0], 4],
    [[240, 0, 0, 0], 4],
  ] as const)
    .some(([network, prefix]) => inIpv4Range(address, network, prefix));
}

function ipv6Parts(address: string): number[] | null {
  const normalized = address.toLowerCase().split('%')[0]!;
  const embeddedIpv4 = normalized.match(/(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/);
  const ipv4 = embeddedIpv4 ? ipv4Parts(embeddedIpv4[1]!) : null;
  if (embeddedIpv4 && !ipv4) return null;
  const withoutIpv4 = embeddedIpv4
    ? normalized.slice(0, normalized.length - embeddedIpv4[1]!.length).replace(/:$/, '')
    : normalized;
  const ipv4Groups = ipv4 ? [(ipv4[0]! << 8) | ipv4[1]!, (ipv4[2]! << 8) | ipv4[3]!] : [];
  const halves = withoutIpv4.split('::');
  if (halves.length > 2) return null;
  const parseHalf = (half: string) => half
    ? half.split(':').filter(Boolean).map(part => parseInt(part, 16))
    : [];
  const left = parseHalf(halves[0]!);
  const right = halves.length === 2 ? parseHalf(halves[1]!) : [];
  if ([...left, ...right, ...ipv4Groups].some(part => !Number.isInteger(part) || part < 0 || part > 0xffff)) return null;
  const missing = 8 - left.length - right.length - ipv4Groups.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  return [...left, ...Array.from({ length: missing }, () => 0), ...right, ...ipv4Groups];
}

function inIpv6Range(address: string, network: readonly number[], prefix: number): boolean {
  const parts = ipv6Parts(address);
  if (!parts) return false;
  let remaining = prefix;
  for (let index = 0; index < network.length; index++) {
    const bits = Math.min(remaining, 16);
    const mask = 0xffff << (16 - bits) & 0xffff;
    if ((parts[index]! & mask) !== (network[index]! & mask)) return false;
    remaining -= bits;
    if (remaining <= 0) return true;
  }
  return true;
}

function ipv6IsBlocked(address: string): boolean {
  const parts = ipv6Parts(address);
  if (!parts) return false;
  const isZero = parts.every(part => part === 0);
  const isLoopback = parts.slice(0, 7).every(part => part === 0) && parts[7] === 1;
  return isZero || isLoopback || ([
    [[0xfc00, 0, 0, 0, 0, 0, 0, 0], 7],
    [[0xfe80, 0, 0, 0, 0, 0, 0, 0], 10],
    [[0xff00, 0, 0, 0, 0, 0, 0, 0], 8],
    [[0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32],
  ] as const)
    .some(([network, prefix]) => inIpv6Range(address, network, prefix));
}

function isBlockedAddress(address: string, family: 4 | 6): boolean {
  if (family === 4) return ipv4IsBlocked(address);
  const mappedIpv4 = address.match(/::ffff:(\d+(?:\.\d+){3})$/i)?.[1];
  return Boolean(mappedIpv4 && ipv4IsBlocked(mappedIpv4)) || ipv6IsBlocked(address);
}

export async function validateRouteGateTarget(
  target: string,
  lookup: AddressLookup = defaultAddressLookup,
  options: { allowQueryAndFragment?: boolean } = {},
): Promise<URL> {
  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new TypeError('Route Gate target must be a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new TypeError('Route Gate target must be an http(s) URL without credentials');
  }
  if (!url.hostname) {
    throw new TypeError('Route Gate target must not contain query or fragment components');
  }
  if (!options.allowQueryAndFragment && (url.search || url.hash)) {
    throw new TypeError('Route Gate target must not contain query or fragment components');
  }

  const literalFamily = ipv4Parts(url.hostname) ? 4 : url.hostname.includes(':') ? 6 : 0;
  const addresses = literalFamily
    ? [{ address: url.hostname.replace(/^\[|\]$/g, ''), family: literalFamily as 4 | 6 }]
    : await lookup(url.hostname);
  if (!addresses.length) throw new TypeError('Route Gate target hostname has no address');
  if (addresses.some(({ address, family }) => isBlockedAddress(address, family))) {
    throw new TypeError('Route Gate target resolves to a loopback, private, link-local, reserved, or multicast address');
  }
  return url;
}

async function safeFetch(
  target: string,
  init: RequestInit,
  lookup: AddressLookup,
): Promise<Response> {
  const initialUrl = await validateRouteGateTarget(target, lookup);
  const response = await fetch(target, { ...init, redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get('location');
    if (location) {
      const redirectUrl = await validateRouteGateTarget(
        new URL(location, initialUrl).toString(),
        lookup,
        { allowQueryAndFragment: true },
      );
      if (redirectUrl.origin !== initialUrl.origin) {
        throw new TypeError('Route Gate blocked a cross-origin redirect');
      }
    }
  }
  return response;
}

function parseCsv(value?: string): string[] {
  return (value || '').split(',').map(item => item.trim()).filter(Boolean);
}

export function resolveRouteGateInput(query?: Record<string, unknown>): {
  projectRef: string;
  supauthUrl: string;
  runtimeUrl: string;
  extraDomains: string[];
} {
  const config = getConfig();
  const supauthUrl = String(
    runtimeEnv('SUPAOAUTH_ROUTE_GATE_ADMIN_URL') ||
    runtimeEnv('SUPAOAUTH_ADMIN_URL') ||
    runtimeEnv('SUPAUTH_INSTALLED_BASE_URL') ||
    runtimeEnv('SUPAUTH_PUBLIC_URL') ||
    '',
  );
  const runtimeUrl = String(
    runtimeEnv('SUPAOAUTH_ROUTE_GATE_RUNTIME_URL') ||
    config.oauthRuntimeUrl,
  );
  const extraDomains = [
    ...parseCsv(runtimeEnv('SUPAOAUTH_ROUTE_GATE_DOMAINS')),
  ];
  if (!supauthUrl || !runtimeUrl) {
    throw new Error('Route Gate requires fixed SupAuth and runtime target configuration');
  }

  return {
    projectRef: String(query?.project_ref || config.projectRef),
    supauthUrl: normalizeBaseUrl(supauthUrl),
    runtimeUrl: normalizeBaseUrl(runtimeUrl),
    extraDomains: extraDomains.map(normalizeBaseUrl),
  };
}

async function auditDomain(baseUrl: string, lookup: AddressLookup): Promise<DomainAudit> {
  try {
    const url = new URL(baseUrl);
    const [adminRes, apiRes, runtimeRes] = await Promise.all([
      safeFetch(`${baseUrl}/api/v1/health`, { signal: AbortSignal.timeout(5000) }, lookup).catch(() => null),
      safeFetch(`${baseUrl}/rest/v1/`, { signal: AbortSignal.timeout(5000) }, lookup).catch(() => null),
      safeFetch(`${baseUrl}/auth/v1/health`, { signal: AbortSignal.timeout(5000) }, lookup).catch(() => null),
    ]);
    return {
      domain: url.hostname,
      functionReachable: adminRes?.ok ?? false,
      apiReachable: apiRes?.ok ?? false,
      authReachable: runtimeRes?.ok ?? false,
      tlsValid: url.protocol === 'https:',
    };
  } catch {
    return {
      domain: baseUrl,
      functionReachable: false,
      apiReachable: false,
      authReachable: false,
      tlsValid: false,
      error: 'Failed to resolve or connect',
    };
  }
}

/**
 * Run the full integration gate against a SupaCloud stack.
 * Tests all standard Supabase routes plus SupaOAuth-specific routes.
 */
export async function runIntegrationGate(
  projectRef: string,
  supauthUrl: string,
  runtimeUrl: string,
  extraDomains: string[] = [],
  options: { lookup?: AddressLookup } = {},
): Promise<IntegrationGateResult> {
  const config = getConfig();
  const lookup = options.lookup || defaultAddressLookup;
  const conflicts: string[] = [];
  const normalizedSupauthUrl = normalizeBaseUrl(supauthUrl);
  const normalizedRuntimeUrl = normalizeBaseUrl(runtimeUrl);
  const normalizedExtraDomains = extraDomains.map(normalizeBaseUrl);
  await Promise.all([
    validateRouteGateTarget(normalizedSupauthUrl, lookup),
    validateRouteGateTarget(normalizedRuntimeUrl, lookup),
    ...normalizedExtraDomains.map(domain => validateRouteGateTarget(domain, lookup)),
  ]);

  // 1. Probe SupAuth SupaCloud Function/Pages routes
  const supauthRoutes: RouteProbe[] = await Promise.all([
    probeRoute(normalizedSupauthUrl, 'admin_root', '/admin', 'GET', [200, 301, 302], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'function_health', '/api/v1/health', 'GET', [200], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'swagger', '/api/swagger', 'GET', [200], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'applications_unauth', '/api/v1/applications', 'GET', [401], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'public_sie', '/v1/public/sign-in-experience/resolve', 'GET', [200, 400, 401, 422], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'public_oauth', '/oauth/authorize', 'GET', [200, 302, 400], {}, lookup),
    probeRoute(normalizedSupauthUrl, 'claim_page', '/claim', 'GET', [200], {}, lookup),
  ]);

  // 2. Probe Supabase runtime routes (must not be broken)
  const runtimeRoutes: RouteProbe[] = await Promise.all([
    probeRoute(normalizedRuntimeUrl, 'gotrue_health', '/auth/v1/health', 'GET', [200], {}, lookup),
    probeRoute(normalizedRuntimeUrl, 'postgrest_root', '/rest/v1/', 'GET', [200, 401, 406], {}, lookup),
    probeRoute(normalizedRuntimeUrl, 'storage_buckets', '/storage/v1/bucket', 'GET', [200, 401], {}, lookup),
    probeRoute(normalizedRuntimeUrl, 'realtime_ws', '/realtime/v1/websocket', 'GET', [200, 400, 403, 426], {}, lookup),
    probeRoute(normalizedRuntimeUrl, 'functions_root', '/functions/v1/', 'GET', [200, 401, 404], {}, lookup),
    probeRoute(normalizedRuntimeUrl, 'auth_v1_signup', '/auth/v1/signup', 'POST', [200, 400, 401, 422], {}, lookup),
  ]);

  // 3. Check for route conflicts
  for (const probe of runtimeRoutes) {
    if (probe.actualStatus === 502 || probe.actualStatus === 503 || probe.actualStatus === 504) {
      conflicts.push(`${probe.name}: upstream error ${probe.actualStatus} on ${probe.path}`);
    }
    if (probe.error?.includes('no Route matched')) {
      conflicts.push(`${probe.name}: SupaCloud gateway route miss on ${probe.path}`);
    }
  }

  // 4. Domain audit
  const domainAudit = await Promise.all(
    [...new Set([normalizedSupauthUrl, normalizedRuntimeUrl, ...normalizedExtraDomains])].map(domain => auditDomain(domain, lookup)),
  );

  const allRoutes = [...supauthRoutes, ...runtimeRoutes];
  const allPassed = allRoutes.every(r => r.ok) && conflicts.length === 0;

  return {
    timestamp: new Date().toISOString(),
    projectRef,
    routes: allRoutes,
    domainAudit,
    envAudit: {
      supacloudApiUrl: config.supacloudApiUrl,
      oauthRuntimeUrl: config.oauthRuntimeUrl,
      runtimeMode: config.runtimeMode,
      corsOrigins: config.corsOrigins,
      supauthUrl: normalizedSupauthUrl,
      runtimeUrl: normalizedRuntimeUrl,
      extraDomains: normalizedExtraDomains,
    },
    allPassed,
    conflicts,
  };
}

export const routeGateRoutes = new Elysia({ prefix: '/v1/route-gate' })
  .get('/', async ({ query }) => {
    const input = resolveRouteGateInput(query as Record<string, unknown>);
    return runIntegrationGate(input.projectRef, input.supauthUrl, input.runtimeUrl, input.extraDomains);
  }, {
    detail: {
      summary: 'Run route/domain integration gate',
      description: 'Validates installed SupAuth Function/Pages routes and preserved Supabase runtime routes on the target SupaCloud project. Reports conflicts, missing routes, and domain health.',
      tags: ['Route Gate'],
    },
  })

  .get('/routes', async ({ query }) => {
    const input = resolveRouteGateInput(query as Record<string, unknown>);
    const result = await runIntegrationGate(input.projectRef, input.supauthUrl, input.runtimeUrl, input.extraDomains);
    return {
      total: result.routes.length,
      passed: result.routes.filter(r => r.ok).length,
      failed: result.routes.filter(r => !r.ok),
      conflicts: result.conflicts,
      allPassed: result.allPassed,
    };
  }, {
    detail: {
      summary: 'Quick route health summary',
      tags: ['Route Gate'],
    },
  });
