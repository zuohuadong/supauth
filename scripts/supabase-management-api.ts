type ManagementApiRequestMethod = 'POST' | 'DELETE';

export async function requestProjectAuthUser(
  managementApiBases: string[],
  tenantRef: string,
  adminKey: string,
  method: ManagementApiRequestMethod,
  body?: Record<string, unknown>,
  fetchImpl: typeof fetch = fetch,
): Promise<Response> {
  if (managementApiBases.length === 0) {
    throw new Error('Missing management API base candidates');
  }

  let lastResponse: Response | null = null;
  for (const managementApiBase of managementApiBases) {
    const response = await fetchImpl(`${managementApiBase}/v1/projects/${encodeURIComponent(tenantRef)}/auth/users`, {
      method,
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        apikey: adminKey,
        authorization: `Bearer ${adminKey}`,
        'x-project-ref': tenantRef,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    lastResponse = response;
    if (response.status !== 404) return response;
  }
  return lastResponse!;
}

export async function lookupCompatibilityUserId(
  managementApiBases: string[],
  tenantRef: string,
  adminKey: string,
  email: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string | null> {
  if (managementApiBases.length === 0) {
    throw new Error('Missing management API base candidates');
  }

  for (let attempt = 0; attempt < 6; attempt += 1) {
    for (const managementApiBase of managementApiBases) {
      const response = await fetchImpl(`${managementApiBase}/v1/projects/${encodeURIComponent(tenantRef)}/auth/users?email=${encodeURIComponent(email)}&limit=1&page=1`, {
        headers: {
          accept: 'application/json',
          apikey: adminKey,
          authorization: `Bearer ${adminKey}`,
          'x-project-ref': tenantRef,
        },
      });
      if (response.status === 404) continue;
      if (!response.ok) {
        throw new Error(`Unable to look up compatibility user: status=${response.status} for ${managementApiBase}`);
      }

      const payload = await response.json().catch(() => null) as { items?: Array<Record<string, unknown>>; users?: Array<Record<string, unknown>>; data?: Array<Record<string, unknown>> } | null;
      const candidates = [
        ...(Array.isArray(payload?.items) ? payload.items : []),
        ...(Array.isArray(payload?.users) ? payload.users : []),
        ...(Array.isArray(payload?.data) ? payload.data : []),
      ];
      const match = candidates.find((item) => typeof item?.id === 'string' && typeof item?.email === 'string' && item.email.toLowerCase() === email.toLowerCase());
      if (typeof match?.id === 'string') return match.id;
    }
    if (attempt < 5) await delay(250);
  }
  return null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
