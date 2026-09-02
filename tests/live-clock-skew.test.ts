import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import { checkLiveClockSkew, type LiveClockCheckOptions } from '../scripts/check-live-clock-skew.js';

const BASE_TIME_MS = 1_700_000_000_000;

describe('live clock skew prerequisite', () => {
  it('uses the request midpoint and accepts the exact five-second boundary', async () => {
    const clockSkewMs = await checkLiveClockSkew(clockOptions({
      serverTimeMs: BASE_TIME_MS + 6_000,
      localTimes: [BASE_TIME_MS, BASE_TIME_MS + 2_000],
    }));

    expect(clockSkewMs).toBe(5_000);
  });

  it('fails when absolute skew exceeds five seconds', async () => {
    await expect(checkLiveClockSkew(clockOptions({
      serverTimeMs: BASE_TIME_MS - 6_000,
      localTimes: [BASE_TIME_MS, BASE_TIME_MS],
    }))).rejects.toThrow('GoTrue clock skew -6.000s exceeds 5.000s');
  });

  it('fails on non-2xx, missing Date, and invalid Date responses', async () => {
    await expect(checkLiveClockSkew(clockOptions({ status: 503 }))).rejects.toThrow('HTTP 503');
    await expect(checkLiveClockSkew(clockOptions({ includeDate: false }))).rejects.toThrow('missing the Date header');
    await expect(checkLiveClockSkew(clockOptions({ dateHeader: 'not-a-date' }))).rejects.toThrow('invalid Date header');
  });

  it('fails when the GoTrue health request times out', async () => {
    const fetchImpl: NonNullable<LiveClockCheckOptions['fetchImpl']> = async (_input, init) => (
      await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
      })
    );

    await expect(checkLiveClockSkew({
      runtimeUrl: 'https://auth.example.test',
      fetchImpl,
      timeoutMs: 5,
    })).rejects.toThrow('timed out after 5ms');
  });

  it('bypasses caches for every GoTrue health request', async () => {
    const requests: Array<{ init?: RequestInit; url: URL }> = [];
    const fetchImpl: NonNullable<LiveClockCheckOptions['fetchImpl']> = async (input, init) => {
      requests.push({ init, url: new URL(input instanceof Request ? input.url : input.toString()) });
      return new Response(null, { headers: { date: new Date(BASE_TIME_MS).toUTCString() } });
    };
    const options = { fetchImpl, now: () => BASE_TIME_MS, runtimeUrl: 'https://auth.example.test' };

    await checkLiveClockSkew(options);
    await checkLiveClockSkew(options);

    expect(requests).toHaveLength(2);
    for (const request of requests) {
      expect(request.url.origin).toBe('https://auth.example.test');
      expect(request.url.pathname).toBe('/auth/v1/health');
      expect(request.url.searchParams.get('clock_check')).toBeTruthy();
      expect(request.init?.cache).toBe('no-store');
      expect(request.init?.signal).toBeInstanceOf(AbortSignal);
    }
    expect(requests[0].url.search).not.toBe(requests[1].url.search);
  });

  it('runs before both strict live compatibility suites', () => {
    for (const workflowPath of ['.github/workflows/ci.yml', '.github/workflows/live-compat.yml']) {
      const workflow = readFileSync(workflowPath, 'utf8');
      const prerequisite = workflow.indexOf('bun --use-system-ca run scripts/check-live-clock-skew.ts');
      const strictSuite = workflow.indexOf('bun run test:supabase-auth-compat');
      expect(prerequisite).toBeGreaterThan(-1);
      expect(prerequisite).toBeLessThan(strictSuite);
      expect(workflow).toContain('OAUTH_RUNTIME_URL: ${{ secrets.LIVE_SUPABASE_AUTH_URL || secrets.LIVE_OAUTH_RUNTIME_URL }}');
      const sessionPreparation = workflow.indexOf('bun --use-system-ca run scripts/prepare-supabase-auth-compat-session.ts');
      if (sessionPreparation > -1) expect(prerequisite).toBeLessThan(sessionPreparation);
    }
    const packageManifest = readFileSync('package.json', 'utf8');
    expect(packageManifest).toContain('bun --use-system-ca test tests/integration/supabase-compat/oauth21.test.ts');
  });

  it('isolates self-hosted checkout from the runner SSH config', () => {
    const ciWorkflow = readFileSync('.github/workflows/ci.yml', 'utf8');
    const liveWorkflow = readFileSync('.github/workflows/live-compat.yml', 'utf8');
    const compatJob = ciWorkflow.slice(
      ciWorkflow.indexOf('  supabase-auth-compat:'),
      ciWorkflow.indexOf('  package-auth-ui:'),
    );
    const liveJob = liveWorkflow.slice(liveWorkflow.indexOf('  live-compat:'));
    const sshCommand = 'ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/Users/zhd/.ssh/known_hosts';

    expect(`${ciWorkflow}\n${liveWorkflow}`.split(`GIT_SSH_COMMAND: ${sshCommand}`)).toHaveLength(3);
    for (const job of [compatJob, liveJob]) {
      expect(job.split(`GIT_SSH_COMMAND: ${sshCommand}`)).toHaveLength(2);
      expect(job).not.toMatch(/ProxyCommand|ProxyJump|7897|StrictHostKeyChecking=no/);
      expect(job).not.toContain('core.sshCommand');
      expect(job).not.toContain('ssh-key:');
      expect(job.indexOf('ssh-keyscan github.com')).toBeLessThan(job.indexOf('- uses: actions/checkout@v6'));
      expect(job.indexOf('insteadOf "https://github.com/"')).toBeLessThan(job.indexOf('- uses: actions/checkout@v6'));
    }
    expect(ciWorkflow.slice(0, ciWorkflow.indexOf('  supabase-auth-compat:'))).not.toContain('GIT_SSH_COMMAND');
    expect(ciWorkflow.slice(ciWorkflow.indexOf('  package-auth-ui:'))).not.toContain('GIT_SSH_COMMAND');
  });
});

interface ClockFixture {
  serverTimeMs?: number;
  localTimes?: [number, number];
  status?: number;
  includeDate?: boolean;
  dateHeader?: string;
}

function clockOptions(fixture: ClockFixture): LiveClockCheckOptions {
  const localTimes = [...(fixture.localTimes ?? [BASE_TIME_MS, BASE_TIME_MS])];
  const headers = new Headers();
  if (fixture.includeDate !== false) {
    headers.set('date', fixture.dateHeader ?? new Date(fixture.serverTimeMs ?? BASE_TIME_MS).toUTCString());
  }
  return {
    runtimeUrl: 'https://auth.example.test',
    fetchImpl: async () => new Response(null, { status: fixture.status ?? 200, headers }),
    now: () => localTimes.shift() ?? BASE_TIME_MS,
  };
}
