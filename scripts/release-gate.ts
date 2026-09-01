#!/usr/bin/env bun
/**
 * Release gate (P0-22).
 *
 * Runs local build/test gates, exports OpenAPI, optionally runs live fixtures,
 * and writes a release manifest with commit and artifact metadata.
 *
 * By default the gate fails when the worktree is dirty or live fixtures are
 * skipped, so release manifests are not produced from under-verified trees.
 * Set ALLOW_DIRTY_RELEASE=1 for local builds that intentionally keep changes.
 * Set ALLOW_SKIP_LIVE_GATE=1 for non-cutover / CI smoke runs.
 */

import { mkdirSync, writeFileSync } from 'node:fs';

const releaseId = process.env.RELEASE_ID || `release-${new Date().toISOString().replace(/[:.]/g, '-')}`;
const artifactDir = process.env.ARTIFACT_DIR || `artifacts/${releaseId}`;
const runLive = process.env.RUN_LIVE_RELEASE_GATE === '1';
const runSupabaseRuntimeCompat = process.env.RUN_SUPABASE_RUNTIME_COMPAT === '1';
const runSupabaseOauth21Compat = process.env.RUN_SUPABASE_OAUTH21_COMPAT === '1';
const allowDirty = process.env.ALLOW_DIRTY_RELEASE === '1';
const allowSkipLive = process.env.ALLOW_SKIP_LIVE_GATE === '1';
const productionRelease = process.env.RELEASE_ENVIRONMENT === 'production';

function run(command: string[], options: { env?: Record<string, string | undefined> } = {}) {
  const result = Bun.spawnSync(command, {
    stdout: 'inherit',
    stderr: 'inherit',
    env: { ...process.env, ...options.env },
  });
  if (result.exitCode !== 0) process.exit(result.exitCode);
}

function output(command: string[]): string {
  const result = Bun.spawnSync(command, { stdout: 'pipe', stderr: 'inherit' });
  if (result.exitCode !== 0) process.exit(result.exitCode);
  return new TextDecoder().decode(result.stdout).trim();
}

const commit = output(['git', 'rev-parse', 'HEAD']);
const status = output(['git', 'status', '--short']);
const isDirty = status.length > 0;

if (productionRelease && (allowDirty || allowSkipLive)) {
  console.error('Release gate FAILED: production releases cannot bypass dirty-worktree or live verification gates.');
  process.exit(1);
}

if (isDirty && !allowDirty) {
  console.error('Release gate FAILED: worktree is dirty.');
  console.error('Uncommitted changes:');
  console.error(status);
  console.error('');
  console.error('Commit or stash your changes, or set ALLOW_DIRTY_RELEASE=1 to override.');
  process.exit(1);
}

if (!runLive && !allowSkipLive) {
  console.error('Release gate FAILED: live fixture gate was not run.');
  console.error('Set RUN_LIVE_RELEASE_GATE=1 for pre-cutover verification, or');
  console.error('ALLOW_SKIP_LIVE_GATE=1 for non-cutover / CI smoke runs.');
  process.exit(1);
}

if (runLive && (!runSupabaseRuntimeCompat || !runSupabaseOauth21Compat)) {
  console.error('Release gate FAILED: live verification requires both Supabase runtime and OAuth 2.1 compatibility suites.');
  process.exit(1);
}

mkdirSync(artifactDir, { recursive: true });

run(['bunx', 'tsc', '--noEmit']);
// 全仓测试会修改 process.env；按文件隔离，避免并行测试互相污染认证配置。
run(['bun', 'test', '--isolate']);
run(['bun', 'run', 'check']);
run(['bun', 'run', 'build'], { env: { SUPAUTH_SUPACLOUD_ARTIFACT_DIR: artifactDir } });
run(['bun', 'run', 'scripts/verify-supacloud-app-artifact.ts', '--artifact-dir', artifactDir]);
run(['bun', 'run', 'scripts/verify-openapi-additive.ts', `${artifactDir}/openapi.json`]);

const supacloudAppManifestHash = output(['shasum', '-a', '256', `${artifactDir}/supacloud-app-manifest.json`]).split(/\s+/)[0];
let supacloudInstalledAppVerification: string | undefined;

if (runLive) {
  const installedBaseUrl = (process.env.SUPAUTH_PUBLIC_URL || process.env.AUTH_PUBLIC_URL || process.env.SUPAUTH_INSTALLED_BASE_URL)?.replace(/\/+$/, '');
  const installedRuntimeUrl = process.env.SUPAUTH_INSTALLED_RUNTIME_URL?.replace(/\/+$/, '');
  if (!installedBaseUrl || !installedRuntimeUrl) {
    console.error('RUN_LIVE_RELEASE_GATE=1 requires SUPAUTH_PUBLIC_URL or SUPAUTH_INSTALLED_BASE_URL, plus SUPAUTH_INSTALLED_RUNTIME_URL');
    process.exit(1);
  }

  if (runSupabaseRuntimeCompat) {
    run([
      'bun',
      '--use-system-ca',
      'test',
      'tests/integration/supabase-compat/supabase-js.test.ts',
      'tests/integration/supabase-compat/full-stack.test.ts',
      'tests/integration/supabase-compat/supacloud-contract.test.ts',
    ], {
      env: {
        REQUIRE_SUPABASE_AUTH_COMPAT: '1',
        RUN_SUPABASE_RUNTIME_COMPAT: '1',
        RUN_SUPABASE_FULL_STACK_COMPAT: '1',
        OAUTH_RUNTIME_URL: process.env.OAUTH_RUNTIME_URL || installedRuntimeUrl,
        MANAGEMENT_URL: process.env.MANAGEMENT_URL || `${installedBaseUrl}/api`,
        SUPABASE_FULLSTACK_URL: process.env.SUPABASE_FULLSTACK_URL || installedRuntimeUrl,
      },
    });
  }

  if (runSupabaseOauth21Compat) {
    run(['bun', '--use-system-ca', 'test', 'tests/integration/supabase-compat/oauth21.test.ts'], {
      env: {
        REQUIRE_SUPABASE_AUTH_COMPAT: '1',
        RUN_SUPABASE_OAUTH21_COMPAT: '1',
        OAUTH_RUNTIME_URL: process.env.OAUTH_RUNTIME_URL || installedRuntimeUrl,
      },
    });
  }

  supacloudInstalledAppVerification = `${artifactDir}/supacloud-installed-app-verification.json`;
  run([
    'bun',
    '--use-system-ca',
    'run',
    'scripts/verify-supacloud-installed-app.ts',
    '--artifact-dir',
    artifactDir,
    '--expected-manifest-hash',
    supacloudAppManifestHash,
    '--output',
    supacloudInstalledAppVerification,
  ]);
}

const openapiHash = output(['shasum', '-a', '256', `${artifactDir}/openapi.json`]);

writeFileSync(`${artifactDir}/release-manifest.json`, JSON.stringify({
  release_id: releaseId,
  commit,
  openapi_hash: openapiHash.split(/\s+/)[0],
  supacloud_app_manifest: `${artifactDir}/supacloud-app-manifest.json`,
  supacloud_app_manifest_hash: supacloudAppManifestHash,
  supacloud_installed_app_verification: supacloudInstalledAppVerification,
  dirty: isDirty,
  live_gate: runLive,
  runtime_mode: 'gotrue',
  created_at: new Date().toISOString(),
}, null, 2));

console.log(`Release gate passed: ${artifactDir}`);
