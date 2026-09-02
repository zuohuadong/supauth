#!/usr/bin/env bun
/**
 * Build the SupAuth SupaCloud-hosted app artifact.
 *
 * This script produces the deploy contract consumed by SupaCloud after a
 * project is created: Function bundle, Admin Console static assets, route
 * bindings, injected environment names, and OpenAPI.
 */

import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { createSupacloudAppManifest } from './supacloud-app-contract.js';

const root = resolve(new URL('..', import.meta.url).pathname);
const artifactDir = resolve(root, process.env.SUPAUTH_SUPACLOUD_ARTIFACT_DIR || 'artifacts/supacloud-app');
const skipBuild = Bun.argv.includes('--skip-build');

function run(command: string[], options: { env?: Record<string, string | undefined> } = {}) {
  const result = Bun.spawnSync(command, {
    cwd: root,
    stdout: 'inherit',
    stderr: 'inherit',
    env: { ...process.env, ...options.env },
  });
  if (result.exitCode !== 0) process.exit(result.exitCode);
}

function requireFile(path: string) {
  if (!existsSync(path)) {
    throw new Error(`Required SupaCloud app artifact is missing: ${path}`);
  }
}

function rel(path: string) {
  return relative(root, path);
}

mkdirSync(artifactDir, { recursive: true });

if (!skipBuild) {
  run(['bun', 'run', '--filter', '@supauth/shared', 'build']);
  run(['bun', 'run', '--filter', '@supauth/auth-server', 'build']);
  run(['bun', 'run', '--filter', '@supauth/admin-console', 'build'], {
    env: {
      VITE_AUTH_SERVER_URL: '/api',
      VITE_ADMIN_SSO_ISSUER: '',
      VITE_SSO_ISSUER: '',
      VITE_ADMIN_SSO_CLIENT_ID: '',
      VITE_SSO_CLIENT_ID: '',
    },
  });
}

const functionBundle = resolve(root, 'packages/auth-server/dist/supacloud-function/supacloud-function.js');
const adminStaticDir = resolve(root, 'packages/admin-console/build');
const adminIndex = resolve(adminStaticDir, 'index.html');
const hostedAuthorize = resolve(adminStaticDir, 'authorize.html');
const hostedClaim = resolve(adminStaticDir, 'claim.html');
const hostedChangePassword = resolve(adminStaticDir, 'change-password.html');
const hostedAccount = resolve(adminStaticDir, 'account.html');
const hostedLogout = resolve(adminStaticDir, 'logout.html');
const openapiPath = resolve(artifactDir, 'openapi.json');
const manifestPath = resolve(artifactDir, 'supacloud-app-manifest.json');
const deploymentBundleDir = resolve(artifactDir, 'function-bundle');
const packagedFunctionBundle = resolve(deploymentBundleDir, 'index.ts');
const packagedAdminStaticDir = resolve(deploymentBundleDir, 'admin-console/build');

requireFile(functionBundle);
requireFile(adminIndex);
requireFile(hostedAuthorize);
requireFile(hostedClaim);
requireFile(hostedChangePassword);
requireFile(hostedAccount);
requireFile(hostedLogout);

rmSync(deploymentBundleDir, { recursive: true, force: true });
mkdirSync(resolve(deploymentBundleDir, 'admin-console'), { recursive: true });
cpSync(functionBundle, packagedFunctionBundle, { errorOnExist: true });
cpSync(adminStaticDir, packagedAdminStaticDir, { recursive: true, errorOnExist: true });

run(['bun', 'run', 'scripts/export-openapi.ts', openapiPath]);

const manifest = createSupacloudAppManifest({
  functionBundle: rel(packagedFunctionBundle),
  adminStaticDir: rel(packagedAdminStaticDir),
  openapiPath: rel(openapiPath),
});

writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`SupAuth SupaCloud app manifest written to ${rel(manifestPath)}`);
