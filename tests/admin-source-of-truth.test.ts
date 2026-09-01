import { describe, expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';

type RootPackageManifest = {
  scripts: Record<string, string>;
};

const rootPackage = JSON.parse(readFileSync('package.json', 'utf8')) as RootPackageManifest;
const developmentLauncher = readFileSync('scripts/dev.ts', 'utf8');
const applicationBuildScript = readFileSync('scripts/build-supacloud-app.ts', 'utf8');
const readme = readFileSync('README.md', 'utf8');
const rootViteDeprecation =
  "The root Admin Console entry is retired. Use `bun run dev:admin` for development or `bun run --filter '@supauth/admin-console' build` for builds.";

describe('Admin Console source-of-truth contract', () => {
  it('routes supported development, build, and artifact paths through the Admin package', () => {
    expect(rootPackage.scripts['dev:admin']).toBe("bun run --filter '@supauth/admin-console' dev");
    expect(developmentLauncher).toContain("args: ['bun', 'run', 'dev:admin']");
    expect(applicationBuildScript).toContain(
      "run(['bun', 'run', '--filter', '@supauth/admin-console', 'build']",
    );
    expect(applicationBuildScript).toContain("resolve(root, 'packages/admin-console/build')");
  });

  it('runs the Admin source check without dropping existing root gates', () => {
    expect(rootPackage.scripts.check.split(' && ')).toEqual([
      'bun run typecheck',
      'bun run test',
      'bun run check:openapi-additive',
      "bun run --filter '@supauth/admin-console' check",
      "bun run --filter '@supauth/admin-console' build",
    ]);
  });

  it('documents the package as the only executable Admin source in both languages', () => {
    expect(readme).toContain(
      '`packages/admin-console` is the only Admin Console source of truth for development, testing, builds, and deployment.',
    );
    expect(readme).toContain(
      '`packages/admin-console` 是 Admin Console 开发、测试、构建和部署的唯一 source of truth。',
    );
    expect(readme).not.toContain('Root `src/` is a thin sync');
    expect(readme).not.toContain('根目录 `src/` 是 `packages/admin-console/src/` 的轻量同步');
  });

  it('fails closed when the retired root Vite entry is loaded', async () => {
    // @ts-expect-error The retired JS entry is intentionally a declaration-free throwing sentinel.
    await expect(import('../vite.config.js')).rejects.toThrow(rootViteDeprecation);
  });
});
