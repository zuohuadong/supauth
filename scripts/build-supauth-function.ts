#!/usr/bin/env bun

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const authServerDir = resolve(root, 'packages/auth-server');
const entrypoint = resolve(authServerDir, 'src/supacloud-function.ts');
const outdir = resolve(authServerDir, 'dist/supacloud-function');

function resolveRuntimeSafeEntry(packageName: string, entrypointName?: string) {
  try {
    return Bun.resolveSync(entrypointName ? `${packageName}/${entrypointName}` : packageName, authServerDir);
  } catch (error) {
    throw new Error(
      `无法解析 ${packageName}/${entrypointName}（基准目录：${authServerDir}）：${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

const fileTypeEntry = resolveRuntimeSafeEntry('file-type');

const build = await Bun.build({
  entrypoints: [entrypoint],
  outdir,
  target: 'bun',
  format: 'esm',
  sourcemap: 'none',
  plugins: [
    {
      name: 'supauth-edge-runtime-safe-dependencies',
      setup(builder) {
        builder.onResolve({ filter: /^file-type$/ }, () => {
          // Elysia 只使用 Blob/内存类型检测；file-type@22 的主入口不静态引入文件系统模块。
          return { path: fileTypeEntry, namespace: 'supauth-file-type' };
        });
        builder.onLoad({ filter: /.*/, namespace: 'supauth-file-type' }, (args) => {
          const source = readFileSync(args.path, 'utf8');
          const runtimeImport = 'function importAtRuntime(specifier) {\n\treturn import(specifier);\n}';
          if (!source.includes(runtimeImport)) {
            throw new Error('file-type 主入口结构已变化，无法安全禁用 Node 文件系统动态导入');
          }
          return {
            contents: source.replace(
              runtimeImport,
              "function importAtRuntime() {\n\treturn Promise.reject(new Error('Edge Runtime 不支持 file-type 的文件系统入口'));\n}",
            ),
            loader: 'js',
            resolveDir: dirname(args.path),
          };
        });
        builder.onResolve({ filter: /^fflate$/ }, () => {
          return { path: resolveRuntimeSafeEntry('fflate', 'browser') };
        });
      },
    },
  ],
});

if (!build.success) {
  const details = build.logs.map((log) => log.message).filter(Boolean).join('\n');
  throw new Error(`SupAuth Function 构建失败${details ? `：\n${details}` : ''}`);
}

if (build.outputs.length !== 1) {
  const outputs = build.outputs.map((output) => output.path).join(', ') || '(无输出)';
  throw new Error(`SupAuth Function 必须生成单文件 bundle，实际输出 ${build.outputs.length} 个：${outputs}`);
}

console.log(`Built SupAuth Function bundle: ${build.outputs[0].path}`);
