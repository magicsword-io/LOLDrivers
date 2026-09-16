import { spawnSync } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const directory = '.analytics-check';
try {
  const build = spawnSync(
    process.execPath,
    ['node_modules/astro/./bin/astro.mjs', 'build', '--outDir', directory],
    {
      env: {
        ...process.env,
        PUBLIC_ENABLE_ANALYTICS: 'true',
        PUBLIC_SITE_MODE: 'preview',
      },
      encoding: 'utf8',
    },
  );
  if (build.status !== 0) throw new Error(build.stderr || build.stdout);
  const verify = spawnSync(
    process.execPath,
    ['scripts/verify-build.mjs', directory, '--analytics'],
    { encoding: 'utf8' },
  );
  if (verify.status !== 0) throw new Error(verify.stderr || verify.stdout);
  process.stdout.write(verify.stdout);
  const html = await readFile(`${directory}/index.html`, 'utf8');
  const snippet = [
    ...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g),
  ].find(([, body]) => body.includes("gtag('config'"))?.[1];
  assert.ok(snippet, 'Google tag initialization not found');
  const context = { dataLayer: [] };
  context.window = context;
  vm.runInNewContext(snippet, context);
  assert.equal(
    context.dataLayer.filter(
      (args) => args[0] === 'config' && args[1] === 'G-33C5VXLWPQ',
    ).length,
    1,
  );
  console.log(
    'Google tag initializes the existing property once. No requests were sent.',
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
