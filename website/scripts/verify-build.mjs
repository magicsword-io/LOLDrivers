import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const root = resolve(process.argv[2] || 'dist');
const analytics = process.argv.includes('--analytics');
const ids = (await readdir('../yaml'))
  .filter((name) => name.endsWith('.yaml'))
  .map((name) => name.slice(0, -5));
const read = (path) => readFile(join(root, path), 'utf8');
const search = JSON.parse(await read('data/search.json'));
assert.equal(search.length, ids.length);
assert.equal(new Set(search.map((driver) => driver.id)).size, ids.length);
assert.ok(
  (await stat(join(root, 'data/search.json'))).size < 2_000_000,
  'Search index exceeded 2 MB',
);

for (const path of [
  'index.html',
  'drivers/index.html',
  'detections/index.html',
  'tools/index.html',
  'api/index.html',
  'about/index.html',
  'search/index.html',
  '404.html',
]) {
  const html = await read(path);
  assert.equal(
    (html.match(/googletagmanager\.com\/gtag\/js\?id=G-33C5VXLWPQ/g) || [])
      .length,
    analytics ? 1 : 0,
    `${path}: analytics gating`,
  );
  assert.ok(
    html.includes('/images/logo-dark.png') && html.includes('/images/logo.png'),
    `${path}: brand logos`,
  );
}
const home = await read('index.html');
assert.equal(
  (home.match(/aria-label="MagicSword prevention"/g) || []).length,
  1,
);
assert.ok(home.includes('utm_content=homepage_cta'));
assert.ok(
  !home.includes('KnownVulnerableSamples'),
  'Homepage embeds full raw data',
);
for (const id of ids) {
  const html = await read(`drivers/${id}/index.html`);
  const raw = JSON.parse(await read(`data/drivers/${id}.json`));
  assert.equal(raw.Id, id);
  assert.equal(
    (html.match(/aria-label="MagicSword prevention"/g) || []).length,
    1,
    `${id}: missing/duplicate banner`,
  );
  assert.ok(
    html.includes('utm_content=driver_block_banner'),
    `${id}: campaign link`,
  );
  assert.equal(
    (html.match(/class="sample"/g) || []).length,
    raw.KnownVulnerableSamples.length,
    `${id}: sample count`,
  );
  assert.equal(
    (html.match(/googletagmanager\.com\/gtag\/js\?id=G-33C5VXLWPQ/g) || [])
      .length,
    analytics ? 1 : 0,
    `${id}: analytics gating`,
  );
}
console.log(
  `Verified ${ids.length} UUID routes, all sample counts, banners, logos, search budget, and ${analytics ? 'enabled' : 'disabled'} analytics.`,
);
