import assert from 'node:assert/strict';
import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const root = resolve(process.argv[2] || 'dist');
const analytics = process.argv.includes('--analytics');
const production = process.argv.includes('--production');
const ids = (await readdir('../yaml'))
  .filter((name) => name.endsWith('.yaml'))
  .map((name) => name.slice(0, -5));
const read = (path) => readFile(join(root, path), 'utf8');
const shareImage = 'https://www.loldrivers.io/social/loldrivers-card.png';
function verifySocialCard(html, path) {
  for (const tag of [
    `property="og:image" content="${shareImage}"`,
    'property="og:image:width" content="1200"',
    'property="og:image:height" content="630"',
    'name="twitter:card" content="summary_large_image"',
    `name="twitter:image" content="${shareImage}"`,
  ]) {
    assert.ok(html.includes(tag), `${path}: missing social metadata ${tag}`);
  }
  const content = (attribute, name) =>
    html.match(
      new RegExp(`<meta ${attribute}="${name}" content="([^"]*)"`),
    )?.[1];
  for (const key of ['title', 'description', 'image:alt']) {
    const og = content('property', `og:${key}`);
    assert.ok(og, `${path}: missing social ${key}`);
    assert.equal(
      content('name', `twitter:${key}`),
      og,
      `${path}: social ${key} mismatch`,
    );
  }
}
const card = await readFile(join(root, 'social/loldrivers-card.png'));
assert.equal(card.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
assert.equal(card.readUInt32BE(16), 1200, 'Share image width');
assert.equal(card.readUInt32BE(20), 630, 'Share image height');
assert.ok(card.length < 5_000_000, 'Share image exceeded 5 MB');
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
  verifySocialCard(html, path);
  assert.equal(
    (html.match(/googletagmanager\.com\/gtag\/js\?id=G-33C5VXLWPQ/g) || [])
      .length,
    analytics ? 1 : 0,
    `${path}: analytics gating`,
  );
  assert.equal(
    html.includes('ASTRO REVIEW PREVIEW'),
    !production,
    `${path}: preview banner`,
  );
  assert.equal(
    html.includes('noindex,nofollow'),
    !production,
    `${path}: indexing`,
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
  verifySocialCard(html, id);
  const raw = JSON.parse(await read(`data/drivers/${id}.json`));
  assert.equal(raw.Id, id);
  assert.equal(
    html.includes('ASTRO REVIEW PREVIEW'),
    !production,
    `${id}: preview banner`,
  );
  assert.equal(
    html.includes('noindex,nofollow'),
    !production,
    `${id}: indexing`,
  );
  assert.ok(
    html.includes(`https://www.loldrivers.io/drivers/${id}/`),
    `${id}: canonical`,
  );
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

const sitemap = await read('sitemap.xml');
const feed = await read('index.xml');
const legacySearch = JSON.parse(await read('index.json'));
assert.equal(legacySearch.length, ids.length);
for (const id of ids) {
  assert.ok(
    sitemap.includes(`<loc>https://www.loldrivers.io/drivers/${id}/</loc>`),
  );
  assert.ok(
    feed.includes(`<guid>https://www.loldrivers.io/drivers/${id}/</guid>`),
  );
}
assert.ok(
  (await read('robots.txt')).includes(production ? 'Allow: /' : 'Disallow: /'),
);
if (production) {
  const api = JSON.parse(await read('api/drivers.json'));
  assert.deepEqual(api.map((driver) => driver.Id).sort(), ids.sort());
  for (const driver of api) {
    assert.deepEqual(
      // Python retains -0.0; JavaScript JSON serialization writes 0. Normalize
      // that representation before comparing otherwise identical catalog records.
      JSON.parse(JSON.stringify(driver)),
      JSON.parse(await read(`data/drivers/${driver.Id}.json`)),
      `${driver.Id}: public API diverged from website source`,
    );
  }
  for (const path of [
    'api/drivers.csv',
    'drivers_table.csv',
    'projects.csv',
    'drivers_top_5_products.csv',
    'drivers_top_5_publishers.csv',
  ]) {
    assert.ok(
      (await stat(join(root, path))).size > 0,
      `${path}: missing download`,
    );
  }
  console.log(
    'Verified production indexing, legacy endpoints, and same-revision public API records.',
  );
}
