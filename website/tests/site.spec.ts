import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { DriverSummary } from '../src/lib/drivers';
const catalog: DriverSummary[] = JSON.parse(
  readFileSync('dist/data/search.json', 'utf8'),
);
const total = catalog.length;
const malicious = catalog.filter(
  (driver) => driver.category === 'malicious',
).length;
const unknown = catalog.filter((driver) => driver.unknown > 0).length;

const dell = 'bb808089-5857-4df2-8998-753a7106cb44';
const secondSample =
  '71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009';

test('searches non-first sample hashes, persists URL state, and opens the matching sample', async ({
  page,
}) => {
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.goto('/');
  await page.getByRole('searchbox').fill(secondSample.toUpperCase());
  await expect(page.locator('#result-count')).toHaveText(
    `1 of ${total} driver entries`,
  );
  await expect(page.locator('#rows .filename')).toHaveText('DBUtilDrv2.sys →');
  await page.reload();
  await expect(page.getByRole('searchbox')).toHaveValue(
    secondSample.toUpperCase(),
  );
  await expect(page.locator('#rows .filename')).toHaveCount(1);
  expect(requests.some((url) => url.includes('/api/drivers.json'))).toBe(false);
  expect(
    requests.some(
      (url) =>
        url.includes('google-analytics.com') ||
        url.includes('googletagmanager.com'),
    ),
  ).toBe(false);
  await page.locator('#rows .filename').click();
  await expect(page).toHaveURL(new RegExp(`/drivers/${dell}/`));
  await expect(page.locator('#sample-2')).toHaveAttribute('open', '');
  await expect(page.locator('.ms-promotion')).toContainText(
    'Block DBUtilDrv2.sys across your endpoints',
  );
});

test('filters, pagination, unknown evidence, and empty results', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.locator('#next')).toBeEnabled();
  await page.locator('#next').click();
  await expect(page.locator('#page-label')).toContainText('13–24');
  await page.getByRole('button', { name: `Malicious ${malicious}` }).click();
  await expect(page.locator('#result-count')).toHaveText(
    `${malicious} of ${total} driver entries`,
  );
  await page.getByRole('button', { name: `All drivers ${total}` }).click();
  await page.locator('#hvci').selectOption('unknown');
  await expect(page.locator('#result-count')).toHaveText(
    `${unknown} of ${total} driver entries`,
  );
  await page.getByRole('searchbox').fill('no-such-driver-test-value');
  await expect(page.locator('#rows')).toContainText('No matching drivers');
  await expect(page.locator('#next')).toBeDisabled();
});

test('search failure is recoverable', async ({ page }) => {
  await page.route('**/data/search.json', (route) => route.abort());
  await page.goto('/');
  await expect(page.locator('#search-error')).toBeVisible();
  await page.unroute('**/data/search.json');
  await page.getByRole('button', { name: 'Retry', exact: true }).click();
  await expect(page.locator('#result-count')).toHaveText(
    `${total} of ${total} driver entries`,
  );
  await expect(page.locator('#search-error')).toBeHidden();
});

test('loads metadata only on request and retains theme across navigation', async ({
  page,
}) => {
  const metadataRequests: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/data/drivers/'))
      metadataRequests.push(request.url());
  });
  await page.goto(`/drivers/${dell}/`);
  expect(metadataRequests).toHaveLength(0);
  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(page.locator('.lol-logo-light')).toBeVisible();
  await expect(page.locator('.ms-logo-light')).toBeVisible();
  await page
    .getByRole('button', { name: 'Load full sample metadata' })
    .first()
    .click();
  await expect(page.locator('#metadata-0')).toContainText('SHA256');
  expect(metadataRequests).toHaveLength(1);
  await page
    .getByRole('link', { name: 'LOLDrivers home', exact: true })
    .click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});

test('renders the catalog without JavaScript', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4321/');
  await expect(page.locator('#rows tr')).toHaveCount(12);
  await expect(page.locator('.ms-promotion')).toBeVisible();
  await page.goto('http://127.0.0.1:4321/drivers/');
  await expect(page.locator('.driver-directory li')).toHaveCount(total);
  await context.close();
});

for (const width of [390, 1440]) {
  test(`renders brand, sponsor, and resources at ${width}px`, async ({
    page,
  }, testInfo) => {
    await page.setViewportSize({ width, height: 1000 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    for (const path of [
      '/',
      `/drivers/${dell}/`,
      '/detections/',
      '/tools/',
      '/api/',
      '/about/',
    ]) {
      await page.goto(path);
      await expect(page.locator('.lol-logo-dark')).toBeVisible();
      expect(
        await page
          .locator('.lol-logo-dark')
          .evaluate(
            (image: HTMLImageElement) =>
              image.complete && image.naturalWidth > 0,
          ),
      ).toBe(true);
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBe(width);
      if (path === '/' || path.startsWith('/drivers/')) {
        await expect(page.locator('.ms-promotion')).toHaveCount(1);
        await expect(page.locator('.ms-promotion')).toBeVisible();
        const name = path === '/' ? 'homepage' : 'driver';
        await page.screenshot({
          path: testInfo.outputPath(`${name}-${width}.png`),
          fullPage: true,
        });
      }
    }
    expect(errors).toEqual([]);
  });
}
