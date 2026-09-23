import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { DriverSummary } from '../src/lib/drivers';

const catalog: DriverSummary[] = JSON.parse(
  readFileSync('dist/data/search.json', 'utf8'),
);
const samples = catalog.reduce((sum, driver) => sum + driver.samples, 0);
const format = (value: number) => value.toLocaleString('en-US');

test.beforeEach(async ({ context }) => {
  await context.route(
    /https:\/\/(www\.)?(googletagmanager|google-analytics)\.com\//,
    (route) => route.abort(),
  );
});

test('chart totals reconcile with the catalog and HVCI links filter driver entries', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  const metrics = page.getByRole('region', { name: 'The catalog at a glance' });
  await expect(metrics.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
  for (const [name, category] of [
    ['Vulnerable', 'vulnerable driver'],
    ['Malicious', 'malicious'],
  ]) {
    await expect(
      metrics.getByRole('link', { name: new RegExp(name) }),
    ).toContainText(
      format(catalog.filter((driver) => driver.category === category).length),
    );
  }
  const bins = [
    [0, 0],
    [1, 1],
    [2, 5],
    [6, 10],
    [11, 20],
    [21, Infinity],
  ];
  const counts = bins
    .map(
      ([min, max]) =>
        catalog.filter(
          (driver) => driver.samples >= min && driver.samples <= max,
        ).length,
    )
    .filter((count, index) => index !== 0 || count > 0);
  await expect(metrics.locator('.bin-value')).toHaveText(counts.map(format));
  expect(counts.reduce((sum, count) => sum + count, 0)).toBe(catalog.length);
  for (const status of ['yes', 'no', 'unknown'] as const) {
    const count = catalog.reduce((sum, driver) => sum + driver[status], 0);
    const link = metrics.locator(`[data-hvci-result="${status}"]`);
    await expect(link).toContainText(format(count));
    await link.focus();
    await expect(metrics.locator('[data-ring-value]')).toHaveText(
      ((count / samples) * 100).toFixed(1),
    );
    await expect(
      metrics.locator(`[data-ring-segment="${status}"]`),
    ).toHaveClass(/is-active/);
  }
  await metrics.locator('[data-hvci-result="unknown"]').click();
  await expect(page.locator('#hvci')).toHaveValue('unknown');
  await expect(page.locator('#result-count')).toHaveText(
    `${catalog.filter((driver) => driver.unknown > 0).length} of ${catalog.length} driver entries`,
  );
  // Summary charts always describe the full catalog, including after a filter.
  await expect(page.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
});

test('metrics render without JavaScript and respect reduced motion', async ({
  browser,
  page,
}) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const staticPage = await context.newPage();
  await staticPage.goto('http://127.0.0.1:4321/');
  await expect(staticPage.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
  await expect(staticPage.locator('[data-ring-segment]')).toHaveCount(3);
  await expect(staticPage.locator('.classification-bar')).toBeVisible();
  await context.close();

  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  await page.locator('[data-metrics]').scrollIntoViewIfNeeded();
  await expect(page.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
  expect(
    await page
      .locator('[data-metrics]')
      .evaluate((element) => element.getAnimations({ subtree: true }).length),
  ).toBe(0);
});

test('entrance animation finishes with exact values and can be stopped by reduced motion', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await page.locator('[data-metrics]').scrollIntoViewIfNeeded();
  await expect
    .poll(() =>
      page
        .locator('[data-metrics]')
        .evaluate((element) => element.getAnimations({ subtree: true }).length),
    )
    .toBeGreaterThan(0);
  await expect
    .poll(() =>
      page
        .locator('[data-metrics]')
        .evaluate((element) => element.getAnimations({ subtree: true }).length),
    )
    .toBe(0);
  await expect(page.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
  await page.reload();
  await page.locator('[data-metrics]').scrollIntoViewIfNeeded();
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('[data-count]')).toHaveText([
    format(catalog.length),
    format(samples),
  ]);
  expect(
    await page
      .locator('[data-metrics]')
      .evaluate((element) => element.getAnimations({ subtree: true }).length),
  ).toBe(0);
});
