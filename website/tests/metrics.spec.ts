import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { DriverSummary } from '../src/lib/drivers';
import { catalogGrowth } from '../src/lib/catalog-growth';

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
  const growth = metrics.locator('[data-growth-chart]');
  const points: { month: string; added: number; total: number }[] = JSON.parse(
    (await growth.getAttribute('data-points'))!,
  );
  for (const point of points) {
    expect(point.added).toBe(
      catalog.filter((driver) => driver.created.startsWith(point.month)).length,
    );
    expect(point.total).toBe(
      catalog.filter((driver) => driver.created.slice(0, 7) <= point.month)
        .length,
    );
  }
  expect(points.at(-1)?.total).toBe(catalog.length);
  expect(points.reduce((sum, point) => sum + point.added, 0)).toBe(
    catalog.length,
  );
  await expect(growth.locator('[data-growth-total]')).toHaveText(
    format(catalog.length),
  );
  await expect(metrics.locator('.metric-tag')).toHaveText(
    `${format(samples)} samples`,
  );
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
  await expect(
    staticPage.getByRole('img', {
      name: 'Cumulative driver entries over time',
    }),
  ).toBeVisible();
  await expect(staticPage.locator('[data-growth-total]')).toHaveText(
    format(catalog.length),
  );
  await expect(staticPage.locator('[data-growth-scrubber]')).toBeHidden();
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

test('growth includes quiet months, year boundaries, and excludes invalid dates', () => {
  expect(
    catalogGrowth([
      { created: '2024-02-29' },
      { created: '2023-12-31' },
      { created: '2023-12-01' },
      { created: '' },
      { created: '2024-02-30' },
      { created: '2023-02-29' },
      { created: '2024-13-01' },
    ]),
  ).toEqual({
    points: [
      { month: '2023-12', added: 2, total: 2 },
      { month: '2024-01', added: 0, total: 2 },
      { month: '2024-02', added: 1, total: 3 },
    ],
    undated: 4,
  });
  expect(catalogGrowth([])).toEqual({ points: [], undated: 0 });
  expect(catalogGrowth([{ created: 'unknown' }])).toEqual({
    points: [],
    undated: 1,
  });
  expect(catalogGrowth([{ created: '2026-09-01' }])).toEqual({
    points: [{ month: '2026-09', added: 1, total: 1 }],
    undated: 0,
  });
});

test('growth chart supports pointer and keyboard inspection of monthly additions', async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  const chart = page.locator('[data-growth-chart]');
  const points: { label: string; added: number; total: number; x: number }[] =
    JSON.parse((await chart.getAttribute('data-points'))!);
  const slider = page.getByRole('slider', { name: 'Month in catalog growth' });
  const expectPoint = async (index: number) => {
    await expect(chart.locator('[data-growth-month]')).toHaveText(
      points[index].label,
    );
    await expect(chart.locator('[data-growth-total]')).toHaveText(
      format(points[index].total),
    );
    await expect(chart.locator('[data-growth-added]')).toHaveText(
      `+${format(points[index].added)} added`,
    );
    await expect(slider).toHaveAttribute(
      'aria-valuetext',
      `${points[index].label}: ${format(points[index].total)} total driver entries, ${format(points[index].added)} added`,
    );
  };
  await slider.focus();
  await page.keyboard.press('Home');
  await expectPoint(0);
  await page.keyboard.press('ArrowRight');
  await expectPoint(1);
  await page.keyboard.press('End');
  await expectPoint(points.length - 1);
  await page.keyboard.press('Tab');

  const plot = chart.locator('svg');
  const bounds = (await plot.boundingBox())!;
  const quietMonth = points.findIndex((point) => point.added === 0);
  expect(quietMonth).toBeGreaterThan(-1);
  await page.mouse.move(
    bounds.x + (points[quietMonth].x / 300) * bounds.width,
    bounds.y + bounds.height / 2,
  );
  await expectPoint(quietMonth);
  await page.mouse.move(0, 0);
  await expectPoint(points.length - 1);
});

test('tapping the growth chart keeps the selected month on mobile', async ({
  browser,
}) => {
  const context = await browser.newContext({
    viewport: { width: 390, height: 844 },
    hasTouch: true,
    isMobile: true,
    reducedMotion: 'reduce',
  });
  await context.route(
    /https:\/\/(www\.)?(googletagmanager|google-analytics)\.com\//,
    (route) => route.abort(),
  );
  const page = await context.newPage();
  await page.goto('http://127.0.0.1:4321/');
  const chart = page.locator('[data-growth-chart]');
  const points: { label: string; total: number; x: number }[] = JSON.parse(
    (await chart.getAttribute('data-points'))!,
  );
  const point = points[Math.floor(points.length / 2)];
  await chart.scrollIntoViewIfNeeded();
  const bounds = (await chart.locator('svg').boundingBox())!;
  await page.touchscreen.tap(
    bounds.x + (point.x / 300) * bounds.width,
    bounds.y + bounds.height / 2,
  );
  await expect(chart.locator('[data-growth-month]')).toHaveText(point.label);
  await expect(chart.locator('[data-growth-total]')).toHaveText(
    format(point.total),
  );
  await expect(chart.locator('[data-growth-scrubber]')).toBeFocused();
  await context.close();
});
