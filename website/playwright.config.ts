import { defineConfig } from '@playwright/test';

const baseURL = `http://127.0.0.1:${process.env.PLAYWRIGHT_PORT || '4321'}`;

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    browserName: 'chromium',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node scripts/serve-test.mjs',
    url: baseURL,
    reuseExistingServer: !process.env.CI,
  },
});
