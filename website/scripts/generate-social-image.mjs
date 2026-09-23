import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Run manually when changing the card design. The PNG is committed so normal
// builds do not need a browser or fetch assets from an external service.
const output = new URL('../public/social/loldrivers-card.png', import.meta.url);
await mkdir(new URL('./', output), { recursive: true });
const browser = await chromium.launch();
try {
  const page = await browser.newPage({
    viewport: { width: 1200, height: 630 },
    deviceScaleFactor: 1,
  });
  await page.goto(new URL('../assets/social-card.html', import.meta.url).href);
  await page.evaluate(async () => {
    await document.fonts.ready;
    await Promise.all([...document.images].map((image) => image.decode()));
  });
  await page.screenshot({ path: fileURLToPath(output) });
  console.log(`Generated ${fileURLToPath(output)}`);
} finally {
  await browser.close();
}
