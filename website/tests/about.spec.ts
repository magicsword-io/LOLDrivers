import { expect, test } from '@playwright/test';

const contributors = [
  {
    name: 'Michael Haag',
    profile: 'https://twitter.com/M_haggis',
    bio: 'and serves as its CTO',
    image: 'michael-headshot.png',
  },
  {
    name: 'Jose Hernandez',
    profile: 'https://twitter.com/_josehelps',
    bio: "MagicSword's CEO and co-founder",
    image: 'jose-headshot.png',
  },
  {
    name: 'Nasreddine Bencherchali',
    profile: 'https://twitter.com/nas_bench',
    bio: 'works at Cisco/Splunk',
    image: 'nas-headshot.png',
  },
] as const;

test.beforeEach(async ({ context }) => {
  await context.route(
    /https:\/\/(www\.)?(googletagmanager|google-analytics)\.com\//,
    (route) => route.abort(),
  );
});

for (const { width, label } of [
  { width: 1440, label: 'desktop' },
  { width: 390, label: 'mobile' },
]) {
  for (const theme of ['dark', 'light'] as const) {
    test(`restores contributor bios and credits on ${label} ${theme}`, async ({
      page,
    }, testInfo) => {
      await page.setViewportSize({ width, height: 1000 });
      const pageErrors: string[] = [];
      page.on('pageerror', (error) => pageErrors.push(error.message));

      await page.goto('/about/');
      if (theme === 'light') {
        await page
          .getByRole('button', { name: 'Switch to light theme' })
          .click();
      }

      await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      await expect(page.locator('.people-grid')).not.toContainText(
        'Nextron Systems',
      );
      await expect(page.locator('.people-grid')).not.toContainText(
        'Senior Threat Researcher at Splunk',
      );
      await expect(page.locator('.people-grid')).not.toContainText(
        'Director of Threat Research at Splunk (STRT)',
      );
      await expect(
        page.getByRole('heading', {
          name: 'About Living Off The Land Drivers',
        }),
      ).toBeVisible();
      await expect(page.locator('.about-mission')).toContainText(
        'valuable resource in your fight against cyber attacks',
      );

      for (const contributor of contributors) {
        const profile = page.getByRole('link', { name: contributor.name });
        const card = page.locator('.person-card').filter({ has: profile });
        await expect(profile).toHaveAttribute('href', contributor.profile);
        await expect(card).toContainText(contributor.bio);
        const image = page.locator(`img[src="/images/${contributor.image}"]`);
        await expect(image).toBeVisible();
        await expect(image).toHaveJSProperty('naturalWidth', 200);
      }

      // Guard Astro inline-link whitespace, verified from the rendered DOM.
      await expect(page.locator('.about-mission')).toContainText(
        'visit LOLRMM',
      );
      await expect(page.locator('.person-card').nth(0)).toContainText(
        'He helped found Atomic Red Team, LOLDrivers, and LOLRMM, and co-hosts Atomics on a Friday.',
      );
      await expect(page.locator('.person-card').nth(1)).toContainText(
        'include Splunk Attack Range, Splunk Security Content, Git-Wild-Hunt, Melting-Cobalt, and BlackCert.',
      );
      await expect(page.locator('.person-card').nth(1)).toContainText(
        'such as Atomic Red Team and LOLBAS.',
      );
      await expect(page.locator('.person-card').nth(2)).toContainText(
        'the EVTX-ETW-Resources project. He also writes a blog about detection and other security topics.',
      );
      await expect(page.getByLabel('Honorable mentions')).toContainText(
        'Florian and Patrick for all',
      );
      await expect(page.getByLabel('Honorable mentions')).toContainText(
        'for all their help getting the idea and the project off the ground',
      );
      await expect(page.getByRole('link', { name: 'Florian' })).toHaveAttribute(
        'href',
        'https://twitter.com/cyb3rops',
      );
      await expect(page.getByRole('link', { name: 'Patrick' })).toHaveAttribute(
        'href',
        'https://twitter.com/bareiss_patrick',
      );
      await expect(
        page.getByRole('link', { name: 'Atomic Red Team' }).first(),
      ).toHaveAttribute('href', 'https://atomicredteam.io/');
      await expect(
        page.getByRole('link', { name: 'LOLBAS' }).first(),
      ).toHaveAttribute('href', 'https://lolbas-project.github.io/');
      expect(
        await page.evaluate(() => document.documentElement.scrollWidth),
      ).toBe(width);
      expect(pageErrors).toEqual([]);
      await page.screenshot({
        path: testInfo.outputPath(`about-${label}-${theme}.png`),
        fullPage: true,
      });
    });
  }
}
