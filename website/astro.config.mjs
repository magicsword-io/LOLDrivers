import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://www.loldrivers.io',
  output: 'static',
  redirects: { '/tags/': '/drivers/', '/categories/': '/drivers/' },
  trailingSlash: 'always',
  devToolbar: { enabled: false },
});
