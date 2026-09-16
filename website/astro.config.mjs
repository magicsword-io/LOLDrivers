import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://www.loldrivers.io',
  output: 'static',
  trailingSlash: 'always',
  devToolbar: { enabled: false },
});
