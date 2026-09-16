# LOLDrivers Astro website

The approved redesign is implemented here as a static Astro review site. The existing Hugo site and production GitHub Pages workflows remain in `loldrivers.io/` and `.github/workflows/`. Merging this preview implementation does not switch the production site.

## Run locally

Use Node 24 (see `.nvmrc`; minimum supported version for the locked dependencies is 22.19).

```sh
cd website
npm ci
npm run dev -- --host 127.0.0.1 --port 55060
```

For a production-style preview:

```sh
npm run build
npm run preview -- --host 127.0.0.1 --port 55060
```

In Conductor, use the workspace's `$CONDUCTOR_PORT` instead of a fixed port when running several workspaces. Commands run from `website/`; catalog paths resolve relative to that directory. The asset preparation step copies the existing project and sponsor logos and favicons into the ignored public asset folders.

## What is included

- The approved charcoal/red and warm white themes, original LOLDrivers logos, and saved theme preference.
- A searchable, sortable, paginated catalog generated from every `../yaml/*.yaml` record. Filename, publisher/company, CVE, UUID, and all sample hashes are indexed. Query/filter/sort/page state is reflected in the URL.
- Static `/drivers/<UUID>/` pages with every sample, copyable hashes, existing binary-download links where a binary exists, source links, research references, CVEs, and detections. Large sample metadata is fetched only when requested.
- Shared MagicSword banners on the homepage and every driver, preserving the existing logos, offer, CTA, and separate homepage/driver campaign parameters.
- Homepage detection/tool callouts and dedicated Detections, Tools, API, About, Search, and all-driver directory pages.
- Existing Defender and Splunk query text and attribution, and the existing community tool destinations.
- Google Analytics component retaining `G-33C5VXLWPQ`. It is **off by default**. An explicit `PUBLIC_ENABLE_ANALYTICS=true` production build enables it; development does not. Normal document navigation emits the normal Google tag page view. There is no client-side router or duplicate manual page-view handler.

The full driver JSON never enters the client JavaScript bundle. The explorer loads `/data/search.json` separately. Each `/data/drivers/<UUID>.json` record is generated from the same YAML as its page. Public API download links continue to use the existing production JSON/CSV endpoints; those exports can differ from unmerged YAML changes in a review branch.

## Review a PR before merging

The **Astro Website Preview** workflow runs on matching PRs and publishes two downloadable artifacts after validation:

- `astro-preview-<PR number>`: the built static site.
- `astro-browser-report-<run ID>`: browser reports and desktop/mobile screenshots.

Extract the site artifact, then run this from the extracted directory:

```sh
python3 -m http.server 4321
```

Open `http://localhost:4321/`. Serve the artifact over HTTP; root-relative links will not work by double-clicking its HTML files. Artifact review needs no deployment credentials and works for fork PRs.

This workflow **does not create a hosted preview URL**. To add hosted PR previews, connect a separate Netlify or Cloudflare Pages project to the repository, set the site build command to `npm --prefix website ci && npm --prefix website run build`, publish `website/dist`, and set Node 24 and `PUBLIC_ENABLE_ANALYTICS=false`. Keep repository root as the working directory for those commands so YAML and existing assets remain available. The provider connection is not configured by this PR. The production GitHub Pages site continues using Hugo until an explicit cutover.

## Validate

```sh
npm run format:check
npm run check
npm run build
npm run verify:build
npm run verify:analytics
npx playwright install chromium
npm test
```

`verify:build` checks all driver routes, sample counts, banner presence and campaign parameters, logos, analytics gating, and the search transfer budget. `verify:analytics` builds a temporary analytics-enabled site, verifies every route, runs the tag initialization in an isolated JavaScript context, and removes the temporary output. It sends no network requests to Google.

The browser suite checks exact non-first-sample hash lookup, filters, pagination, URL restoration, unknown evidence, no-result and retry states, on-demand metadata, no-JavaScript browsing, persistent themes, responsive layout, and absence of analytics requests from previews. The artifact report contains homepage and driver screenshots at desktop and phone widths.

See [the migration checklist](../docs/astro-migration.md) for production cutover and the existing build issues identified during design review.
