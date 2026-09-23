# LOLDrivers Astro website

This is the primary LOLDrivers website. `Deploy Site` builds Astro and publishes its validated `dist/` artifact to GitHub Pages at **https://www.loldrivers.io/** on main pushes. Pull requests validate the same production configuration without deployment permissions. Tagged releases do not publish a website. Legacy Hugo files remain as historical content and shared asset sources; Hugo is not part of the website build.

## Run locally

Use Node 24 (`.nvmrc`) and Python 3.11. From the repository root, create an environment and generate the legacy public APIs from the same YAML used by Astro:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r website/requirements.txt
python bin/export-api.py --output website/public/api
```

Re-run the exporter after YAML changes. It shares the established Python CSV formatter with the maintenance generator; it reads no driver binaries and downloads no blocklists.

Use Node 24 (see `.nvmrc`; minimum supported version for the locked dependencies is 22.19).

```sh
cd website
npm ci
npm run dev -- --host 127.0.0.1 --port 55060
```

For a local review build (analytics disabled, preview notice and noindex enabled):

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
- A manual carousel of the five newest driver entries, with keyboard-accessible previous/next controls on desktop and mobile.
- Visual catalog metrics: classification composition, driver entries grouped by sample count, and sample-level HVCI results. D3 generates the ring SVG at build time; small browser-native animations honor reduced motion. Counts and charts remain visible without JavaScript, and category/HVCI links open matching driver entries in the explorer.
- A branded 1200 × 630 share image and Open Graph/X large-image card metadata on all pages. Driver links retain their own title and description.
- Existing Defender and Splunk query text and attribution, and the existing community tool destinations.
- Google Analytics component retaining `G-33C5VXLWPQ`. It is **off by default**. An explicit `PUBLIC_ENABLE_ANALYTICS=true` production build enables it; development does not. Normal document navigation emits the normal Google tag page view. There is no client-side router or duplicate manual page-view handler.

The full driver JSON never enters the client JavaScript bundle. The explorer loads `/data/search.json` separately. Each `/data/drivers/<UUID>.json` record is generated from the same YAML as its page. Production includes `/api/drivers.json`, `/api/drivers.csv`, and `/drivers_table.csv` generated from the same source revision as the pages. Production verification compares every API record against the page metadata. API links use the public domain, so review builds still link to live production downloads.

## Review a PR before merging

The **Astro Website Preview** workflow runs on matching PRs and publishes two downloadable artifacts after validation:

- `astro-preview-<PR number>`: the built static site.
- `astro-browser-report-<run ID>`: browser reports and desktop/mobile screenshots.

Extract the site artifact, then run this from the extracted directory:

```sh
python3 -m http.server 4321
```

Open `http://localhost:4321/`. Serve the artifact over HTTP; root-relative links will not work by double-clicking its HTML files. Artifact review needs no deployment credentials and works for fork PRs.

This workflow **does not create a hosted preview URL**. To add hosted PR previews, connect a separate Netlify or Cloudflare Pages project to the repository, set the site build command to `npm --prefix website ci && npm --prefix website run build`, publish `website/dist`, and set Node 24 and `PUBLIC_ENABLE_ANALYTICS=false`. Keep repository root as the working directory for those commands so YAML and existing assets remain available. The provider connection is not configured by this PR. Production is served independently by the Astro `Deploy Site` workflow.

## Validate

The social image is committed at `public/social/loldrivers-card.png`. To edit it, update `assets/social-card.html`, install Chromium with `npx playwright install chromium`, and run `npm run generate:social`. Normal builds use the committed PNG without requiring a browser. Social platforms must fetch the deployed metadata and image before the new card appears.

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

## Production validation and deployment

From `website/`, after running the exporter above:

```sh
PUBLIC_SITE_MODE=production PUBLIC_ENABLE_ANALYTICS=true npm run build
npm run verify:build -- dist --analytics --production
TEST_PRODUCTION=true npm test
```

`PUBLIC_SITE_MODE=production` removes the review notice/noindex and allows crawling. Analytics is controlled separately by `PUBLIC_ENABLE_ANALYTICS=true`. Production browser tests intercept Google requests so QA does not send analytics traffic. Preview builds leave both production settings off. `verify:analytics` checks initialization without contacting Google.

The production workflow runs the exporter compatibility tests, formatting/types, full artifact verification, and Chromium against the actual production artifact before uploading it. Only main pushes or manual runs on main can deploy; the deploy job alone gets Pages/OIDC permissions. All production runs share a concurrency group. The artifact contains `source-revision.txt` and is retained for 30 days.

Legacy `/index.json`, RSS URLs, sitemap, robots, CSV downloads, and UUID routes are preserved. Empty legacy taxonomy pages redirect to the driver directory. See the [migration guide](../docs/astro-migration.md) for rollback and post-merge checks.
