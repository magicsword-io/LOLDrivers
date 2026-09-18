# Astro redesign and production cutover

The primary site is Astro in [`website/`](../website/README.md). Merging the production cutover replaces Hugo publication with a tested Astro artifact on the existing GitHub Pages custom domain. Legacy Hugo content remains in the repository for compatibility/reference; no active website or release deployment builds Hugo.

## Accepted design requirements

- Charcoal surfaces and restrained LOLDrivers red accents; a warm white alternative with saved theme preference. Use amber for vulnerable categories, red for malicious categories, and text labels for both. Keep MagicSword's green identity.
- Original LOLDrivers light/dark logos in a shared header. Driver search, Detections, Tools, API, and About are primary navigation destinations.
- MagicSword banner on the homepage and **every driver**, preserving “Free for up to 100 endpoints,” the CTA, and existing UTM values. The driver banner names the current driver.
- Preserve GA4 property **G-33C5VXLWPQ**, enabled explicitly for production and disabled in review builds.
- Homepage shortcuts and resource cards for Detections & policies and Tools & integrations, with detailed destinations for each.
- Every source YAML entry and sample remains available. Show unknown/mixed HVCI evidence explicitly. Keep the full catalog JSON out of the browser bundle and large metadata out of initial driver-page payloads.

## Production artifact chain

`Deploy Site` runs on PRs, main pushes, and manual dispatch. It checks out the event revision, generates public JSON/CSV APIs directly from that revision's YAML using the shared legacy Python formatter, builds Astro with production metadata/analytics, verifies every UUID route and API record, and runs Chromium against that exact output. Only after those checks pass is `website/dist` uploaded. Only main push/manual runs may publish via the `github-pages` environment. The build is read-only; Pages/OIDC permissions exist only in the deploy job. Production runs are serialized.

This removes the cross-workflow `workflow_run` dependency, so failed or racing generated-content commits cannot supply stale data to the website. The API exporter needs neither LFS binaries nor Microsoft's blocklist service. The release workflow packages `drivers.zip` after validation and cannot redeploy Hugo.

## Preserved URL and presentation contract

- Existing `/drivers/<UUID>/`, `/about/`, `/search/`; new `/detections/`, `/tools/`, `/api/`, and driver directory.
- `/api/drivers.json` and `/api/drivers.csv`: same established Python schema/format, generated from current YAML. `/drivers_table.csv` remains available.
- `/projects.csv`, `/drivers_top_5_products.csv`, `/drivers_top_5_publishers.csv`: existing compatibility downloads retained unchanged (legacy snapshots, not newly calculated metrics).
- `/index.json`: legacy search field names with current driver entries. Root and driver RSS (`/index.xml`, `/drivers/index.xml`) use stable UUID GUIDs and catalog creation dates. Empty about/taxonomy feeds remain valid at their existing URLs.
- `/tags/` and `/categories/` redirect to `/drivers/`; `/sitemap.xml` inventories all canonical pages and every UUID.
- `www.loldrivers.io`, root path, canonical URLs, robots, favicons, social metadata, existing sample downloads, and shared sponsor placements.
- Production uses `PUBLIC_SITE_MODE=production` and `PUBLIC_ENABLE_ANALYTICS=true`; review builds retain the notice/noindex and disabled analytics. QA intercepts Google traffic.

## Preview and release boundaries

`Astro Website Preview` still creates downloadable review artifacts, not hosted per-PR URLs. It has no production permissions. A hosting connection is only needed for optional hosted previews, not the production cutover.

Binary-dependent signature generation, repository-generated content writers, and blocklist metrics remain separate maintenance concerns below. They no longer produce, gate, or deploy the website artifact. Their repair and wholesale deletion of old Hugo source are deferred; this cutover does not claim to validate or repair detection signatures.

## Post-merge acceptance and rollback

1. Confirm the main `Deploy Site` build and deploy both succeed. Check `/source-revision.txt` against that run's source SHA.
2. Smoke-test the public homepage, a UUID page, both API downloads, sitemap/RSS, and HTTPS/custom-domain redirects. Check the absence of the review notice/noindex and presence of the existing GA property. Confirm GA receipt when account access is available.
3. Before merge, only artifact/PR validation is possible; production publication and real GA receipt are separate post-merge gates.
4. For an Astro regression, revert the offending change on main and let the workflow rebuild/publish; retain successful Pages artifacts for 30 days. For immediate rollback to Hugo, revert the cutover commit and run the restored generation/deployment workflow, accounting for its known maintenance issues below. Do not rerun historical tag-release deployment jobs, which could overwrite the live site.

## Existing build issues to resolve independently

| Location | Finding | Required repair |
| --- | --- | --- |
| `generate-site.yml`, `release.yml`, `bin/gen-files.py` | Binary-dependent generation does not request LFS hydration. During the September 14 audit, 265 committed ClamAV rows matched the hash and byte length of committed LFS pointer text rather than the binary. | Hydrate LFS before binary-dependent generation; reject pointer inputs; regenerate and verify the affected signatures. Keep ordinary website builds independent of driver binary downloads. |
| `deploy.yml` | Previously deployed after any completed generator run. | Resolved: same-revision generation/build/tests and gated artifact publication in one workflow. |
| `release.yml` | Previously rebuilt/deployed Hugo with untransferred generated output. | Resolved: remove website generation/deployment from tag releases; packaging depends on validation. |
| `generate-site.yml`, `generate-counter.yml` | Competing main-branch writers, unrestricted `git add .`, and empty-commit behavior. | Serialize updates, restrict paths, skip empty diffs, and generate website-only assets during the build. |
| `hvcicheck.yml` | Push trigger names `master`; downloaded script URL is a Gist HTML page. | Correct trigger intent; vendor the script or use a reviewed immutable raw revision. |
| `bin/site.py` metrics | Cached blocklist XML is reused while the displayed generation date changes; blocklist percentages use a different denominator than the current card text. | Track source snapshot date/digest separately; display matchable and unknown denominators. Per-sample blocklist filters require exported verdicts, not inference from HVCI. |

Remaining maintenance repairs require their own data-level validation; they are not evidence that detection artifacts are correct. Production is explicitly decoupled from these jobs by the same-revision website-only exporter.
