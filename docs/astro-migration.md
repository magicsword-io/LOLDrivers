# Astro redesign and production cutover

The review site in [`website/`](../website/README.md) implements the approved visual direction and content browsing. It builds independently alongside Hugo so the redesign can be reviewed before changing the live site.

## Accepted design requirements

- Charcoal surfaces and restrained LOLDrivers red accents; a warm white alternative with saved theme preference. Use amber for vulnerable categories, red for malicious categories, and text labels for both. Keep MagicSword's green identity.
- Original LOLDrivers light/dark logos in a shared header. Driver search, Detections, Tools, API, and About are primary navigation destinations.
- MagicSword banner on the homepage and **every driver**, preserving “Free for up to 100 endpoints,” the CTA, and existing UTM values. The driver banner names the current driver.
- Preserve GA4 property **G-33C5VXLWPQ**, enabled explicitly for production and disabled in review builds.
- Homepage shortcuts and resource cards for Detections & policies and Tools & integrations, with detailed destinations for each.
- Every source YAML entry and sample remains available. Show unknown/mixed HVCI evidence explicitly. Keep the full catalog JSON out of the browser bundle and large metadata out of initial driver-page payloads.

## Preview delivery in this PR

`website-preview.yml` builds the source branch, checks Astro/types, verifies every generated UUID route and banner, checks analytics behavior, runs Chromium tests, and uploads a static site artifact plus browser reports/screenshots. It uses read-only permissions and does not need repository push or deployment secrets.

Artifacts can be downloaded and served locally before merging. A hosted per-PR URL additionally requires a preview hosting project connected to the repository; that external setup has not been performed. Existing production deployment workflows are unchanged.

## Production cutover checklist

1. Review the Astro site using real catalog entries: vulnerable and malicious, verified and unverified, missing metadata, multiple samples, and the largest entry. Confirm both themes and sponsor placements.
2. Decide whether to keep the Astro source in `website/` or replace the legacy site directory. Keep a single authoritative YAML source and reuse the established Python exports for public API/detection contracts.
3. Wire data generation and Astro build into one validated artifact chain. Preserve `/drivers/<UUID>/`, `/about/`, `/search/`, `/api/drivers.json`, `/api/drivers.csv`, and any existing sitemap/RSS/download URLs found in the final route inventory. The preview API links deliberately point to the existing production exports.
4. Preserve the `www.loldrivers.io` custom domain, root base path, canonicals, robots, favicons, and social metadata. Add the production sitemap/feed policy. Remove the review notice/noindex metadata through explicit deployment configuration.
5. Enable the existing Google tag for production with `PUBLIC_ENABLE_ANALYTICS=true`. Review builds stay disabled. Confirm receipt in the existing GA4 property after deployment when account access is available.
6. Replace Hugo installation and its output path with pinned Node, strict `npm ci`, validation, `astro build`, and upload of `website/dist`. Keep publishing from main gated on successful checks. Use a shared production deployment concurrency group and retain rollback to the prior successful site artifact.
7. Keep repository-hosted generated detections current for existing consumers. Replace competing generated-content writers with one controlled update process. Only then retire generated Hugo pages, theme submodule, Sass/Go tooling, and outdated build instructions.

## Existing build issues to resolve independently

| Location | Finding | Required repair |
| --- | --- | --- |
| `generate-site.yml`, `release.yml`, `bin/gen-files.py` | Binary-dependent generation does not request LFS hydration. During the September 14 audit, 265 committed ClamAV rows matched the hash and byte length of committed LFS pointer text rather than the binary. | Hydrate LFS before binary-dependent generation; reject pointer inputs; regenerate and verify the affected signatures. Keep ordinary website builds independent of driver binary downloads. |
| `deploy.yml` | A `workflow_run: completed` trigger has no success gate and does not consume a revision-associated generation artifact. | Gate publication on successful generation/validation and deploy the artifact built from the intended source revision. |
| `release.yml` | Generation and site build use separate runners with no transfer of generated output. Release packaging also depends on site deployment. | Transfer artifacts explicitly or generate/build in one job; package the tagged release independently. |
| `generate-site.yml`, `generate-counter.yml` | Competing main-branch writers, unrestricted `git add .`, and empty-commit behavior. | Serialize updates, restrict paths, skip empty diffs, and generate website-only assets during the build. |
| `hvcicheck.yml` | Push trigger names `master`; downloaded script URL is a Gist HTML page. | Correct trigger intent; vendor the script or use a reviewed immutable raw revision. |
| `bin/site.py` metrics | Cached blocklist XML is reused while the displayed generation date changes; blocklist percentages use a different denominator than the current card text. | Track source snapshot date/digest separately; display matchable and unknown denominators. Per-sample blocklist filters require exported verdicts, not inference from HVCI. |

The preview does not regenerate detection files or fix these existing maintenance workflows. Those changes require their own data-level validation before the production cutover.
