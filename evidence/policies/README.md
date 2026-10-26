# Historical policy evidence — context only

The two `.xml.context-only` files preserve the original policy bytes and authorship.
They are research inputs, excluded from detection generation, public API selectors,
and the site's public root. Do not rename them to active `.xml` policies or deploy
them. Their names are not generator ownership declarations.

- `LOLDrivers-legacy-DenyPolicy.xml.context-only`: formerly
  `detections/wdac/DenyPolicy.xml`, contributed by Florian Stosse and HotCakeX
  (see repository history and README). FilePublisher denies have minimum-only
  version ranges, allowing denial of later fixed versions. No affected-version
  upper bounds were invented. The active artifact now uses only catalog
  Authenticode hashes.
- `Microsoft-SiPolicy_Enforced.xml.context-only`: formerly
  `loldrivers.io/SiPolicy_Enforced.xml`, a downloaded Microsoft blocklist snapshot.
  It has third-party publisher/CA rules and remains third-party historical
  evidence, not a LOLDrivers-generated policy or a verified current blocklist.

Neither archive is a blanket waiver for active detections. The safety gate checks
all current detection files, including files outside the ownership manifest.
