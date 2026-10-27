# Indicator and generated-policy safety

Run the complete gate before merging catalog, generator, dependency, workflow or
detection changes. It fails on unsafe active indicators, parser errors, stale
generated files and public copies from a different catalog revision.

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install -r bin/requirements-safety.txt
# Hydrate immutable Git LFS objects before the real-sample engine controls.
git lfs pull
.venv/bin/python bin/validate.py
.venv/bin/python -m unittest discover -s bin/tests -p 'test_*.py'
.venv/bin/python bin/validate-safety.py --report .context/indicator-review.json
.venv/bin/python bin/yara-generator/validate-malicious-rules.py \
  --skip-generate --all-categories --output-dir .context/yara-validation
npm --prefix website ci
PUBLIC_SITE_MODE=preview PUBLIC_ENABLE_ANALYTICS=false npm --prefix website run build
npm --prefix website run verify:build
```

The checks and generators operate offline after dependency installation and
checkout. They read driver bytes statically and never execute a driver, compile
or install a Windows policy, deploy anything, or update branch protection.
`bin/requirements-safety.txt` pins direct and transitive dependencies, including
pySigma, plyara, yara-python, PyYAML, jsonschema and cryptography. No live external
feed, public suffix list download, current date or certificate trust service is
an input to detection generation.

## Source and export contract

The source schema is `bin/spec/drivers.spec.json`; `bin/indicator_safety.py` adds
semantic checks that JSON Schema alone cannot express. No `AGENTS.md` was present
in this workspace or its ancestor directories at implementation time.

| Actual source field | Normalization and output semantics |
| --- | --- |
| `Id`, `Category` | Stable record identity and malicious/vulnerable grouping. Per-driver output paths use the full UUID to avoid collisions and survive display-name changes. |
| `Author`, `Created`, `MitreID`, `CVE`, legacy `CVEs`, `Verified` | Attribution, dates, vulnerability/ATT&CK references and verification annotations; retained as catalog metadata, never standalone match selectors. |
| `Tags[0]` | Historical driver display identity. Only a driver-specific `.sys`, `.dll`, `.exe` or `.dat` basename becomes an `ImageLoaded\|endswith` Sigma **hunting** selector, with a leading directory separator. Generic names such as `driver.sys`, `monitor.sys`, `disk.sys`, `setup.exe`, and ubiquitous Windows components are omitted from name rules. |
| Other `Tags` | Product/display labels; preserved in JSON `ResearchEvidence.Tags`. They are not automatically promoted to selectors. Public `Tags` contains only validated hunting identities. |
| `DetectionNames` | Optional reviewed filename patterns. Require `Reviewed: true`, `Reason`, and nonempty `PositiveExamples`/`NegativeExamples`; every example is checked after Windows basename/case normalization. Only specific stems with at least four literal letters are permitted. Not a publisher/version rule. |
| `KnownVulnerableSamples[].MD5`, `SHA1`, `SHA256` | Exact **raw file** digests, lowercased without trimming or guessing. Feed raw hash lists, Sigma hash rules, Sysmon event filters, YARA, and JSON/CSV. ClamAV uses source-listed SHA256 values plus the actual file/LFS-object size. Lacework uses malicious raw SHA256 equality predicates from this local revision. |
| `Authentihash.{MD5,SHA1,SHA256}` | **Authenticode image** digests; distinct from raw file digests. Feed separately named Authenticode lists, JSON/CSV, and WDAC SHA1/SHA256 denies. WDAC does not support MD5 here. |
| `AuthentihashMD5`, `AuthentihashSHA1`, `AuthentihashSHA256` | Legacy Authenticode aliases, normalized into `Authentihash`. Conflicting aliases fail; they never become raw file digests. |
| `PageHash.{MD5,SHA1,SHA256}`, `PageHashMD5/SHA1/SHA256` | Explicitly typed page evidence, checked if present, retained in research only. No current catalog records supply page hashes. The active WDAC exporter does not guess page-hash semantics or derive them from other digests. |
| `Imphash`, `RichPEHeaderHash.{MD5,SHA1,SHA256}`, legacy `RichPEHeaderMD5/SHA1/SHA256` | Format-checked research evidence. Import/Rich hashes can be shared by unrelated files and are excluded from standalone rules and flat blocking feeds. Legacy generator-owned `.imphash` feeds were removed. |
| `Filename`, `OriginalFilename`, `InternalName`, `FileVersion`, `ProductVersion`, `Company`, `CompanyName`, `Description`, `FileDescription`, `Product`, `ProductName` | PE/sample evidence under each exported sample's `ResearchEvidence`. Never an automatic blocking selector or fallback when a hash is invalid/missing. Human website pages can still show the original catalog evidence. |
| `Publisher`, `Signature`, `Signatures[].Certificates`, `Signatures[].Signer` | Signing evidence only, moved out of active exported sample fields. No signing identity generates a WDAC deny. A signer, including an exact certificate, may cover unrelated products. |
| Certificate `TBS.{MD5,SHA1,SHA256,SHA384,SHA512}`, `Thumbprint`/`Fingerprint` | Distinct TBS and whole-certificate digest namespaces. Scalar thumbprints mean SHA1; mappings name their algorithm explicitly. Validate lengths, hex and placeholders. |
| Certificate `DER`/`Base64`/`PEM`, `Subject`, `Issuer`, `ValidFrom`, `ValidTo` | Embedded certificates, when supplied, are parsed with cryptography. Check canonical subject/issuer, DER fingerprints, TBS digests and validity consistency. YAML binary DER and wrapped base64 are supported. Expired historical certificates are retained. |
| `Commands`, `Resources`, `Detection[].{type,value}`, acknowledgements, dates, imports, exports, PDB paths, sections, machine metadata, other sample fields | Research/documentation. `Detection` entries are descriptions/links, not executable selectors; the public JSON places them in `ResearchEvidence.Detection`. All other sample metadata is nested in sample `ResearchEvidence`. Common imports such as `ntoskrnl.exe` never supply attribution. |
| `LoadsDespiteHVCI` | Selects subsets of the same exact hashes. It cannot replace an absent digest. |

Every declared supported digest must be the exact hexadecimal length for its
algorithm. Empty/null/placeholder, all-zero, repeated-character and common test
digests fail. Omit unavailable optional hashes. An active sample needs a raw
file or Authenticode digest; names, import/page hashes and certificates alone do
not satisfy that requirement. Authenticode-only historical records remain active.

Filename checks examine the basename a consumer would extract, after quote,
slash, case and trailing-dot normalization. `*`, `*.*`, `*.sys`, `*.dll`, `*.exe`,
wildcard-only stems and their directory-qualified variants fail. Variable and
unresolved-template expansion is rejected before directory removal. Specific
reviewed wildcards, for example `AcmeDriver*.sys`, have positive and negative
coverage controls. Exact names remain hunting leads: a fixed release may use the
same driver name. Blocking artifacts use hashes rather than those hunting names.

Legacy `drivers_top_5_products.csv`, `drivers_top_5_publishers.csv` and
`projects.csv` are presentation downloads, not catalog indicator feeds; no rule
generator consumes them. Product/publisher aggregate labels cannot be used as
standalone blocking identities.

There are no service, registry, event-ID-only, port-only or network selectors in
the supported generators. URLs in `Resources` and `Detection` are citations,
not network indicators. Unsupported final selector fields fail closed. Adding a
network backend requires pinned offline PSL handling, shared-infrastructure
review and hostname-boundary controls before that backend is enabled.

## Research exclusions and API migration

Use `DetectionScope: context-only` and a nonempty `ContextReason` on a record or
sample when attribution is insufficient. A record whose samples are all
context-only must itself be context-only. Alternatively put historical material
directly under `ResearchEvidence`, outside detection-bearing fields. A malformed
hash in a recognized digest field still fails; preserve an uninterpretable old
value as research text rather than pretending it is a valid indicator.

Exclusions are applied before **every** generator. They remove raw/Authenti hash
feeds, HVCI subsets, Sigma, Sysmon, YARA, WDAC, Lacework and ClamAV entries. Public
JSON retains excluded samples in `ResearchEvidence.ExcludedSamples` and emits no
active sample/name for a wholly excluded record. Research objects are explicitly
`DetectionScope: context-only`. `Verified` and `Category` retain their source
meaning: a legitimately signed vulnerable driver is still vulnerable, not harmless.

Public JSON `KnownVulnerableSamples` now contains only raw hashes, typed
`Authentihash`, and a nested research section. This is an intentional API
migration: consumers must not recursively flatten `ResearchEvidence` into
indicators. CSV keeps its legacy hash columns, leaves standalone publisher/PE
metadata columns empty, and provides a compact context-only reference to the
JSON evidence. Its `IndicatorSemantics` column explicitly distinguishes hash
blocking from filename hunting. CSV rows do not contain large unscoped certificate blobs.
`bin/export-api.py` and the legacy `bin/site.py` use the same projection.

The website's separate `/data/drivers/<UUID>.json` download is entirely research
evidence: `DetectionScope: context-only`, with the original record under
`ResearchEvidence`. The metadata viewer requires and preserves that scope. The
artifact verifier compares these records directly with source YAML, and compares
production indicator APIs with the validated canonical projection. The required
`indicator-safety` job builds and verifies these actual JSON artifacts too.

## Final rule checks and ownership

`bin/validate-safety.py` runs the real `bin/gen-files.py` in a fresh temporary
directory and regenerates the public API. It parses both these outputs and all
existing detection files, including files absent from the ownership manifest.
Committed generated bytes must agree with the regenerated revision. The legacy
public JSON/CSV/table and any locally generated Astro public API must agree.
Source YAML bytes are fingerprinted before/after and must remain unchanged.

- Sigma uses pySigma's condition parser plus checks for nonempty supported
  selectors, exact hashes, scoped names, and path boundaries. Only the current
  single-selection contract is supported; extending conditions requires extending
  validation first.
- YARA uses plyara and the native libyara compiler. Every rule requires a complete
  raw-file hash. Renamed-driver exclusions remain joined with **AND**. The five
  established filenames are retained as compatibility aliases; the former
  VersionInfo/string heuristics no longer independently match unrelated files,
  embedded driver fragments or memory images. Authenticode-only samples have no
  raw-file YARA rule; WDAC and Authenticode feeds cover them instead.
- Sysmon XML is parsed and every emitted event filter must contain exact raw
  file hashes. Empty event selectors and import-hash-only selectors fail.
- WDAC XML is parsed with exact digest lengths/namespaces, unique IDs, valid
  file/signer references, and no unresolved selectors. Generated denies are
  **Authenticode SHA1/SHA256 only** and are referenced by the kernel and user-mode
  scenarios. The baseline `Allow FileName="*"` is deliberate deny-list scaffolding,
  not a blocking indicator. A non-hash signer rule in an independently authored
  policy must retain exact publisher **AND** exact file/product **AND** bounded
  four-part versions through `FileAttribRef`. Every referenced alternative is
  checked. Publisher/CA-only, wildcard/empty publisher, missing upper bound,
  reversed ranges, full-future version sentinels, unknown combinations and dangling
  references fail. No validator rewrites a scope or changes an AND to an OR.
  Missing baseline allows fail too: a deny-list must not implicitly deny unrelated
  files through WDAC's default-deny behavior. Version/hash semantics follow
  [Microsoft's rule documentation](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create).
- Hash feeds, ClamAV `SHA256:size:name` and Lacework's exact-equality filter have
  explicit format parsers and active-catalog membership checks. They never fall
  back from a bad hash to a name or publisher.
  ClamAV's hash-length interpretation is described in its
  [official hash-signature format](https://docs.clamav.net/manual/Signatures/HashSignatures.html).

`detections/.generated-files.json` establishes file ownership. Reconciliation
removes only previously owned artifacts that the current generator no longer
emits. Unowned files are preserved and still validated; a generator refuses to
overwrite an existing unowned path. Symlink escapes are rejected. Initial
ownership covers the exact hash/Sigma/Sysmon/ClamAV/Lacework output paths from the
previous scripts and the five documented YARA sets. Previously the per-driver
Sigma script deleted the whole output directory, and YARA preserved disappeared
rules indefinitely; neither behavior remains.

The independently contributed legacy WDAC policy and downloaded Microsoft
snapshot are preserved byte-for-byte with context-only extensions under
`evidence/policies/`, retaining authorship. Minimum-only publisher denies were
not assigned invented affected-version upper bounds. The active WDAC artifact is
newly generated from catalog Authenticode evidence. Third-party policy downloads
for optional site metrics now stay under `.context/`, outside public roots.
The summary parsers no longer flatten signer-linked `FileAttrib` constraints
into standalone filename matches; those constrained signer rules are counted
but conservatively left unevaluated.

To refresh owned artifacts and the committed public copy:

```sh
.venv/bin/python bin/gen-files.py
.venv/bin/python bin/export-api.py --output loldrivers.io/content/api
.venv/bin/python bin/validate-safety.py
```

`--output` on `gen-files.py` selects an isolated output root. The standalone
YARA and Lacework entry points also use the shared validated local catalog,
without remote `main` fetches or stale YARA merges.

## Evidence, controls and practical limits

The gate cross-checks every declared raw digest that can be associated with a
hydrated binary. Contradictory sample hashes fail, even when another digest
matches. Git LFS pointers permit SHA256/size checks without inventing SHA1/MD5
values; full engine controls require hydrated objects. Binaries without a raw
catalog link are reported for attribution review and cannot supply new generated
raw-hash indicators; independently cataloged Authenticode rules retain their scope.
`--report` writes source/field/value/rule/remediation for those
research findings. Unsafe active findings always exit nonzero.

Controls include corrupt hashes/certificates, placeholders, missing metadata,
wildcard variants, normalization, scope loss, exclusion across every generator,
stale removal, manual ownership, public-copy disagreement, deterministic offline
generation and immutable source formatting. Native YARA positive/negative scans
include synthetic affected/fixed-version/Windows-file controls and real WDTKernel
versus CPUID samples sharing the same Microsoft WHCP leaf signer; a targeted WDT
rule must not expand to CPUID. Both products remain cataloged as vulnerable.

Certificate consistency is **not** chain trust, revocation status, signature
verification against the PE, or proof of sample provenance. Legacy records have
subject/TBS metadata but no embedded DER, so their actual certificates cannot be
reconstructed or verified from that metadata. New metadata extraction retains
canonical subject/issuer, DER and certificate fingerprints without destructively
replacing characters in distinguished names. No historical identities were guessed.

libyara match/compile and pySigma parse checks are exercised. Exact Windows
WDAC/ConfigCI compilation/enforcement, Sysmon installation/event evaluation,
ClamAV database loading and Lacework's hosted query engine are **not** exercised
by this macOS/Linux gate. Their XML/format/reference checks are conservative
offline contracts, not claims of native Windows or hosted-engine certification.
Version-bound checks verify structure, inclusive bounds and references; the
generated WDAC policy uses exact image hashes instead of inferring version ranges.

## Required merge status

Configure branch rules/rulesets on `main` to require the **`indicator-safety`**
status from the **Indicator safety** workflow for the current revision. That job
has no path filter and runs on every PR and merge-queue group, with source checks,
adversarial controls, isolated regeneration and native scans of all five YARA
sets. Existing YAML/website checks may remain required separately. The older
path-filtered malicious-YARA workflow is supplementary, not a replacement.

Workflow files alone do **not** enforce branch protection. Requiring the check
is a separate repository administration operation; verify the live branch rules
after installing or migrating the workflow.
