# LOLDrivers YARA generation and validation

The five established YARA filenames now contain exact-file hash rules. PE
VersionInfo strings, publisher names, imports and filenames cannot independently
attribute a vulnerable driver or distinguish unrelated products from one signer.
Hash requirements remain mandatory in renamed-driver rules.

The `strict` files retain their names for compatibility and use the same complete
file hash checks. Rules do not scan embedded fragments or memory images. Samples
with only Authenticode hashes are covered by WDAC/Authenti feeds, rather than by
substituting an unrelated raw hash or a broader YARA selector.

Install the pinned backends and generate from this revision's local YAML:

```sh
python -m pip install -r bin/requirements-safety.txt
python bin/yara-generator/yara-generator.py -o /tmp/loldrivers-yara
python bin/yara-generator/validate-malicious-rules.py --skip-generate \
  --all-categories --output-dir .context/yara-validation
```

`-y` selects input catalog directories; `-o` selects the YARA output folder.
`-d` is retained for command-line compatibility; generation does not need binaries.
`-f` writes an optional summary. Existing generator-owned files are reconciled,
not merged with stale rules; separate manual files are preserved. An unowned
existing target file is refused. Full repository regeneration should use
`python bin/gen-files.py`, which maintains the ownership manifest.

Validation uses pinned yara-python/libyara, scans sample bytes statically, and
exits nonzero for missing or unexpected matches, absent positive coverage, or
unhydrated LFS objects. No driver is executed. By default it checks the two
malicious sets; `--all-categories` checks all five. JSON details are written to
`summary.json`; `--json-output` also prints them.

See [the complete safety contract](../../docs/indicator-safety.md) for source
fields, exclusions, API migration, CI requirements and engine limitations.
