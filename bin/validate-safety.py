#!/usr/bin/env python3
"""Regenerate in isolation; check both regenerated and committed public selectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from api_exports import export_api_files
from detection_generation import MANIFEST, REPO, owned_paths
from generated_safety import OutputValidator
from indicator_safety import Finding, SafetyError, load_catalog
from sample_evidence import check_samples


def source_snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((root / "yaml").glob("*.y*ml"))}


def check(root, report_path=None):
    root = Path(root).resolve()
    before = source_snapshot(root)
    records = load_catalog(root / "yaml")
    report = check_samples(records, root / "drivers")
    if report_path:
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(json.dumps(report, indent=2) + "\n")
    findings = []
    validator = OutputValidator(records)
    with tempfile.TemporaryDirectory(prefix="loldrivers-safety-") as temporary:
        isolated = Path(temporary)
        subprocess.run([sys.executable, str(root / "bin/gen-files.py"), "--catalog", str(root / "yaml"),
                        "--drivers", str(root / "drivers"), "--output", str(isolated)], check=True)
        expected_paths = owned_paths(isolated)
        actual_paths = owned_paths(root)
        for stale in sorted(actual_paths - expected_paths):
            findings.append(Finding(str(root / stale), "$", stale, "stale-rule", "Regenerate owned outputs after source removal, rename or exclusion."))
        for relative in sorted(expected_paths):
            expected, actual = isolated / relative, root / relative
            try:
                validator.validate(expected)
            except SafetyError as exc:
                findings.extend(exc.findings)
            except Exception as exc:
                findings.append(Finding(str(expected), "$", "<generated output>", "backend-parse", str(exc)))
            if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
                findings.append(Finding(str(actual), "$", "missing/different output", "regeneration", "Run python bin/gen-files.py. Do not retain stale selectors or hand-edit generated files."))
        if actual_paths != expected_paths:
            findings.append(Finding(str(root / MANIFEST), "files", "ownership differs", "manifest", "Regenerate; preserve manual rules outside the explicit ownership manifest."))
        # Also inspect files absent from the manifest: a stale renamed or manual
        # rule cannot bypass validation by losing its ownership entry.
        for path in sorted((root / "detections").rglob("*")):
            if path.is_file() and path.suffix.lower() in {".xml", ".yar", ".yml", ".yaml", ".hdb", ".all", ".md5", ".sha1", ".sha256", ".imphash"}:
                try:
                    validator.validate(path)
                except SafetyError as exc:
                    findings.extend(exc.findings)
                except Exception as exc:
                    findings.append(Finding(str(path), "$", "<committed output>", "backend-parse", str(exc)))
        # The public legacy/canonical copy must be from exactly this revision.
        api = isolated / "public/api"
        export_api_files(root / "yaml", api)
        copies = [root / "loldrivers.io/content/api"]
        if (root / "website/public/api").exists():
            copies.append(root / "website/public/api")
        for directory in copies:
            for name in ("drivers.json", "drivers.csv"):
                path = directory / name
                if not path.is_file() or path.read_bytes() != (api / name).read_bytes():
                    findings.append(Finding(str(path), "$", "public/canonical mismatch", "public-copy", "Run python bin/export-api.py --output " + str(directory)))
            table = directory.parent / "drivers_table.csv"
            if not table.is_file() or table.read_bytes() != (api.parent / "drivers_table.csv").read_bytes():
                findings.append(Finding(str(table), "$", "public table mismatch", "public-copy", "Regenerate the public API and its adjacent driver table."))
        # A historically downloaded policy must not remain a public active feed.
        legacy_policy = root / "loldrivers.io/SiPolicy_Enforced.xml"
        if legacy_policy.exists():
            findings.append(Finding(str(legacy_policy), "$", "historical third-party policy", "public-policy", "Keep unvalidated historical policy evidence in evidence/policies with a context-only extension."))
    if source_snapshot(root) != before:
        findings.append(Finding(str(root / "yaml"), "$", "source changed", "source-mutation", "Generators must never rewrite source YAML."))
    if findings:
        raise SafetyError(findings)
    print(f"PASS: {len(records)} records; {len(expected_paths)} regenerated artifacts; {validator.count} final artifact parses; public copies agree; source YAML unchanged.")
    print(f"Static evidence: {report['hydrated_binaries_checked']} binaries and {report['lfs_pointers_checked']} LFS pointers checked; {len(report['review_findings'])} unlinked binaries excluded for review.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO)
    parser.add_argument("--report", type=Path, help="Write evidence-only review findings as JSON")
    args = parser.parse_args()
    try:
        check(args.repo_root, args.report)
    except SafetyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"{args.repo_root}: $='<validation>' [safety-backend]: {exc}. Install bin/requirements-safety.txt and resolve parser/generator failures.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
