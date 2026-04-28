#!/usr/bin/env python3
"""Validate malicious YARA rules against samples in the LOLDrivers repository."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class ScanStats:
    rule_file: str
    rule_count: int
    hit_count: int
    unique_file_count: int
    hit_output: str
    err_output: str


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent

    parser = argparse.ArgumentParser(
        description="Generate and validate malicious-driver YARA rules."
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=repo_root,
        help="Path to LOLDrivers repository root.",
    )
    parser.add_argument(
        "--python-bin",
        default=sys.executable,
        help="Python interpreter used to execute yara-generator.py.",
    )
    parser.add_argument(
        "--yara-bin",
        default="yara",
        help="Path to yara executable.",
    )
    parser.add_argument(
        "--skip-generate",
        action="store_true",
        help="Validate existing committed rule files without regenerating them in place.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/tmp/yara-malicious-validation"),
        help="Directory for scan outputs and summary.",
    )
    parser.add_argument(
        "--list-limit",
        type=int,
        default=20,
        help="Max number of missing/extra items to print.",
    )
    parser.add_argument(
        "--json-output",
        "--json",
        dest="json_output",
        action="store_true",
        help="Print machine-readable JSON summary.",
    )

    return parser.parse_args()


def ensure_tool_exists(tool_name: str) -> None:
    if shutil.which(tool_name) is None:
        raise RuntimeError(f"Required tool not found in PATH: {tool_name}")


def load_intentionally_skipped_files(generator_script: Path) -> set[str]:
    """Read SKIP_DRIVERS from yara-generator.py without importing/running it."""
    code = generator_script.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(code, filename=str(generator_script))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SKIP_DRIVERS":
                    value = ast.literal_eval(node.value)
                    if isinstance(value, list):
                        return {
                            item.lower()
                            for item in value
                            if isinstance(item, str) and item.endswith(".bin")
                        }
    return set()


def count_rules(rule_path: Path) -> int:
    count = 0
    with rule_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("rule "):
                count += 1
    return count


def run_scan(yara_bin: str, rule_file: Path, drivers_dir: Path, output_prefix: Path) -> ScanStats:
    hit_path = output_prefix.with_suffix(".hits.txt")
    err_path = output_prefix.with_suffix(".err.txt")
    cmd = [yara_bin, "-r", str(rule_file), str(drivers_dir)]
    with hit_path.open("w", encoding="utf-8") as out, err_path.open(
        "w", encoding="utf-8"
    ) as err:
        proc = subprocess.run(cmd, stdout=out, stderr=err, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"yara failed for {rule_file} (exit {proc.returncode}). See {err_path}"
        )

    hit_count = 0
    unique = set()
    with hit_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            hit_count += 1
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                unique.add(Path(parts[1]).name.lower())

    return ScanStats(
        rule_file=str(rule_file),
        rule_count=count_rules(rule_file),
        hit_count=hit_count,
        unique_file_count=len(unique),
        hit_output=str(hit_path),
        err_output=str(err_path),
    )


def load_expected_malicious_filenames(
    yaml_dir: Path, repo_driver_filenames: set[str]
) -> tuple[set[str], int, int]:
    expected = set()
    malicious_samples_total = 0
    unresolved_sample_count = 0
    for path in sorted(list(yaml_dir.glob("*.yaml")) + list(yaml_dir.glob("*.yml"))):
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            continue
        if data.get("Category") != "malicious":
            continue
        samples = data.get("KnownVulnerableSamples") or []
        if not isinstance(samples, list):
            continue
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            malicious_samples_total += 1
            candidates = []
            for key in ("MD5", "SHA1", "SHA256"):
                value = sample.get(key)
                if isinstance(value, str) and value:
                    candidates.append(f"{value.lower()}.bin")

            matched = False
            for candidate in candidates:
                if candidate in repo_driver_filenames:
                    expected.add(candidate)
                    matched = True

            if not matched:
                unresolved_sample_count += 1

    return expected, malicious_samples_total, unresolved_sample_count


def load_observed_filenames(path: Path) -> set[str]:
    observed = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                observed.add(Path(parts[1]).name.lower())
    return observed


def parse_bin_list_from_line(line: str) -> list[str]:
    marker = "for ["
    marker_pos = line.find(marker)
    if marker_pos == -1:
        return []
    start = line.find("[", marker_pos)
    end = line.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        values = ast.literal_eval(line[start : end + 1])
    except (ValueError, SyntaxError):
        return []
    if not isinstance(values, list):
        return []
    return [item.lower() for item in values if isinstance(item, str) and item.endswith(".bin")]


def parse_generator_log_reasons(log_path: Path) -> dict[str, set[str]]:
    reasons = {
        "no_pe_fileinfo": set(),
        "insufficient_versioninfo_strings": set(),
        "no_yaml_for_group_representative": set(),
    }
    if not log_path.exists():
        return reasons

    no_fileinfo_re = re.compile(
        r"Couldn't extract any PE header infos for file .*?/drivers/([^/\s]+\.bin)\b"
    )
    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = no_fileinfo_re.search(line)
            if m:
                reasons["no_pe_fileinfo"].add(m.group(1).lower())
                continue
            if "Number of extracted PE version info values is empty or not big enough" in line:
                reasons["insufficient_versioninfo_strings"].update(parse_bin_list_from_line(line))
                continue
            if "No YAML info found for" in line:
                reasons["no_yaml_for_group_representative"].update(parse_bin_list_from_line(line))
    return reasons


def run_generator(
    args: argparse.Namespace,
    repo_root: Path,
    output_dir: Path,
    rules_output_dir: Path,
) -> None:
    script = repo_root / "bin" / "yara-generator" / "yara-generator.py"
    drivers_dir = repo_root / "drivers"
    yaml_dir = repo_root / "yaml"
    rules_other = rules_output_dir / "other"
    rules_output_dir.mkdir(parents=True, exist_ok=True)
    rules_other.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "yara-generator-validation.log"
    cmd = [
        args.python_bin,
        str(script),
        "-d",
        str(drivers_dir),
        "-y",
        str(yaml_dir),
        "-o",
        str(rules_output_dir),
        "-f",
        str(log_path),
    ]
    proc = subprocess.run(cmd, check=False, cwd=str(repo_root))
    if proc.returncode != 0:
        raise RuntimeError(f"Rule generation failed (exit {proc.returncode})")


def main() -> int:
    args = parse_args()
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "yara-generator-validation.log"

    ensure_tool_exists(args.yara_bin)

    drivers_dir = repo_root / "drivers"
    yaml_dir = repo_root / "yaml"
    generator_script = repo_root / "bin" / "yara-generator" / "yara-generator.py"
    rules_dir = repo_root / "detections" / "yara"
    mal_rule = rules_dir / "yara-rules_mal_drivers.yar"
    mal_strict_rule = rules_dir / "other" / "yara-rules_mal_drivers_strict.yar"

    if args.skip_generate:
        if not log_path.exists():
            temp_rules_dir = output_dir / "generated-rules"
            run_generator(args, repo_root, output_dir, temp_rules_dir)
    else:
        run_generator(args, repo_root, output_dir, rules_dir)

    for required in [drivers_dir, yaml_dir, generator_script, mal_rule, mal_strict_rule]:
        if not required.exists():
            raise RuntimeError(f"Missing required path: {required}")

    normal_stats = run_scan(
        args.yara_bin, mal_rule, drivers_dir, output_dir / "malicious"
    )
    strict_stats = run_scan(
        args.yara_bin, mal_strict_rule, drivers_dir, output_dir / "malicious_strict"
    )

    repo_driver_filenames = {
        p.name.lower() for p in drivers_dir.rglob("*.bin") if p.is_file()
    }
    expected, malicious_samples_total, unresolved_sample_count = (
        load_expected_malicious_filenames(yaml_dir, repo_driver_filenames)
    )
    intentionally_skipped_files = load_intentionally_skipped_files(generator_script)
    intentionally_skipped_expected = sorted(expected & intentionally_skipped_files)
    expected_for_detection = expected - intentionally_skipped_files
    observed_normal = load_observed_filenames(Path(normal_stats.hit_output))
    observed_strict = load_observed_filenames(Path(strict_stats.hit_output))
    observed_union = observed_normal | observed_strict

    missing = sorted(expected_for_detection - observed_union)
    extra = sorted(observed_union - expected_for_detection)
    total_driver_files = len([p for p in drivers_dir.rglob("*.bin") if p.is_file()])

    reason_sets = parse_generator_log_reasons(log_path)
    mal_rule_text = mal_rule.read_text(encoding="utf-8", errors="ignore")
    mal_strict_rule_text = mal_strict_rule.read_text(encoding="utf-8", errors="ignore")
    vuln_rule_path = rules_dir / "other" / "yara-rules_vuln_drivers.yar"
    vuln_rule_text = (
        vuln_rule_path.read_text(encoding="utf-8", errors="ignore")
        if vuln_rule_path.exists()
        else ""
    )

    missing_reasons = {
        "no_pe_fileinfo": [],
        "insufficient_versioninfo_strings": [],
        "no_yaml_for_group_representative": [],
        "grouped_into_vulnerable_rule": [],
        "unknown": [],
    }
    for filename in missing:
        if filename in reason_sets["no_pe_fileinfo"]:
            missing_reasons["no_pe_fileinfo"].append(filename)
            continue
        if filename in reason_sets["insufficient_versioninfo_strings"]:
            missing_reasons["insufficient_versioninfo_strings"].append(filename)
            continue
        if filename in reason_sets["no_yaml_for_group_representative"]:
            missing_reasons["no_yaml_for_group_representative"].append(filename)
            continue

        file_path = drivers_dir / filename
        if file_path.exists():
            sha256 = hashlib.sha256(file_path.read_bytes()).hexdigest()
            in_malicious_rules = sha256 in mal_rule_text or sha256 in mal_strict_rule_text
            in_vuln_rules = sha256 in vuln_rule_text
            if in_vuln_rules and not in_malicious_rules:
                missing_reasons["grouped_into_vulnerable_rule"].append(filename)
                continue

        missing_reasons["unknown"].append(filename)

    summary = {
        "repo_root": str(repo_root),
        "total_driver_files": total_driver_files,
        "generator_log_path": str(log_path),
        "scan_stats": {
            "malicious": normal_stats.__dict__,
            "malicious_strict": strict_stats.__dict__,
        },
        "malicious_samples_in_yaml": malicious_samples_total,
        "malicious_samples_resolvable_to_repo_files": len(expected),
        "intentionally_skipped_samples": len(intentionally_skipped_expected),
        "intentionally_skipped_examples": intentionally_skipped_expected[: args.list_limit],
        "malicious_samples_expected_for_detection": len(expected_for_detection),
        "malicious_samples_without_repo_file": unresolved_sample_count,
        "observed_malicious_samples_union": len(observed_union),
        "missing_expected_matches": len(missing),
        "non_malicious_extra_hits": len(extra),
        "missing_expected_examples": missing[: args.list_limit],
        "extra_hit_examples": extra[: args.list_limit],
        "missing_reason_counts": {
            key: len(values) for key, values in missing_reasons.items()
        },
        "missing_reason_examples": {
            key: values[: args.list_limit] for key, values in missing_reasons.items()
        },
    }
    exit_code = 2 if summary["missing_reason_counts"]["unknown"] > 0 else 0
    summary["validation_status"] = "failed_unknown_missing_matches" if exit_code else "ok"
    summary["validation_exit_code"] = exit_code

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.json_output:
        print(json.dumps(summary, indent=2))
        return exit_code

    print("Malicious Rule Validation")
    print(f"repo_root: {repo_root}")
    print(f"total driver files: {total_driver_files}")
    print("")
    print("Rule files")
    print(
        f"- malicious        rules={normal_stats.rule_count} "
        f"hits={normal_stats.hit_count} unique_files={normal_stats.unique_file_count}"
    )
    print(
        f"- malicious_strict rules={strict_stats.rule_count} "
        f"hits={strict_stats.hit_count} unique_files={strict_stats.unique_file_count}"
    )
    print("")
    print("YAML comparison (union of both malicious scans)")
    print(f"- malicious samples in YAML          : {malicious_samples_total}")
    print(f"- samples resolvable to repo files   : {len(expected)}")
    print(
        f"- intentionally skipped samples      : {len(intentionally_skipped_expected)}"
    )
    print(
        f"- expected for detection             : {len(expected_for_detection)}"
    )
    print(f"- samples without repo file mapping  : {unresolved_sample_count}")
    print(f"- matched malicious samples (union)  : {len(observed_union)}")
    print(f"- missing expected matches  : {len(missing)}")
    print(f"- non-malicious extra hits  : {len(extra)}")
    print("")
    print("Missing reason breakdown")
    print(
        f"- no PE FileInfo                     : {len(missing_reasons['no_pe_fileinfo'])}"
    )
    print(
        f"- insufficient VersionInfo strings   : {len(missing_reasons['insufficient_versioninfo_strings'])}"
    )
    print(
        f"- no YAML for grouped representative : {len(missing_reasons['no_yaml_for_group_representative'])}"
    )
    print(
        f"- grouped into vulnerable rule       : {len(missing_reasons['grouped_into_vulnerable_rule'])}"
    )
    print(f"- unknown                            : {len(missing_reasons['unknown'])}")
    print("")
    print(f"summary file: {summary_path}")
    print(f"malicious hits: {normal_stats.hit_output}")
    print(f"strict hits: {strict_stats.hit_output}")

    if missing:
        print("")
        print(f"Missing expected examples (first {args.list_limit}):")
        for item in missing[: args.list_limit]:
            print(item)
    if extra:
        print("")
        print(f"Extra hit examples (first {args.list_limit}):")
        for item in extra[: args.list_limit]:
            print(item)
    if exit_code:
        print("")
        print("Validation failed: unexplained missing expected matches remain.")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
