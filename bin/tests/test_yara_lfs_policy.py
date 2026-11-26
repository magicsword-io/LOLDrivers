"""Partial Git LFS checkouts must not hide a bad native YARA match."""

import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_malicious_rules",
    ROOT / "bin/yara-generator/validate-malicious-rules.py",
)
RULES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RULES)


def summary(**overrides):
    base = {"missing": [], "unexpected": [], "unhydrated_lfs": [], "expected_matches": 0}
    base.update(overrides)
    return base


class YaraLfsPolicyTests(unittest.TestCase):
    def test_pointers_fail_closed_by_default(self):
        status, missing = RULES.validation_status(
            summary(unhydrated_lfs=["sample.bin"], expected_matches=1),
            True,
            False,
        )
        self.assertEqual(status, "failed")
        self.assertEqual(missing, [])

    def test_allow_unhydrated_accepts_pointers_when_hydrated_matches_exist(self):
        status, missing = RULES.validation_status(
            summary(unhydrated_lfs=["other.bin"], expected_matches=2),
            True,
            True,
        )
        self.assertEqual(status, "ok")
        self.assertEqual(missing, [])

    def test_allow_unhydrated_still_fails_unexpected_matches(self):
        status, _ = RULES.validation_status(
            summary(
                unhydrated_lfs=["other.bin"],
                expected_matches=1,
                unexpected=[{"file": "changed.bin", "rules": "malicious"}],
            ),
            True,
            True,
        )
        self.assertEqual(status, "failed")

    def test_allow_unhydrated_still_fails_missing_matches(self):
        status, missing = RULES.validation_status(
            summary(
                unhydrated_lfs=["other.bin"],
                expected_matches=1,
                missing=[{"file": "changed.bin", "rules": "malicious"}],
            ),
            True,
            True,
        )
        self.assertEqual(status, "failed")
        self.assertEqual(missing, [{"file": "changed.bin", "rules": "malicious"}])

    def test_allow_unhydrated_skips_coverage_only_while_pointers_remain(self):
        skipped, missing = RULES.validation_status(
            summary(unhydrated_lfs=["other.bin"], expected_matches=0),
            True,
            True,
        )
        self.assertEqual(skipped, "ok")
        self.assertEqual(missing, [])

        covered, missing = RULES.validation_status(
            summary(expected_matches=0),
            True,
            True,
        )
        self.assertEqual(covered, "failed")
        self.assertEqual(missing[0]["file"], "<coverage>")

    def test_strict_coverage_failure_when_no_malicious_bytes_were_scanned(self):
        status, missing = RULES.validation_status(
            summary(expected_matches=0),
            True,
            False,
        )
        self.assertEqual(status, "failed")
        self.assertEqual(missing[0]["file"], "<coverage>")


if __name__ == "__main__":
    unittest.main()
