import hashlib
import importlib.util
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GEN_FILES_PATH = REPOSITORY_ROOT / "bin" / "gen-files.py"
SPEC = importlib.util.spec_from_file_location("gen_files", GEN_FILES_PATH)
GEN_FILES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN_FILES)


def lfs_pointer(sha256, size, newline=b"\n"):
    return (
        b"version https://git-lfs.github.com/spec/v1" + newline
        + b"oid sha256:" + sha256.encode("ascii") + newline
        + b"size " + str(size).encode("ascii") + newline
    )


class ClamAvHashListTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.drivers = self.root / "drivers"
        self.drivers.mkdir()
        self.output = self.root / "detections" / "av" / "LOLDrivers.hdb"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_driver(self, name, content):
        path = self.drivers / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def generate(self):
        GEN_FILES.gen_clamav_hash_list(self.drivers, self.output)
        return self.output.read_text(encoding="ascii")

    def test_hydrated_and_lfs_pointer_entries_match(self):
        hydrated = b"hydrated driver content"
        pointed = b"pointer-backed driver content" * 1024
        pointed_sha256 = hashlib.sha256(pointed).hexdigest()
        self.write_driver("hydrated.bin", hydrated)
        self.write_driver("pointer.bin", lfs_pointer(pointed_sha256, len(pointed), b"\r\n"))

        actual = self.generate()

        expected = (
            f"{hashlib.sha256(hydrated).hexdigest()}:{len(hydrated)}:hydrated.bin\n"
            f"{pointed_sha256}:{len(pointed)}:pointer.bin\n"
        )
        self.assertEqual(actual, expected)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o644)

    def test_mixed_checkout_matches_all_hydrated_output(self):
        first = b"first driver"
        second = b"second driver" * 4096
        pointer_sha256 = hashlib.sha256(second).hexdigest()

        self.write_driver("first.bin", first)
        self.write_driver("second.bin", lfs_pointer(pointer_sha256, len(second)))
        mixed_output = self.generate()

        hydrated_drivers = self.root / "hydrated-drivers"
        hydrated_drivers.mkdir()
        (hydrated_drivers / "first.bin").write_bytes(first)
        (hydrated_drivers / "second.bin").write_bytes(second)
        hydrated_output = self.root / "hydrated.hdb"
        GEN_FILES.gen_clamav_hash_list(hydrated_drivers, hydrated_output)

        self.assertEqual(mixed_output, hydrated_output.read_text(encoding="ascii"))

    def test_rejects_malformed_or_unsupported_pointer_and_preserves_output(self):
        valid_sha256 = "a" * 64
        pointer_header_at_limit = lfs_pointer("1" * 64, "")
        oversized_size = "9" * (
            GEN_FILES.LFS_POINTER_MAX_BYTES - len(pointer_header_at_limit)
        )
        oversized_pointer = lfs_pointer("1" * 64, oversized_size)
        self.assertEqual(len(oversized_pointer), GEN_FILES.LFS_POINTER_MAX_BYTES)
        cases = {
            "truncated": b"version https://git-lfs.github.com/spec/v1\noid sha256:" + valid_sha256.encode("ascii") + b"\n",
            "truncated-prefix": b"version ",
            "truncated-no-delimiter": b"version",
            "tab-delimiter": b"version\t",
            "partial-prefix": b"versio",
            "duplicate-field": lfs_pointer(valid_sha256, 10) + b"size 10\n",
            "bad-digest": lfs_pointer("g" * 64, 10),
            "bad-size": lfs_pointer(valid_sha256, "ten"),
            "noncanonical-size": lfs_pointer(valid_sha256, "010"),
            "unsupported-version": b"version https://git-lfs.github.com/spec/v2\noid sha256:" + valid_sha256.encode("ascii") + b"\nsize 10\n",
            "unsupported-algorithm": b"version https://git-lfs.github.com/spec/v1\noid sha1:" + (b"a" * 40) + b"\nsize 10\n",
            "unsupported-extension": lfs_pointer(valid_sha256, 10) + b"ext-0-foo value\n",
            "oversized-pointer": oversized_pointer + b"trailing bytes",
        }

        for name, content in cases.items():
            with self.subTest(name=name):
                for driver in self.drivers.glob("*.bin"):
                    driver.unlink()
                self.write_driver(f"{name}.bin", content)
                self.output.parent.mkdir(parents=True, exist_ok=True)
                self.output.write_text("previous database\n", encoding="ascii")

                with self.assertRaisesRegex(GEN_FILES.ClamAvHashListError, "pointer"):
                    GEN_FILES.gen_clamav_hash_list(self.drivers, self.output)

                self.assertEqual(self.output.read_text(encoding="ascii"), "previous database\n")

    def test_replace_failure_preserves_output_and_cleans_up_temporary_file(self):
        self.write_driver("driver.bin", b"driver content")
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text("previous database\n", encoding="ascii")

        with mock.patch.object(GEN_FILES.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                GEN_FILES.gen_clamav_hash_list(self.drivers, self.output)

        self.assertEqual(self.output.read_text(encoding="ascii"), "previous database\n")
        self.assertEqual(list(self.output.parent.glob(".LOLDrivers.hdb.*")), [])

    def test_preserves_existing_non_executable_output_permissions(self):
        self.write_driver("driver.bin", b"driver content")
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text("previous database\n", encoding="ascii")
        self.output.chmod(0o640)

        self.generate()

        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)

    def test_ignores_unsupported_extensions_and_sorts_entries(self):
        self.write_driver("z.bin", b"z")
        self.write_driver("nested/a.bin", b"a")
        self.write_driver("ignored.txt", lfs_pointer("a" * 64, 10))

        actual = self.generate()

        self.assertEqual(
            actual,
            f"{hashlib.sha256(b'a').hexdigest()}:1:a.bin\n"
            f"{hashlib.sha256(b'z').hexdigest()}:1:z.bin\n",
        )

    def test_rejects_missing_or_empty_driver_directories(self):
        missing = self.root / "missing"
        with self.assertRaisesRegex(GEN_FILES.ClamAvHashListError, "does not exist"):
            GEN_FILES.gen_clamav_hash_list(missing, self.output)

        with self.assertRaisesRegex(GEN_FILES.ClamAvHashListError, "No .bin drivers"):
            GEN_FILES.gen_clamav_hash_list(self.drivers, self.output)

    def test_hashes_large_hydrated_binary(self):
        content = b"x" * (1024 * 1024 + 1)
        self.write_driver("large.bin", content)

        actual = self.generate()

        self.assertEqual(
            actual,
            f"{hashlib.sha256(content).hexdigest()}:{len(content)}:large.bin\n",
        )


if __name__ == "__main__":
    unittest.main()
