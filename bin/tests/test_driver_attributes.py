"""Keep driver additions covered by LFS without per-sample attribute edits."""

import os
from pathlib import Path
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LFS_ATTRIBUTES = {'filter': 'lfs', 'diff': 'lfs', 'merge': 'lfs', 'text': 'unset'}


class DriverAttributesTests(unittest.TestCase):
    def assert_lfs_attributes(self, filenames):
        output = subprocess.check_output(
            ['git', '-c', f'core.attributesFile={os.devnull}', 'check-attr', '-z',
             *LFS_ATTRIBUTES, '--', *filenames],
            cwd=REPOSITORY_ROOT,
        ).decode().split('\0')[:-1]
        self.assertEqual(len(output), len(filenames) * len(LFS_ATTRIBUTES) * 3)
        for index in range(0, len(output), 3):
            filename, attribute, value = output[index:index + 3]
            self.assertEqual(value, LFS_ATTRIBUTES[attribute], f'{filename}: {attribute}')

    def test_existing_driver_binaries_keep_lfs_attributes(self):
        filenames = subprocess.check_output(
            ['git', 'ls-files', '-z', '--', 'drivers/*.bin'],
            cwd=REPOSITORY_ROOT,
        ).decode().split('\0')[:-1]
        self.assertTrue(filenames)
        self.assert_lfs_attributes(filenames)

    def test_future_driver_binaries_inherit_lfs_attributes(self):
        self.assert_lfs_attributes([
            'drivers/future-sample.bin',
            'drivers/future/nested-sample.bin',
        ])

    def test_root_does_not_duplicate_driver_lfs_rules(self):
        redundant_rules = []
        for line in (REPOSITORY_ROOT / '.gitattributes').read_text().splitlines():
            fields = line.split()
            if fields and fields[0].startswith('drivers/') and 'filter=lfs' in fields[1:]:
                redundant_rules.append(line)
        self.assertFalse(
            redundant_rules,
            'Use the existing wildcard in drivers/.gitattributes; per-sample LFS '
            f'rules in the root cause merge conflicts: {redundant_rules}',
        )


if __name__ == '__main__':
    unittest.main()
