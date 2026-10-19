import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / 'bin'))

from api_exports import (  # noqa: E402
    ApiExportError,
    export_api_files,
    load_drivers,
    write_drivers_csv,
    write_drivers_table_csv,
)


class ApiExportsCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog_dir = REPOSITORY_ROOT / 'yaml'
        cls.legacy_api_dir = REPOSITORY_ROOT / 'loldrivers.io' / 'content' / 'api'
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.output_dir = Path(cls.temporary_directory.name) / 'api'
        cls.exported_drivers = export_api_files(cls.catalog_dir, cls.output_dir)

    @classmethod
    def tearDownClass(cls):
        cls.temporary_directory.cleanup()

    @staticmethod
    def records_by_id(records):
        return {record['Id']: record for record in records}

    @staticmethod
    def csv_rows_by_id(csv_path):
        with csv_path.open(newline='', encoding='utf-8') as source:
            return {row['Id']: row for row in csv.DictReader(source)}

    def test_json_matches_the_same_revision_yaml_catalog(self):
        expected = self.records_by_id(load_drivers(self.catalog_dir))

        with (self.output_dir / 'drivers.json').open(encoding='utf-8') as source:
            actual = self.records_by_id(json.load(source))

        self.assertEqual(actual, expected)
        self.assertEqual(self.records_by_id(self.exported_drivers), expected)

    def test_committed_api_records_reproduce_legacy_csv_formats(self):
        with (self.legacy_api_dir / 'drivers.json').open(encoding='utf-8') as source:
            legacy_json = json.load(source)

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_dir = Path(temporary_directory) / 'api'
            output_dir.mkdir()
            write_drivers_csv(legacy_json, output_dir, False)
            write_drivers_table_csv(legacy_json, output_dir.parent)

            self.assertEqual(
                self.csv_rows_by_id(output_dir / 'drivers.csv'),
                self.csv_rows_by_id(self.legacy_api_dir / 'drivers.csv'))
            with (output_dir.parent / 'drivers_table.csv').open(newline='', encoding='utf-8') as source:
                reproduced_table_rows = list(csv.reader(source))
            with (REPOSITORY_ROOT / 'loldrivers.io' / 'content' / 'drivers_table.csv').open(
                newline='', encoding='utf-8') as source:
                legacy_table_rows = list(csv.reader(source))
            self.assertEqual(reproduced_table_rows, legacy_table_rows)

    def test_export_writes_the_driver_table_next_to_api_directory(self):
        self.assertTrue((self.output_dir.parent / 'drivers_table.csv').is_file())

    def test_rejects_a_filename_and_id_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            catalog_dir = Path(temporary_directory)
            (catalog_dir / 'expected-id.yaml').write_text('Id: actual-id\n', encoding='utf-8')

            with self.assertRaisesRegex(ApiExportError, 'does not match filename'):
                load_drivers(catalog_dir)


class ApiExportsAuthentihashTests(unittest.TestCase):
    def test_exports_available_authentihashes(self):
        hashes = {'MD5': 'a' * 32, 'SHA1': 'b' * 40, 'SHA256': 'c' * 64}
        cases = [
            ('SHA256 only', [{'Authentihash': {'SHA256': hashes['SHA256']}}],
             ('', '', hashes['SHA256'])),
            ('MD5 only', [{'Authentihash': {'MD5': hashes['MD5']}}],
             (hashes['MD5'], '', '')),
            ('SHA1 only', [{'Authentihash': {'SHA1': hashes['SHA1']}}],
             ('', hashes['SHA1'], '')),
            ('absent', [{}], ('', '', '')),
            ('empty', [{'Authentihash': {}}], ('', '', '')),
            ('null', [{'Authentihash': None}], ('', '', '')),
            ('mixed samples', [
                {'Authentihash': hashes},
                {},
                {'Authentihash': {}},
                {'Authentihash': None},
                {'Authentihash': {'SHA256': 'd' * 64}},
                {'Authentihash': {'MD5': 'e' * 32, 'SHA1': 'f' * 40}},
            ], (f"{hashes['MD5']}, {'e' * 32}",
                f"{hashes['SHA1']}, {'f' * 40}",
                f"{hashes['SHA256']}, {'d' * 64}")),
        ]

        for name, samples, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                catalog_dir = Path(temporary_directory) / 'yaml'
                catalog_dir.mkdir()
                output_dir = Path(temporary_directory) / 'api'
                driver = {
                    'Id': 'test-driver',
                    'Tags': ['test.sys'],
                    'Category': 'vulnerable driver',
                    'Created': '2026-01-01',
                    'KnownVulnerableSamples': [
                        {'Filename': 'test.sys', 'SHA256': '0' * 64, **sample}
                        for sample in samples
                    ],
                }
                (catalog_dir / 'test-driver.yaml').write_text(
                    yaml.safe_dump(driver), encoding='utf-8')

                export_api_files(catalog_dir, output_dir)

                with (output_dir / 'drivers.csv').open(newline='', encoding='utf-8') as source:
                    row, = list(csv.DictReader(source))
                self.assertEqual(
                    tuple(row[f'KnownVulnerableSamples_Authentihash_{algorithm}']
                          for algorithm in ('MD5', 'SHA1', 'SHA256')),
                    expected)
                with (output_dir / 'drivers.json').open(encoding='utf-8') as source:
                    self.assertEqual(json.load(source), [driver])


if __name__ == '__main__':
    unittest.main()
