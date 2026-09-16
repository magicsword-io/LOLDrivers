"""Deterministic public API exports derived from LOLDrivers YAML records."""

import csv
import json
import os
from pathlib import Path

import pandas as pd
import yaml


class ApiExportError(ValueError):
    """Raised when the YAML catalog cannot form a stable public API export."""


def write_drivers_csv(drivers, output_dir, VERBOSE):
    output_file = os.path.join(output_dir, 'drivers.csv')

    header = ['Id', 'Author', 'Created', 'Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID',
              'OperatingSystem', 'Resources', 'Driver Description', 'Person', 'Handle', 'Detection',
              'KnownVulnerableSamples_MD5', 'KnownVulnerableSamples_SHA1', 'KnownVulnerableSamples_SHA256',
              'KnownVulnerableSamples_Publisher', 'KnownVulnerableSamples_Date',
              'KnownVulnerableSamples_Company', 'KnownVulnerableSamples_Description',
              'KnownVulnerableSamples_Authentihash_MD5', 'KnownVulnerableSamples_Authentihash_SHA1', 'KnownVulnerableSamples_Authentihash_SHA256', 'Verified', 'Tags']
    rows = []
    for driver in drivers:
        if VERBOSE:
            print(f"Writing driver CSV: {driver['Id']}")

        md5s = [s['MD5'] for s in driver['KnownVulnerableSamples'] if 'MD5' in s]
        sha1s = [s['SHA1'] for s in driver['KnownVulnerableSamples'] if 'SHA1' in s]
        sha256s = [s['SHA256'] for s in driver['KnownVulnerableSamples'] if 'SHA256' in s]
        publishers = [s['Publisher'] for s in driver['KnownVulnerableSamples'] if 'Publisher' in s]
        dates = [s['Date'] for s in driver['KnownVulnerableSamples'] if 'Date' in s]
        companies = [s['Company'] for s in driver['KnownVulnerableSamples'] if 'Company' in s]
        descriptions = [s['Description'] for s in driver['KnownVulnerableSamples'] if 'Description' in s]
        authentihash_md5s = [s['Authentihash']['MD5'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]
        authentihash_sha1s = [s['Authentihash']['SHA1'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]
        authentihash_sha256s = [s['Authentihash']['SHA256'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]

        row = {
            'Id': driver.get('Id', ''),
            'Author': driver.get('Author', ''),
            'Created': driver.get('Created', ''),
            'Command': driver.get('Command', ''),
            'Description': driver.get('Description', ''),
            'Usecase': driver.get('Usecase', ''),
            'Category': driver.get('Category', ''),
            'Privileges': driver.get('Privileges', ''),
            'MitreID': driver.get('MitreID', ''),
            'OperatingSystem': driver.get('OperatingSystem', ''),
            'Resources': driver.get('Resources', ''),
            'Driver Description': driver.get('Driver Description', ''),
            'Person': driver.get('Person', ''),
            'Handle': driver.get('Handle', ''),
            'Detection': driver.get('Detection', ''),
            'KnownVulnerableSamples_MD5': ', '.join(str(md5) for md5 in md5s),
            'KnownVulnerableSamples_SHA1': ', '.join(str(sha1) for sha1 in sha1s),
            'KnownVulnerableSamples_SHA256': ', '.join(str(sha256) for sha256 in sha256s),
            'KnownVulnerableSamples_Publisher': ', '.join(str(publisher) for publisher in publishers),
            'KnownVulnerableSamples_Date': ', '.join(str(date) for date in dates),
            'KnownVulnerableSamples_Company': ', '.join(str(company) for company in companies),
            'KnownVulnerableSamples_Description': ', '.join(str(description) for description in descriptions),
            'KnownVulnerableSamples_Authentihash_MD5': ', '.join(str(md5) for md5 in authentihash_md5s),
            'KnownVulnerableSamples_Authentihash_SHA1': ', '.join(str(sha1) for sha1 in authentihash_sha1s),
            'KnownVulnerableSamples_Authentihash_SHA256': ', '.join(str(sha256) for sha256 in authentihash_sha256s),
            'Verified': driver.get('Verified', ''),
            'Tags': ', '.join(str(tag) for tag in driver['Tags'])
        }

        rows.append(row)

    df = pd.DataFrame(rows, columns=header)
    df.to_csv(output_file, quoting=1, index=False)


def write_drivers_table_csv(drivers, output_dir):
    output_file = os.path.join(output_dir, 'drivers_table.csv')
    with open(output_file, 'w') as output_file:
        writer = csv.writer(output_file)
        for driver in drivers:
            link = '[' + driver['Tags'][0] + '](drivers/' + driver["Id"] + '/)'
            if ('SHA256' not in driver['KnownVulnerableSamples'][0]) or (driver['KnownVulnerableSamples'][0]['SHA256'] is None ) or (driver['KnownVulnerableSamples'][0]['SHA256'] == ''):
                sha256='not available '
            else:
                sha256='[' + driver['KnownVulnerableSamples'][0]['SHA256'] + '](drivers/' + driver["Id"]+ '/)'
            writer.writerow([link, sha256, driver['Category'].capitalize(), driver['Created']])


def load_drivers(input_dir):
    """Load catalog YAML in a deterministic order and validate its public IDs."""
    input_path = Path(input_dir)
    yaml_files = sorted({*input_path.glob('*.yaml'), *input_path.glob('*.yml')})
    if not yaml_files:
        raise ApiExportError(f'No YAML files found in {input_path}')

    drivers = []
    seen_ids = set()
    for yaml_file in yaml_files:
        with yaml_file.open(encoding='utf-8') as stream:
            driver = yaml.safe_load(stream)

        if not isinstance(driver, dict):
            raise ApiExportError(f'{yaml_file}: expected a YAML mapping')

        driver_id = driver.get('Id')
        if not isinstance(driver_id, str) or not driver_id:
            raise ApiExportError(f'{yaml_file}: expected a non-empty Id')
        if driver_id != yaml_file.stem:
            raise ApiExportError(
                f'{yaml_file}: Id {driver_id!r} does not match filename {yaml_file.stem!r}')
        if driver_id in seen_ids:
            raise ApiExportError(f'{yaml_file}: duplicate Id {driver_id!r}')

        seen_ids.add(driver_id)
        drivers.append(driver)

    return drivers


def export_api_files(input_dir, output_dir, verbose=False):
    """Write same-revision JSON and CSV public exports to ``output_dir``."""
    drivers = load_drivers(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    write_drivers_csv(drivers, output_path, verbose)
    with (output_path / 'drivers.json').open('w', encoding='utf-8') as output_file:
        json.dump(drivers, output_file, ensure_ascii=False, indent=4)
    write_drivers_table_csv(drivers, output_path.parent)

    return drivers
