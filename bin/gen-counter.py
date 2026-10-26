"""Update README badges from driver entries and recorded samples in the YAML catalog."""

import argparse
import os
from pathlib import Path
import re

import yaml


def catalog_counts(folder):
    entry_count = 0
    sample_count = 0
    for path in Path(folder).glob('*.yaml'):
        with path.open(encoding='utf-8') as source:
            driver = yaml.safe_load(source)
        if driver is not None:
            entry_count += 1
            sample_count += len(driver.get('KnownVulnerableSamples', []))
    return entry_count, sample_count


def badge_url(sample_count):
    return f'https://img.shields.io/badge/Drivers-{sample_count}-flat.svg'


def update_readme(path, entry_count, sample_count):
    path = Path(path)
    original = path.read_text(encoding='utf-8')
    updated = original
    found = set()
    for label, count in (
        ('Driver_Entries', entry_count),
        ('Known_Samples', sample_count),
        ('Drivers', sample_count),
    ):
        updated, replacements = re.subn(
            rf'(https://img\.shields\.io/badge/{label}-)\d+(-[^\s)]+\.svg)',
            lambda match: f'{match[1]}{count}{match[2]}',
            updated,
        )
        if replacements > 1:
            raise ValueError(f'Expected at most one {label} badge in {path}, found {replacements}')
        if replacements:
            found.add(label)
    current = {'Driver_Entries', 'Known_Samples'}
    if found & current and not current <= found:
        raise ValueError(f'Expected both Driver_Entries and Known_Samples badges in {path}')
    if not found:
        raise ValueError(f'Expected Driver_Entries and Known_Samples badges or a legacy Drivers badge in {path}')
    if updated != original:
        path.write_text(updated, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--folder', type=Path, default=Path('yaml'))
    parser.add_argument('--readme', type=Path, help='Update the catalog badges in this README')
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error(f'Catalog directory does not exist: {args.folder}')
    entry_count, sample_count = catalog_counts(args.folder)
    # Preserve the existing stdout/GITHUB_OUTPUT contract for workflow consumers.
    url = badge_url(sample_count)
    if args.readme:
        update_readme(args.readme, entry_count, sample_count)
    print(url)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            print(f'result={url}', file=output)


if __name__ == '__main__':
    main()
