"""Generate the README badge from the recorded samples in the YAML catalog."""

import argparse
import os
from pathlib import Path
import re

import yaml


def badge_url(folder):
    sample_count = 0
    for path in Path(folder).glob('*.yaml'):
        with path.open(encoding='utf-8') as source:
            driver = yaml.safe_load(source)
        if driver is not None:
            sample_count += len(driver.get('KnownVulnerableSamples', []))
    return f'https://img.shields.io/badge/Drivers-{sample_count}-flat.svg'


def update_readme(path, url):
    path = Path(path)
    original = path.read_text(encoding='utf-8')
    updated, replacements = re.subn(
        r'https://img\.shields\.io/badge/Drivers-[^\s)]+-flat\.svg',
        url,
        original,
    )
    if replacements != 1:
        raise ValueError(f'Expected one Drivers badge in {path}, found {replacements}')
    if updated != original:
        path.write_text(updated, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f', '--folder', type=Path, default=Path('yaml'))
    parser.add_argument('--readme', type=Path, help='Update the Drivers badge in this README')
    args = parser.parse_args()
    if not args.folder.is_dir():
        parser.error(f'Catalog directory does not exist: {args.folder}')
    url = badge_url(args.folder)
    if args.readme:
        update_readme(args.readme, url)
    print(url)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            print(f'result={url}', file=output)


if __name__ == '__main__':
    main()
