#!/usr/bin/env python3
"""Statically scan repository samples with the native YARA engine; never execute them."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import yara
from detection_generation import REPO, YARA_PATHS, yara_text
from generated_safety import OutputValidator
from indicator_safety import detection_record, load_catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=REPO)
    parser.add_argument('--skip-generate', action='store_true')
    parser.add_argument('--all-categories', action='store_true', help='Also validate all vulnerable and renamed rule sets')
    parser.add_argument('--output-dir', type=Path, default=Path('/tmp/yara-malicious-validation'))
    parser.add_argument('--json-output', '--json', action='store_true')
    args = parser.parse_args()
    records = load_catalog(args.repo_root / 'yaml')
    expected = {category: {a: set() for a in ('MD5', 'SHA1', 'SHA256')}
                for category in ('malicious', 'vulnerable driver')}
    for driver in records:
        for sample in detection_record(driver)['KnownVulnerableSamples']:
            for a in expected[driver['Category']]:
                if a in sample:
                    expected[driver['Category']][a].add(sample[a].lower())
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = {'native_engine': yara.__version__, 'scanned': 0, 'expected_matches': 0,
               'unhydrated_lfs': [], 'missing': [], 'unexpected': []}
    validator = OutputValidator(records)
    with tempfile.TemporaryDirectory(prefix='loldrivers-yara-') as temporary:
        sets = []
        for name, (category, renamed) in YARA_PATHS.items():
            if category != 'malicious' and not args.all_categories:
                continue
            if args.skip_generate:
                path = args.repo_root / 'detections/yara' / name
            else:
                path = Path(temporary) / Path(name).name
                path.write_text(yara_text(records, category, renamed))
            validator.validate(path)
            sets.append((name, category, yara.compile(filepath=str(path), externals={'filename': ''})))
        for path in sorted((args.repo_root / 'drivers').rglob('*.bin')):
            data = path.read_bytes()
            if data.startswith(b'version https://git-lfs.github.com/spec/v1'):
                summary['unhydrated_lfs'].append(path.name)
                continue
            calculated = {a: hashlib.new(a.lower(), data).hexdigest() for a in ('MD5', 'SHA1', 'SHA256')}
            known = {category: any(value in expected[category][a] for a, value in calculated.items()) for category in expected}
            summary['scanned'] += 1
            if known['malicious'] or args.all_categories and known['vulnerable driver']:
                summary['expected_matches'] += 1
            for name, category, rules in sets:
                matches = bool(rules.match(data=data, externals={'filename': path.name}))
                if known[category] and not matches:
                    summary['missing'].append({'file': path.name, 'rules': name})
                if matches and not known[category]:
                    summary['unexpected'].append({'file': path.name, 'rules': name})
    if any(expected['malicious'].values()) and not summary['expected_matches']:
        summary['missing'].append({'file': '<coverage>', 'rules': 'No known affected sample bytes were available'})
    summary['validation_status'] = 'failed' if summary['missing'] or summary['unexpected'] or summary['unhydrated_lfs'] else 'ok'
    (args.output_dir / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    if args.json_output:
        print(json.dumps(summary, indent=2))
    else:
        print(f"YARA {summary['native_engine']}: {summary['scanned']} static scans; {summary['expected_matches']} known affected; {len(summary['missing'])} missing; {len(summary['unexpected'])} unexpected; {len(summary['unhydrated_lfs'])} unhydrated LFS objects.")
    return 1 if summary['validation_status'] != 'ok' else 0


if __name__ == '__main__':
    sys.exit(main())
