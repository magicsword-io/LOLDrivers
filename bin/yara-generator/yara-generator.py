#!/usr/bin/env python3
"""Generate exact-file YARA rules from the validated catalog, offline."""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection_generation import OWNER, REPO, YARA_PATHS, yara_text
from indicator_safety import load_catalog, fail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-y', nargs='+', type=Path, default=[REPO / 'yaml'])
    parser.add_argument('-d', nargs='*', help='Compatibility argument; binaries are not needed for exact-file hash rules')
    parser.add_argument('-o', type=Path, default=REPO / 'detections/yara')
    parser.add_argument('-f', type=Path, help='Optional generation summary log')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    records = [record for folder in args.y for record in load_catalog(folder)]
    outputs = {name: yara_text(records, category, renamed) for name, (category, renamed) in YARA_PATHS.items()}
    # These five files are wholly generator-owned; hand-authored files elsewhere
    # in the output directory are preserved. Never merge stale generated rules.
    for name in outputs:
        path = args.o / name
        if path.exists() and OWNER not in path.read_text()[:300]:
            fail(path, '$', name, 'ownership', 'Establish generator ownership before replacing an existing rule file.')
    for name, text in outputs.items():
        path = args.o / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    summary = f'Generated {len(outputs)} exact-file YARA sets from {len(records)} catalog records'
    if args.f:
        args.f.write_text(summary + '\n')
    print(summary)


if __name__ == '__main__':
    main()
