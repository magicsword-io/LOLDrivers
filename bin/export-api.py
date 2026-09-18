#!/usr/bin/env python3
"""Export the current YAML catalog as the public JSON and CSV API files."""

import argparse

from api_exports import ApiExportError, export_api_files


def main():
    parser = argparse.ArgumentParser(
        description='Write deterministic LOLDrivers API exports without site generation.')
    parser.add_argument(
        '-p', '--path', '--input', dest='input_dir', default='yaml',
        help='directory containing LOLDrivers YAML records (default: yaml)')
    parser.add_argument(
        '-o', '--output', dest='output_dir', default='website/public/api',
        help='directory for drivers.json and drivers.csv (default: website/public/api)')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='print each driver while formatting the CSV')
    args = parser.parse_args()

    try:
        drivers = export_api_files(args.input_dir, args.output_dir, args.verbose)
    except ApiExportError as error:
        parser.error(str(error))

    print(f'Wrote {len(drivers)} driver records to {args.output_dir}')


if __name__ == '__main__':
    main()
