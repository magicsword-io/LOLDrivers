#!/usr/bin/python

'''
Validates YAML metadata and driver binary filenames.
'''

import glob
import hashlib
import json
import jsonschema
import re
import yaml
import sys
import argparse
from pathlib import Path
from os import path, walk

# UUID regex pattern (8-4-4-4-12 hex format)
UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)
MD5_PATTERN = re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE)
SHA256_PATTERN = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
LFS_POINTER_PATTERN = re.compile(
    rb'^version https://git-lfs.github.com/spec/v1\r?\n'
    rb'oid sha256:([a-f0-9]{64})\r?\n',
    re.IGNORECASE,
)


def check_filename_matches_id(yaml_file, yaml_data):
    """Validates that the YAML filename matches the Id field inside the file."""
    filename = Path(yaml_file).stem  # Get filename without extension
    file_id = yaml_data.get('Id', '')
    
    # Check if filename matches Id
    if filename != file_id:
        return f"ERROR: Filename '{filename}.yaml' does not match Id '{file_id}'"
    
    # Check if Id is a valid UUID format
    if not UUID_PATTERN.match(file_id):
        return f"ERROR: Id '{file_id}' is not a valid UUID format (expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
    
    return None


VALID_CATEGORIES = ["vulnerable driver", "malicious"]


def check_category(yaml_data):
    """Validates that Category uses an allowed value."""
    category = yaml_data.get('Category', '')
    if category not in VALID_CATEGORIES:
        return (
            f"ERROR: Invalid Category '{category}' for object: {yaml_data['Id']}. "
            f"Allowed values: {VALID_CATEGORIES}"
        )
    return None


def check_hash_length(object, hash_algo, hash_length):
    known_vulnerable_samples = object.get('KnownVulnerableSamples', [])
    for sample in known_vulnerable_samples:
        hash_value = sample.get(hash_algo, '')
        if hash_value and len(hash_value) != hash_length:
            return f"ERROR: {hash_algo} length is not {hash_length} characters for object: {object['Id']}"
    return None


def collect_sample_hashes(yaml_data, sample_md5s_by_sha256):
    """Collect valid MD5/SHA256 pairs for validating Git LFS pointers."""
    for sample in yaml_data.get('KnownVulnerableSamples', []):
        md5 = sample.get('MD5', '')
        sha256 = sample.get('SHA256', '')
        if (
            isinstance(md5, str)
            and isinstance(sha256, str)
            and MD5_PATTERN.fullmatch(md5)
            and SHA256_PATTERN.fullmatch(sha256)
        ):
            sample_md5s_by_sha256.setdefault(sha256.lower(), set()).add(md5.lower())


def get_lfs_sha256(driver_file):
    """Return the object SHA256 when a file is an unhydrated Git LFS pointer."""
    if Path(driver_file).stat().st_size > 1024:
        return None

    with open(driver_file, 'rb') as stream:
        match = LFS_POINTER_PATTERN.match(stream.read())
    return match.group(1).decode('ascii').lower() if match else None


def get_file_md5(driver_file):
    """Calculate the MD5 used as the canonical driver filename."""
    digest = hashlib.md5(usedforsecurity=False)
    with open(driver_file, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def check_driver_filenames(drivers_dir, sample_md5s_by_sha256, verbose=False):
    """Validate that each .bin filename is the MD5 of its driver content."""
    errors = []

    for driver_file in sorted(glob.glob(path.join(drivers_dir, "*.bin"))):
        if verbose:
            print("processing driver file {0}".format(driver_file))

        filename_md5 = Path(driver_file).stem.lower()
        lfs_sha256 = get_lfs_sha256(driver_file)

        if lfs_sha256:
            expected_md5s = sample_md5s_by_sha256.get(lfs_sha256, set())
            if expected_md5s and filename_md5 not in expected_md5s:
                expected = ', '.join(sorted(expected_md5s))
                errors.append(
                    f"ERROR: Driver filename '{Path(driver_file).name}' does not match "
                    f"the MD5 for Git LFS object SHA256 '{lfs_sha256}' (expected: {expected})"
                )
            elif not MD5_PATTERN.fullmatch(filename_md5):
                errors.append(
                    f"ERROR: Driver filename '{Path(driver_file).name}' is not an MD5 hash "
                    "(expected: 32 hexadecimal characters plus .bin)"
                )
            continue

        actual_md5 = get_file_md5(driver_file)
        if filename_md5 != actual_md5:
            errors.append(
                f"ERROR: Driver filename '{Path(driver_file).name}' does not match "
                f"file MD5 '{actual_md5}' (expected: {actual_md5}.bin)"
            )

    return errors


def validate_schema(yaml_dir, schema_file, verbose, drivers_dir='drivers/'):

    error = False
    errors = []
    sample_md5s_by_sha256 = {}

    try:
        with open(schema_file, 'rb') as f:
            schema = json.load(f)
    except IOError:
        print("ERROR: reading schema file {0}".format(schema_file))

    yaml_files = glob.glob(path.join(yaml_dir, "*.yaml"))

    for yaml_file in yaml_files:
        if verbose:
            print("processing YAML file {0}".format(yaml_file))

        with open(yaml_file, 'r') as stream:
            try:
                yaml_data = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(yaml_file))
                errors.append("ERROR: Error reading {0}".format(yaml_file))
                error = True
                continue

        validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
        for schema_error in validator.iter_errors(yaml_data):
            errors.append("ERROR: {0} at file {1}:\n\t{2}".format(json.dumps(schema_error.message), yaml_file, schema_error.path))
            error = True

        # Additional YAML checks
        check_errors = [
            check_filename_matches_id(yaml_file, yaml_data),
            check_category(yaml_data),
            check_hash_length(yaml_data, "MD5", 32),
            check_hash_length(yaml_data, "SHA1", 40),
            check_hash_length(yaml_data, "SHA256", 64),
        ]

        for check_error in check_errors:
            if check_error:
                errors.append(check_error)
                error = True

        collect_sample_hashes(yaml_data, sample_md5s_by_sha256)

    driver_errors = check_driver_filenames(drivers_dir, sample_md5s_by_sha256, verbose)
    if driver_errors:
        errors.extend(driver_errors)
        error = True

    return error, errors


def main(yaml_dir, schema_file, verbose, drivers_dir='drivers/'):

    error, errors = validate_schema(yaml_dir, schema_file, verbose, drivers_dir)

    for err in errors:
        print(err)

    if error:
        sys.exit("Errors found")
    else:
        print("No Errors found")


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="Validates YAML metadata and driver binary filenames")
    parser.add_argument("-y", "--yaml_dir", default='yaml/', help="path to the directory containing YAML files")
    parser.add_argument("-s", "--schema_file", default='bin/spec/drivers.spec.json', help="path to the JSON schema file")
    parser.add_argument("-d", "--drivers_dir", default='drivers/', help="path to the directory containing driver binaries")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")
    # parse them
    args = parser.parse_args()
    yaml_dir = args.yaml_dir
    schema_file = args.schema_file
    drivers_dir = args.drivers_dir
    verbose = args.verbose

    main(yaml_dir, schema_file, verbose, drivers_dir)
