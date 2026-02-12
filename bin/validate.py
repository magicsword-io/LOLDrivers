#!/usr/bin/python

'''
Validates YAML files in a directory against a JSON schema.
'''

import glob
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


def check_hash_length(object, hash_algo, hash_length):
    known_vulnerable_samples = object.get('KnownVulnerableSamples', [])
    for sample in known_vulnerable_samples:
        hash_value = sample.get(hash_algo, '')
        if hash_value and len(hash_value) != hash_length:
            return f"ERROR: {hash_algo} length is not {hash_length} characters for object: {object['Id']}"
    return None


def validate_schema(yaml_dir, schema_file, verbose):

    error = False
    errors = []

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
            check_hash_length(yaml_data, "MD5", 32),
            check_hash_length(yaml_data, "SHA1", 40),
            check_hash_length(yaml_data, "SHA256", 64),
        ]

        for check_error in check_errors:
            if check_error:
                errors.append(check_error)
                error = True

    return error, errors


def main(yaml_dir, schema_file, verbose):

    error, errors = validate_schema(yaml_dir, schema_file, verbose)

    for err in errors:
        print(err)

    if error:
        sys.exit("Errors found")
    else:
        print("No Errors found")


if __name__ == "__main__":
    # grab arguments
    parser = argparse.ArgumentParser(description="Validates YAML files in a directory against a JSON schema")
    parser.add_argument("-y", "--yaml_dir", default='yaml/', help="path to the directory containing YAML files")
    parser.add_argument("-s", "--schema_file", default='bin/spec/drivers.spec.json', help="path to the JSON schema file")
    parser.add_argument("-v", "--verbose", required=False, action='store_true', help="prints verbose output")
    # parse them
    args = parser.parse_args()
    yaml_dir = args.yaml_dir
    schema_file = args.schema_file
    verbose = args.verbose

    main(yaml_dir, schema_file, verbose)

