#!/usr/bin/python

'''
Validates YAML files in a directory against a JSON schema.
'''

import glob
import json
import jsonschema
import yaml
import sys
import argparse
from pathlib import Path
from os import path, walk


def check_md5_length(object):
    md5_len = 32
    known_vulnerable_samples = object.get('KnownVulnerableSamples', [])
    for sample in known_vulnerable_samples:
        md5 = sample.get('MD5', '')
        if md5 and len(md5) != md5_len:
            return f"ERROR: MD5 length is not {md5_len} characters for object: {object['Id']}"
    return None

def check_sha1_length(object):
    sha1_len = 40
    known_vulnerable_samples = object.get('KnownVulnerableSamples', [])
    for sample in known_vulnerable_samples:
        sha1 = sample.get('SHA1', '')
        if sha1 and len(sha1) != sha1_len:
            return f"ERROR: SHA1 length is not {sha1_len} characters for object: {object['Id']}"
    return None

def check_sha256_length(object):
    sha256_len = 64
    known_vulnerable_samples = object.get('KnownVulnerableSamples', [])
    for sample in known_vulnerable_samples:
        sha256 = sample.get('SHA256', '')
        if sha256 and len(sha256) != sha256_len:
            return f"ERROR: SHA256 length is not {sha256_len} characters for object: {object['Id']}"
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
            check_md5_length(yaml_data),
            check_sha1_length(yaml_data),
            check_sha256_length(yaml_data),
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

