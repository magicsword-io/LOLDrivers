#!/usr/bin/python
"""Validates YAML files in a directory against a JSON schema."""

import glob
import json
import jsonschema
import re
import yaml
import sys
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from os import path, walk

# UUID regex pattern (8-4-4-4-12 hex format)
UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)


def check_filename_matches_id(yaml_file: str, yaml_data: Dict[str, Any]) -> Optional[str]:
    """Validates that the YAML filename matches the Id field inside the file.
    
    Args:
        yaml_file: Path to the YAML file.
        yaml_data: Parsed YAML data as a dictionary.
    
    Returns:
        Error message string if validation fails, None otherwise.
    """
    if not isinstance(yaml_data, dict):
        return f"ERROR: YAML data is not a dictionary in file {yaml_file}"
    
    filename = Path(yaml_file).stem  # Get filename without extension
    file_id = yaml_data.get('Id', '')
    
    # Check if filename matches Id
    if filename != file_id:
        return f"ERROR: Filename '{filename}.yaml' does not match Id '{file_id}'"
    
    # Check if Id is a valid UUID format
    if not UUID_PATTERN.match(file_id):
        return f"ERROR: Id '{file_id}' is not a valid UUID format (expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
    
    return None


def check_hash_length(obj: Dict[str, Any], hash_algo: str, hash_length: int) -> Optional[str]:
    """Validates hash lengths for known vulnerable samples.
    
    Args:
        obj: Dictionary containing driver information.
        hash_algo: Hash algorithm name (e.g., 'MD5', 'SHA1', 'SHA256').
        hash_length: Expected length of the hash in characters.
    
    Returns:
        Error message string if validation fails, None otherwise.
    """
    known_vulnerable_samples = obj.get('KnownVulnerableSamples', [])
    if not isinstance(known_vulnerable_samples, list):
        return f"ERROR: KnownVulnerableSamples is not a list in object: {obj.get('Id', 'UNKNOWN')}"
    
    for sample in known_vulnerable_samples:
        if not isinstance(sample, dict):
            continue
        hash_value = sample.get(hash_algo, '')
        if hash_value and len(str(hash_value)) != hash_length:
            return f"ERROR: {hash_algo} length is not {hash_length} characters for object: {obj.get('Id', 'UNKNOWN')}"
    return None


def validate_schema(yaml_dir: str, schema_file: str, verbose: bool) -> Tuple[bool, List[str]]:
    """Validates YAML files against a JSON schema.
    
    Args:
        yaml_dir: Path to directory containing YAML files to validate.
        schema_file: Path to the JSON schema file.
        verbose: If True, print detailed processing information.
    
    Returns:
        Tuple of (has_errors, error_list) where has_errors is a boolean
        and error_list is a list of error message strings.
    """
    error = False
    errors: List[str] = []

    try:
        with open(schema_file, 'rb') as f:
            schema = json.load(f)
    except FileNotFoundError:
        return True, [f"ERROR: Schema file not found: {schema_file}"]
    except json.JSONDecodeError as exc:
        return True, [f"ERROR: Failed to parse schema file {schema_file}: {exc}"]
    except IOError as exc:
        return True, [f"ERROR: Failed to read schema file {schema_file}: {exc}"]

    if not path.exists(yaml_dir):
        return True, [f"ERROR: YAML directory not found: {yaml_dir}"]

    yaml_files = glob.glob(path.join(yaml_dir, "*.yaml"))

    for yaml_file in yaml_files:
        if verbose:
            print("processing YAML file {0}".format(yaml_file))

        try:
            with open(yaml_file, 'r', encoding='utf-8') as stream:
                yaml_data = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            errors.append(f"ERROR: Failed to parse YAML file {yaml_file}: {exc}")
            error = True
            continue
        except IOError as exc:
            errors.append(f"ERROR: Failed to read file {yaml_file}: {exc}")
            error = True
            continue

        if yaml_data is None:
            errors.append(f"ERROR: YAML file {yaml_file} is empty or invalid")
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


def main(yaml_dir: str, schema_file: str, verbose: bool) -> None:
    """Main entry point for schema validation.
    
    Args:
        yaml_dir: Path to directory containing YAML files to validate.
        schema_file: Path to the JSON schema file.
        verbose: If True, print detailed processing information.
    """
    error, errors = validate_schema(yaml_dir, schema_file, verbose)

    for err in errors:
        print(err)

    if error:
        sys.exit(1)
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

