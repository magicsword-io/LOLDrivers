#!/usr/bin/python

"""
Validates YAML files in a directory against a JSON schema.

This script validates LOLDrivers YAML files against a JSON schema specification,
performing structural validation and custom checks for filename-ID matching and hash length.
"""

import glob
import json
import jsonschema
import re
import yaml
import sys
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from os import path, walk

# UUID regex pattern (8-4-4-4-12 hex format)
UUID_PATTERN = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.IGNORECASE)


def check_filename_matches_id(yaml_file: str, yaml_data: Dict[str, Any]) -> Optional[str]:
    """Validate that YAML filename matches the Id field inside the file.
    
    Args:
        yaml_file: Path to the YAML file being validated
        yaml_data: Parsed YAML data dictionary
        
    Returns:
        Error message string if validation fails, None if successful
        
    Raises:
        None - returns error messages instead
    """
    try:
        filename = Path(yaml_file).stem  # Get filename without extension
        file_id = yaml_data.get('Id', '')
        
        if not file_id:
            return f"ERROR: Missing 'Id' field in {yaml_file}"
        
        # Check if filename matches Id
        if filename != file_id:
            return f"ERROR: Filename '{filename}.yaml' does not match Id '{file_id}'"
        
        # Check if Id is a valid UUID format
        if not UUID_PATTERN.match(file_id):
            return f"ERROR: Id '{file_id}' is not a valid UUID format (expected: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        
        return None
    except Exception as e:
        return f"ERROR: Exception checking filename for {yaml_file}: {str(e)}"


def check_hash_length(obj: Dict[str, Any], hash_algo: str, hash_length: int) -> Optional[str]:
    """Validate hash field lengths match expected cryptographic algorithm standards.
    
    Args:
        obj: YAML data object containing driver information
        hash_algo: Algorithm name (MD5, SHA1, SHA256)
        hash_length: Expected character length for this algorithm
        
    Returns:
        Error message string if validation fails, None if successful
    """
    try:
        known_vulnerable_samples = obj.get('KnownVulnerableSamples', [])
        if not isinstance(known_vulnerable_samples, list):
            return None
            
        driver_id = obj.get('Id', 'UNKNOWN')
        
        for sample in known_vulnerable_samples:
            if not isinstance(sample, dict):
                continue
                
            hash_value = sample.get(hash_algo, '')
            if hash_value and len(hash_value) != hash_length:
                return f"ERROR: {hash_algo} length is not {hash_length} characters for object: {driver_id}"
        
        return None
    except Exception as e:
        return f"ERROR: Exception checking hash length: {str(e)}"


def validate_schema(yaml_dir: str, schema_file: str, verbose: bool) -> Tuple[bool, List[str]]:
    """Validate all YAML files in directory against JSON schema.
    
    Args:
        yaml_dir: Directory path containing YAML files to validate
        schema_file: Path to JSON schema specification file
        verbose: Enable verbose output during validation
        
    Returns:
        Tuple of (has_errors: bool, error_messages: List[str])
    """
    error = False
    errors = []

    # Load schema
    try:
        with open(schema_file, 'rb') as f:
            schema = json.load(f)
    except IOError as e:
        errors.append(f"ERROR: Unable to read schema file {schema_file}: {str(e)}")
        return True, errors
    except json.JSONDecodeError as e:
        errors.append(f"ERROR: Schema file {schema_file} is not valid JSON: {str(e)}")
        return True, errors

    # Get all YAML files
    try:
        yaml_files = glob.glob(path.join(yaml_dir, "*.yaml"))
        if not yaml_files:
            errors.append(f"WARNING: No YAML files found in {yaml_dir}")
    except Exception as e:
        errors.append(f"ERROR: Unable to read directory {yaml_dir}: {str(e)}")
        return True, errors

    # Validate each file
    for yaml_file in yaml_files:
        if verbose:
            print(f"Processing YAML file {yaml_file}")

        try:
            with open(yaml_file, 'r', encoding='utf-8') as stream:
                yaml_data = yaml.safe_load(stream)
                if not isinstance(yaml_data, dict):
                    errors.append(f"ERROR: {yaml_file} does not contain a YAML dictionary")
                    error = True
                    continue
        except yaml.YAMLError as exc:
            errors.append(f"ERROR: YAML parsing error in {yaml_file}: {str(exc)}")
            error = True
            continue
        except IOError as e:
            errors.append(f"ERROR: Unable to read file {yaml_file}: {str(e)}")
            error = True
            continue

        # Schema validation
        try:
            validator = jsonschema.Draft7Validator(schema, format_checker=jsonschema.FormatChecker())
            for schema_error in validator.iter_errors(yaml_data):
                errors.append(f"ERROR: {json.dumps(schema_error.message)} at file {yaml_file}:\n\t{schema_error.path}")
                error = True
        except Exception as e:
            errors.append(f"ERROR: Schema validation exception for {yaml_file}: {str(e)}")
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
    """Main entry point for YAML validation.
    
    Args:
        yaml_dir: Directory path containing YAML files to validate
        schema_file: Path to JSON schema specification file
        verbose: Enable verbose output during validation
        
    Exits:
        With error message if validation fails
    """
    try:
        error, errors = validate_schema(yaml_dir, schema_file, verbose)

        for err in errors:
            print(err)

        if error:
            sys.exit("Errors found")
        else:
            print("No Errors found")
    except Exception as e:
        print(f"CRITICAL ERROR: Unexpected exception: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    """Script entry point with command-line argument handling."""
    try:
        # Parse command-line arguments
        parser = argparse.ArgumentParser(
            description="Validates LOLDrivers YAML files against a JSON schema specification",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument(
            "-y", "--yaml_dir",
            default='yaml/',
            help="Path to the directory containing YAML files (default: yaml/)"
        )
        parser.add_argument(
            "-s", "--schema_file",
            default='bin/spec/drivers.spec.json',
            help="Path to the JSON schema file (default: bin/spec/drivers.spec.json)"
        )
        parser.add_argument(
            "-v", "--verbose",
            required=False,
            action='store_true',
            help="Enable verbose output"
        )
        
        args = parser.parse_args()
        yaml_dir: str = args.yaml_dir
        schema_file: str = args.schema_file
        verbose: bool = args.verbose

        main(yaml_dir, schema_file, verbose)
    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)

