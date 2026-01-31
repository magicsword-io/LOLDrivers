#!/usr/bin/env python3
"""Update drivers.json with latest version info from YAML driver files.

This script synchronizes version information between individual YAML driver files
and the consolidated drivers.json file. It runs automatically in CI/CD to keep
version metadata consistent and up-to-date.

Functionality:
    - Scans all YAML files in /yaml directory
    - Extracts ProductVersion, FileVersion, and timestamps
    - Updates drivers.json with latest version metadata
    - Logs all changes for audit trail
    - Designed to run in CI/CD pipeline automatically

Usage:
    python bin/update-versions.py [--json-file PATH] [--yaml-dir PATH]

Example:
    python bin/update-versions.py
    python bin/update-versions.py --json-file drivers.json --yaml-dir yaml/
"""

import json
import yaml
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional


def get_latest_version_from_yaml(yaml_path: str) -> Dict[str, Any]:
    """Extract version info from driver YAML file.
    
    Finds the latest known vulnerable sample and extracts version metadata.
    Prioritizes samples with complete timestamp information.
    
    Args:
        yaml_path: Path to the driver YAML file.
        
    Returns:
        Dictionary with version metadata including:
        - filename: Driver filename
        - product: ProductVersion from PE headers
        - file: FileVersion from PE headers
        - timestamp: Creation timestamp
        
    Raises:
        FileNotFoundError: If YAML file doesn't exist
        yaml.YAMLError: If YAML is malformed
    """
    try:
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"YAML file not found: {yaml_path}")
    except yaml.YAMLError as e:
        raise yaml.YAMLError(f"Failed to parse YAML {yaml_path}: {e}")
    
    if not data or 'KnownVulnerableSamples' not in data:
        return {}
    
    samples = data.get('KnownVulnerableSamples', [])
    if not isinstance(samples, list) or len(samples) == 0:
        return {}
    
    versions = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
            
        version_entry = {
            'filename': sample.get('Filename', 'unknown'),
            'product': sample.get('ProductVersion'),
            'file': sample.get('FileVersion'),
            'timestamp': sample.get('CreationTimestamp'),
        }
        versions.append(version_entry)
    
    if not versions:
        return {}
    
    # Return latest version (by timestamp, fallback to first sample)
    def get_timestamp_key(entry: Dict[str, Any]) -> str:
        return entry.get('timestamp', '') or ''
    
    latest = max(versions, key=get_timestamp_key)
    return latest if latest.get('timestamp') else versions[0]


def update_drivers_json(yaml_dir: str, json_file: str, 
                       verbose: bool = False) -> Tuple[int, List[str]]:
    """Update drivers.json with current version info from YAML files.
    
    Scans all YAML files, extracts version info, and updates the JSON file
    with latest metadata. Creates audit trail of all changes.
    
    Args:
        yaml_dir: Directory containing YAML driver files.
        json_file: Path to drivers.json file.
        verbose: If True, print detailed processing information.
        
    Returns:
        Tuple of (files_updated, list of changes logged).
        
    Raises:
        FileNotFoundError: If YAML directory or JSON file doesn't exist
        json.JSONDecodeError: If drivers.json is malformed
        IOError: If file operations fail
    """
    # Load existing drivers.json
    try:
        with open(json_file, 'r') as f:
            drivers = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"drivers.json not found: {json_file}")
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Failed to parse drivers.json: {e}",
            e.doc,
            e.pos
        )
    
    if not isinstance(drivers, dict):
        raise TypeError("drivers.json root must be a dictionary")
    
    changes = []
    updated_count = 0
    
    # Scan YAML directory
    yaml_path = Path(yaml_dir)
    if not yaml_path.exists():
        raise FileNotFoundError(f"YAML directory not found: {yaml_dir}")
    
    yaml_files = sorted(yaml_path.glob('*.yaml'))
    if verbose:
        print(f"Found {len(yaml_files)} YAML files")
    
    for yaml_file in yaml_files:
        driver_id = yaml_file.stem
        
        try:
            version_info = get_latest_version_from_yaml(str(yaml_file))
        except (yaml.YAMLError, IOError) as e:
            changes.append(f"ERROR reading {driver_id}: {e}")
            if verbose:
                print(f"ERROR: {driver_id}: {e}")
            continue
        
        if not version_info or not version_info.get('filename'):
            continue
        
        # Check if driver exists in JSON
        if driver_id not in drivers:
            if verbose:
                print(f"SKIP: {driver_id} (not in drivers.json)")
            continue
        
        # Compare and update version info
        old_version = drivers[driver_id].get('version', {})
        new_version = {
            'product': version_info.get('product'),
            'file': version_info.get('file'),
            'timestamp': version_info.get('timestamp'),
            'verified': datetime.now().isoformat()
        }
        
        # Only update if different
        if old_version != new_version:
            drivers[driver_id]['version'] = new_version
            updated_count += 1
            
            change_msg = (
                f"Updated {driver_id}: "
                f"product={new_version.get('product')}, "
                f"timestamp={new_version.get('timestamp')}"
            )
            changes.append(change_msg)
            
            if verbose:
                print(f"UPDATE: {change_msg}")
    
    # Write back to JSON
    try:
        with open(json_file, 'w') as f:
            json.dump(drivers, f, indent=2)
    except IOError as e:
        raise IOError(f"Failed to write drivers.json: {e}")
    
    return updated_count, changes


def main() -> int:
    """Main entry point for version update script.
    
    Parses arguments, runs version synchronization, and reports results.
    Returns appropriate exit code for CI/CD integration.
    
    Returns:
        0 if successful, 1 if errors occurred
    """
    parser = argparse.ArgumentParser(
        description='Update drivers.json with latest version info from YAML files'
    )
    parser.add_argument(
        '--json-file',
        default='drivers.json',
        help='Path to drivers.json file (default: drivers.json)'
    )
    parser.add_argument(
        '--yaml-dir',
        default='yaml',
        help='Path to YAML driver directory (default: yaml)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Print detailed processing information'
    )
    
    args = parser.parse_args()
    
    try:
        updated, changes = update_drivers_json(
            args.yaml_dir,
            args.json_file,
            verbose=args.verbose
        )
        
        print(f"✓ Updated {updated} drivers in {args.json_file}")
        
        if changes:
            if args.verbose:
                print("\nChanges:")
                for change in changes:
                    print(f"  - {change}")
            
            # Log errors separately
            errors = [c for c in changes if c.startswith('ERROR')]
            if errors:
                print(f"\n⚠ {len(errors)} errors occurred during processing")
                return 1
        
        return 0
        
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON: {e}")
        return 1
    except yaml.YAMLError as e:
        print(f"ERROR: Failed to parse YAML: {e}")
        return 1
    except IOError as e:
        print(f"ERROR: File operation failed: {e}")
        return 1
    except Exception as e:
        print(f"ERROR: Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
