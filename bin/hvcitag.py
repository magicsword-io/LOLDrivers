"""Tag driver samples with HVCI (Hypervisor-protected Code Integrity) compatibility status.

This script reads HVCI driver allowlist from a CSV file and tags LOLDrivers YAML
sample entries with whether they can load despite HVCI protection (TRUE/FALSE).
"""

import csv
import os
import sys
import yaml
from typing import List, Tuple, Dict, Any, Iterator


# Default configuration
DEFAULT_CSV_PATH = 'hvci_drivers.csv'
DEFAULT_YAML_PATHS = ["../yaml"]


class NoAliasDumper(yaml.Dumper):
    """YAML dumper that avoids creating anchor/alias references.
    
    This prevents YAML from creating references like &id001, *id001,
    which can complicate diff viewing and maintenance.
    """
    
    def ignore_aliases(self, data: Any) -> bool:
        """Override to always return True, never creating aliases.
        
        Args:
            data: YAML data being serialized
            
        Returns:
            Always True to disable aliasing
        """
        return True


def get_hashes_from_csv(csv_file_path: str) -> Tuple[List[str], List[str]]:
    """Extract driver hashes from HVCI allowlist CSV file.
    
    Expects CSV with columns: Status and hash columns (MD5, SHA1, SHA256, etc.)
    Rows with Status='Allowed' are added to allowed list, others to disallowed.
    
    Args:
        csv_file_path: Path to CSV file with HVCI driver allowlist
        
    Returns:
        Tuple of (allowed_hashes, disallowed_hashes) lists
        
    Raises:
        IOError: If file cannot be read
        csv.Error: If CSV format is invalid
    """
    allowed_drivers: List[str] = []
    disallowed_drivers: List[str] = []

    try:
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            if not csv_reader.fieldnames or 'Status' not in csv_reader.fieldnames:
                raise ValueError("CSV must have 'Status' column")
            
            for row in csv_reader:
                if row is None or 'Status' not in row:
                    continue
                
                status = row.pop('Status', None)
                # Extract non-empty hash values
                hashes = [x for x in list(row.values()) if x and isinstance(x, str)]
                
                if status == "Allowed":
                    allowed_drivers.extend(hashes)
                else:
                    disallowed_drivers.extend(hashes)
            
    except IOError as e:
        raise IOError(f"Failed to read CSV file {csv_file_path}: {str(e)}")
    except csv.Error as e:
        raise csv.Error(f"CSV parsing error in {csv_file_path}: {str(e)}")
    
    return allowed_drivers, disallowed_drivers


def yield_yaml_files(paths: List[str]) -> Iterator[str]:
    """Generator yielding all YAML files in given directory paths.
    
    Args:
        paths: List of directory paths to search
        
    Yields:
        Full file paths to YAML files found
        
    Raises:
        OSError: If directory cannot be accessed
    """
    for path_ in paths:
        if not os.path.isdir(path_):
            print(f"WARNING: Directory not found: {path_}", file=sys.stderr)
            continue
        
        try:
            for root, _, files in os.walk(path_):
                for file in files:
                    if file.endswith(".yaml"):
                        yield os.path.join(root, file)
        except OSError as e:
            print(f"WARNING: Error walking directory {path_}: {str(e)}", file=sys.stderr)
            continue


def tag_hvci_compatibility(yaml_file: str, allowed_hashes: List[str]) -> int:
    """Tag YAML driver file with HVCI compatibility for each sample.
    
    Args:
        yaml_file: Path to YAML driver file
        allowed_hashes: List of hashes that load despite HVCI
        
    Returns:
        Number of samples tagged (0 if error)
        
    Raises:
        IOError: If file cannot be read/written
        yaml.YAMLError: If YAML parsing fails
    """
    try:
        # Read YAML
        with open(yaml_file, encoding="utf-8") as f:
            data: Dict[str, Any] = yaml.safe_load(f)
        
        if data is None or not isinstance(data, dict):
            print(f"WARNING: {yaml_file} does not contain valid data", file=sys.stderr)
            return 0
        
        # Tag samples
        vuln_samples = data.get('KnownVulnerableSamples', [])
        if not isinstance(vuln_samples, list):
            print(f"WARNING: {yaml_file} has invalid KnownVulnerableSamples", file=sys.stderr)
            return 0
        
        tagged_count = 0
        for index, sample in enumerate(vuln_samples):
            if not isinstance(sample, dict):
                continue
            
            # Try hashes in order of preference (MD5 > SHA1 > SHA256)
            md5 = sample.get('MD5') or ''
            sha1 = sample.get('SHA1') or ''
            sha256 = sample.get('SHA256') or ''
            
            loads_despite_hvci = 'FALSE'
            
            if md5 and md5 in allowed_hashes:
                loads_despite_hvci = 'TRUE'
            elif sha1 and sha1 in allowed_hashes:
                loads_despite_hvci = 'TRUE'
            elif sha256 and sha256 in allowed_hashes:
                loads_despite_hvci = 'TRUE'
            
            if data['KnownVulnerableSamples'][index].get('LoadsDespiteHVCI') != loads_despite_hvci:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = loads_despite_hvci
                tagged_count += 1
        
        # Write YAML back
        with open(yaml_file, 'w', encoding='utf-8') as outfile:
            yaml.dump(data, outfile, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper)
        
        return tagged_count
        
    except IOError as e:
        print(f"ERROR: IO error processing {yaml_file}: {str(e)}", file=sys.stderr)
        raise
    except yaml.YAMLError as e:
        print(f"ERROR: YAML error processing {yaml_file}: {str(e)}", file=sys.stderr)
        raise


def main(csv_file_path: str, yaml_paths: List[str]) -> None:
    """Main entry point for HVCI tagging.
    
    Args:
        csv_file_path: Path to HVCI allowlist CSV file
        yaml_paths: List of directories containing YAML files
        
    Exits:
        With status code 0 on success, 1 on error
    """
    try:
        # Load allowed/disallowed hashes
        print(f"Loading HVCI allowlist from {csv_file_path}...")
        allowed_drivers, disallowed_drivers = get_hashes_from_csv(csv_file_path)
        print(f"Loaded {len(allowed_drivers)} allowed and {len(disallowed_drivers)} disallowed hashes")
        
        # Tag YAML files
        total_files = 0
        total_tagged = 0
        
        for yaml_file in yield_yaml_files(yaml_paths):
            total_files += 1
            try:
                tagged = tag_hvci_compatibility(yaml_file, allowed_drivers)
                total_tagged += tagged
                if tagged > 0:
                    print(f"Tagged {tagged} samples in {yaml_file}")
            except Exception as e:
                print(f"ERROR: Failed to process {yaml_file}: {str(e)}", file=sys.stderr)
                continue
        
        print(f"\nCompleted: Tagged {total_tagged} samples across {total_files} files")
        
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    """Script entry point."""
    try:
        # Could be expanded to support command-line arguments
        main(DEFAULT_CSV_PATH, DEFAULT_YAML_PATHS)
    except KeyboardInterrupt:
        print("\nHVCI tagging interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)