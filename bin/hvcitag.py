"""Tag YAML driver files with HVCI (Hypervisor-protected Code Integrity) compatibility."""

import csv
import os
import yaml
from typing import List, Tuple, Dict, Any, Generator

YAML_DIRECTORY: str = '../yaml'
CSV_FILE_PATH: str = 'hvci_drivers.csv'
YAML_PATHS: List[str] = ["../yaml"]


class NoAliasDumper(yaml.Dumper):
    """YAML dumper that avoids creating aliases for repeated references."""
    
    def ignore_aliases(self, data: Any) -> bool:
        """Override to prevent YAML aliases.
        
        Args:
            data: Data to check for aliasing.
        
        Returns:
            Always True to disable all aliases.
        """
        return True


def get_hashes_from_csv(csv_file_path: str) -> Tuple[List[str], List[str]]:
    """Load HVCI status hashes from CSV file.
    
    Args:
        csv_file_path: Path to the CSV file containing hash and status data.
    
    Returns:
        Tuple of (allowed_hashes, disallowed_hashes) lists.
    
    Raises:
        FileNotFoundError: If CSV file does not exist.
        csv.Error: If CSV file is malformed.
    """
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")
    
    allowed_drivers: List[str] = []
    disallowed_drivers: List[str] = []

    try:
        with open(csv_file_path, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            
            if csv_reader.fieldnames is None:
                raise ValueError("CSV file has no header row")
            
            if 'Status' not in csv_reader.fieldnames:
                raise ValueError("CSV file missing 'Status' column")
            
            for row in csv_reader:
                if row['Status'] == "Allowed":
                    row.pop('Status', None)
                    allowed_drivers += [x for x in list(row.values()) if x]
                else:
                    row.pop('Status', None)
                    disallowed_drivers += [x for x in list(row.values()) if x]
    except (csv.Error, ValueError) as exc:
        raise RuntimeError(f"Error processing CSV file {csv_file_path}: {exc}") from exc

    return allowed_drivers, disallowed_drivers


def yield_yaml_file(path_to_yaml_folder: List[str]) -> Generator[str, None, None]:
    """Recursively yield all YAML files from given paths.
    
    Args:
        path_to_yaml_folder: List of directory paths to search.
    
    Yields:
        Full paths to YAML files found.
    
    Raises:
        FileNotFoundError: If a path does not exist.
    """
    for path_ in path_to_yaml_folder:
        if not os.path.exists(path_):
            raise FileNotFoundError(f"Path not found: {path_}")
        
        for root, _, files in os.walk(path_):
            for file in files:
                if file.endswith(".yaml"):
                    yield os.path.join(root, file)


def tag_hvci_compatibility(yaml_file: str, allowed_drivers: List[str]) -> None:
    """Tag a YAML file's samples with HVCI compatibility status.
    
    Args:
        yaml_file: Path to the YAML file to update.
        allowed_drivers: List of hashes that load despite HVCI.
    
    Raises:
        IOError: If file cannot be read or written.
        yaml.YAMLError: If YAML parsing fails.
    """
    try:
        with open(yaml_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (IOError, yaml.YAMLError) as exc:
        raise RuntimeError(f"Failed to read YAML file {yaml_file}: {exc}") from exc
    
    if not isinstance(data, dict) or 'KnownVulnerableSamples' not in data:
        return
    
    vuln_samples = data['KnownVulnerableSamples']
    if not isinstance(vuln_samples, list):
        return
    
    for index, sample in enumerate(vuln_samples):
        if not isinstance(sample, dict):
            continue
        
        # Get hashes from sample
        md5 = sample.get('MD5') or ''
        sha1 = sample.get('SHA1') or ''
        sha256 = sample.get('SHA256') or ''

        # Determine HVCI compatibility based on hash match
        hvci_status = 'FALSE'
        
        if md5 and md5 in allowed_drivers:
            hvci_status = 'TRUE'
        elif sha1 and sha1 in allowed_drivers:
            hvci_status = 'TRUE'
        elif sha256 and sha256 in allowed_drivers:
            hvci_status = 'TRUE'
        
        data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = hvci_status
    
    # Write updated YAML back to file
    try:
        with open(yaml_file, 'w', encoding='utf-8') as outfile:
            yaml.dump(data, outfile, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper)
    except IOError as exc:
        raise RuntimeError(f"Failed to write YAML file {yaml_file}: {exc}") from exc


def main(csv_path: str, yaml_paths: List[str]) -> None:
    """Main entry point for HVCI tagging.
    
    Args:
        csv_path: Path to CSV file with HVCI status.
        yaml_paths: List of directories containing YAML driver files.
    """
    # Load HVCI status from CSV
    allowed_drivers, disallowed_drivers = get_hashes_from_csv(csv_path)
    
    # Process each YAML file
    for yaml_file in yield_yaml_file(yaml_paths):
        try:
            tag_hvci_compatibility(yaml_file, allowed_drivers)
        except RuntimeError as exc:
            print(f"Warning: {exc}")
    
    print("HVCI tagging completed successfully")


if __name__ == '__main__':
    main(CSV_FILE_PATH, YAML_PATHS)