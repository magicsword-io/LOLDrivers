"""Generate a shields.io badge SVG counter for YAML driver files."""

import os
import argparse
import urllib.parse
import yaml
from typing import Dict, Any

DEFAULT_FOLDER: str = 'yaml/'


def count_samples(folder: str) -> int:
    """Count total number of KnownVulnerableSamples across all YAML files.
    
    Args:
        folder: Path to folder containing YAML files.
    
    Returns:
        Total count of vulnerable samples found.
    
    Raises:
        FileNotFoundError: If the folder does not exist.
        yaml.YAMLError: If a YAML file cannot be parsed.
    """
    if not os.path.exists(folder):
        raise FileNotFoundError(f"Folder not found: {folder}")
    
    sample_count = 0
    
    if not os.path.isdir(folder):
        raise NotADirectoryError(f"Path is not a directory: {folder}")
    
    for filename in os.listdir(folder):
        if not filename.endswith('.yaml'):
            continue
        
        filepath = os.path.join(folder, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                yaml_data = yaml.safe_load(f)
                
                if yaml_data is not None and isinstance(yaml_data, dict):
                    samples = yaml_data.get('KnownVulnerableSamples', [])
                    if isinstance(samples, list):
                        sample_count += len(samples)
        except (yaml.YAMLError, IOError) as exc:
            raise RuntimeError(f"Error processing {filepath}: {exc}") from exc
    
    return sample_count


def generate_badge_url(sample_count: int) -> str:
    """Generate shields.io badge URL for the given sample count.
    
    Args:
        sample_count: Number of vulnerable samples to display.
    
    Returns:
        Full URL to the shields.io badge SVG.
    """
    params: Dict[str, str] = {
        'label': 'Drivers',
        'message': str(sample_count),
        'style': 'flat'
    }
    
    url = 'https://img.shields.io/badge/{}-{}-{}.svg'.format(
        urllib.parse.quote_plus(params['label']),
        urllib.parse.quote_plus(params['message']),
        urllib.parse.quote_plus(params['style'])
    )
    
    return url


def main(folder: str) -> None:
    """Main entry point for badge generation.
    
    Args:
        folder: Path to folder containing YAML files.
    
    Raises:
        EnvironmentError: If GITHUB_OUTPUT environment variable is not set.
    """
    sample_count = count_samples(folder)
    url = generate_badge_url(sample_count)
    
    # Save shields URL in Github Output to be used in the next step.
    if 'GITHUB_OUTPUT' not in os.environ:
        raise EnvironmentError("GITHUB_OUTPUT environment variable not set")
    
    try:
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as fh:
            print(f'result={url}', file=fh)
    except IOError as exc:
        raise RuntimeError(f"Failed to write to GITHUB_OUTPUT: {exc}") from exc


if __name__ == '__main__':
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate an SVG counter for a folder with a list of YAML files.')
    parser.add_argument('-f', '--folder', metavar='FOLDER', type=str, default=DEFAULT_FOLDER, 
                        help=f'the folder to search for YAML files (default: {DEFAULT_FOLDER})')
    args = parser.parse_args()
    
    main(args.folder)
