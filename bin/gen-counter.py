"""Generate a shields.io SVG counter badge for LOLDrivers YAML files.

This script counts the total number of known vulnerable driver samples
and generates a shields.io badge URL for display in documentation.
"""

import os
import sys
import argparse
import urllib.parse
import yaml
from typing import Dict, Any, Optional


def count_vulnerable_samples(folder: str) -> int:
    """Count total vulnerable driver samples across YAML files.
    
    Args:
        folder: Path to directory containing YAML driver definitions
        
    Returns:
        Total count of known vulnerable samples found
        
    Raises:
        OSError: If folder cannot be read
        yaml.YAMLError: If YAML parsing fails
    """
    if not os.path.isdir(folder):
        raise OSError(f"Directory not found: {folder}")
    
    sample_count: int = 0
    
    for filename in os.listdir(folder):
        if not filename.endswith('.yaml'):
            continue
        
        filepath = os.path.join(folder, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                yaml_data: Optional[Dict[str, Any]] = yaml.safe_load(f)
                
                if yaml_data is None:
                    continue
                
                if not isinstance(yaml_data, dict):
                    print(f"WARNING: {filepath} does not contain a dictionary", file=sys.stderr)
                    continue
                
                samples = yaml_data.get('KnownVulnerableSamples', [])
                if isinstance(samples, list):
                    sample_count += len(samples)
                else:
                    print(f"WARNING: {filepath} has malformed KnownVulnerableSamples", file=sys.stderr)
                    
        except yaml.YAMLError as e:
            print(f"ERROR: Failed to parse {filepath}: {str(e)}", file=sys.stderr)
            raise
        except IOError as e:
            print(f"ERROR: Failed to read {filepath}: {str(e)}", file=sys.stderr)
            raise
    
    return sample_count


def generate_badge_url(label: str, message: str, style: str = 'flat') -> str:
    """Generate a shields.io badge URL.
    
    Args:
        label: Left-side label text
        message: Right-side message/count text
        style: Badge style (default: flat)
        
    Returns:
        Full shields.io SVG badge URL
    """
    url = 'https://img.shields.io/badge/{}-{}-{}.svg'.format(
        urllib.parse.quote_plus(label),
        urllib.parse.quote_plus(message),
        urllib.parse.quote_plus(style)
    )
    return url


def main(folder: str) -> None:
    """Main entry point for counter generation.
    
    Args:
        folder: Path to directory containing YAML files
        
    Exits:
        With status code 0 on success, 1 on error
    """
    try:
        # Count samples
        sample_count = count_vulnerable_samples(folder)
        
        # Generate badge URL
        url = generate_badge_url('Drivers', str(sample_count))
        
        # Write to GitHub Output if available
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            try:
                with open(github_output, 'a', encoding='utf-8') as fh:
                    print(f'result={url}', file=fh)
                print(f"Badge URL written to GitHub Output: {url}")
            except IOError as e:
                print(f"ERROR: Failed to write to GITHUB_OUTPUT: {str(e)}", file=sys.stderr)
                sys.exit(1)
        else:
            # Output to stdout if not running in GitHub Actions
            print(url)
        
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    """Script entry point with command-line argument handling."""
    try:
        parser = argparse.ArgumentParser(
            description='Generate a shields.io counter badge for LOLDrivers YAML files',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument(
            '-f', '--folder',
            metavar='FOLDER',
            type=str,
            default='yaml/',
            help='Directory containing YAML files (default: yaml/)'
        )
        
        args = parser.parse_args()
        folder: str = args.folder
        
        main(folder)
        
    except KeyboardInterrupt:
        print("\nCounter generation interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"FATAL ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
