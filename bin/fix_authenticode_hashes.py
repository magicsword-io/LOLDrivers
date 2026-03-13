#!/usr/bin/env python3
"""
Cross-references YAML driver files against Microsoft's SiPolicy (VulnerableDriverBlockList)
to identify hashes that are actually authenticode hashes misclassified as file hashes.

The SiPolicy XML deny rules contain authenticode hashes, not flat file hashes.
This script finds YAML entries where these hashes were incorrectly stored as SHA256/SHA1
and moves them to the Authentihash section via targeted text edits (preserving formatting).

Usage:
    python3 bin/fix_authenticode_hashes.py [--dry-run] [--sipolicy PATH ...]
"""

import argparse
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

import yaml


NS = '{urn:schemas-microsoft-com:sipolicy}'


def parse_sipolicy_hashes(xml_paths):
    """Parse SiPolicy XML files and return a dict of hash -> hash_info."""
    groups = {}  # prefix -> {sha1: ..., sha256: ..., page_sha1: ..., page_sha256: ...}
    all_hashes = {}  # lowercase hash -> {type, prefix, friendly_name}

    for xml_path in xml_paths:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for deny in root.iter(f'{NS}Deny'):
            friendly = deny.get('FriendlyName', '')
            hash_val = deny.get('Hash', '').lower()
            if not hash_val or not friendly:
                continue

            if 'Hash Page Sha256' in friendly:
                hash_type = 'page_sha256'
                prefix = friendly.replace(' Hash Page Sha256', '')
            elif 'Hash Page Sha1' in friendly:
                hash_type = 'page_sha1'
                prefix = friendly.replace(' Hash Page Sha1', '')
            elif 'Hash Sha256' in friendly:
                hash_type = 'sha256'
                prefix = friendly.replace(' Hash Sha256', '')
            elif 'Hash Sha1' in friendly:
                hash_type = 'sha1'
                prefix = friendly.replace(' Hash Sha1', '')
            else:
                all_hashes[hash_val] = {'type': 'unknown', 'friendly': friendly}
                continue

            if prefix not in groups:
                groups[prefix] = {}
            groups[prefix][hash_type] = hash_val

            all_hashes[hash_val] = {
                'type': hash_type,
                'prefix': prefix,
                'friendly': friendly,
            }

    return all_hashes, groups


def apply_text_edit(content, hash_field, hash_val, authentihash, indent):
    """Apply a targeted text edit: replace hash line and add Authentihash block."""
    # Find the line with the hash value (case-insensitive match)
    pattern = re.compile(
        rf'^({indent}{hash_field}:\s*)[\'"]?{re.escape(hash_val)}[\'"]?\s*$',
        re.IGNORECASE | re.MULTILINE
    )
    match = pattern.search(content)
    if not match:
        return content, False

    # Replace the hash value with empty string
    new_line = f"{indent}{hash_field}: ''"
    content = content[:match.start()] + new_line + content[match.end():]

    # Now find where to insert the Authentihash block
    # Look for LoadsDespiteHVCI line that follows this sample's hash
    # We need to find the LoadsDespiteHVCI line for THIS specific sample
    hvci_pattern = re.compile(
        rf'^{indent}LoadsDespiteHVCI:.*$', re.MULTILINE
    )

    # Search from the position of the hash line we just modified
    search_start = match.start()
    hvci_match = hvci_pattern.search(content, search_start)
    if not hvci_match:
        return content, False

    # Check if there's already an Authentihash block between our edit and HVCI
    segment = content[search_start:hvci_match.start()]
    if 'Authentihash:' in segment:
        return content, False

    # Build authentihash block
    auth_sha1 = authentihash['SHA1'] or "''"
    auth_sha256 = authentihash['SHA256'] or "''"
    auth_block = f"\n{indent}Authentihash:\n"
    auth_block += f"{indent}    MD5: ''\n"
    auth_block += f"{indent}    SHA1: {auth_sha1}\n"
    auth_block += f"{indent}    SHA256: {auth_sha256}"

    # Insert after the LoadsDespiteHVCI line
    insert_pos = hvci_match.end()
    content = content[:insert_pos] + auth_block + content[insert_pos:]

    return content, True


def process_yaml_files(yaml_dir, all_hashes, groups, dry_run=False):
    """Process all YAML files and fix misclassified authenticode hashes."""
    yaml_files = sorted(glob.glob(os.path.join(yaml_dir, '*.yaml')))
    modified_files = []
    total_samples_fixed = 0

    for yaml_file in yaml_files:
        # Parse YAML to understand structure
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)

        if not data or 'KnownVulnerableSamples' not in data:
            continue

        samples = data['KnownVulnerableSamples']
        if not samples:
            continue

        # Identify which samples need fixing
        fixes = []
        for sample in samples:
            existing_auth = sample.get('Authentihash', {})
            if existing_auth and (existing_auth.get('SHA256') or existing_auth.get('SHA1')):
                continue

            matched_fields = {}
            for field in ['SHA256', 'SHA1', 'MD5']:
                val = sample.get(field, '')
                if val and val.lower() in all_hashes:
                    matched_fields[field] = val

            if not matched_fields:
                continue

            # Find the SiPolicy group
            first_match = list(matched_fields.values())[0]
            info = all_hashes.get(first_match.lower())
            if not info or 'prefix' not in info:
                continue

            group = groups.get(info['prefix'], {})
            authentihash = {'MD5': '', 'SHA1': '', 'SHA256': ''}

            if group:
                if 'sha1' in group:
                    authentihash['SHA1'] = group['sha1']
                if 'sha256' in group:
                    authentihash['SHA256'] = group['sha256']

            for field, val in matched_fields.items():
                field_info = all_hashes[val.lower()]
                if field_info['type'] == 'sha256':
                    authentihash['SHA256'] = val.lower()
                elif field_info['type'] == 'sha1':
                    authentihash['SHA1'] = val.lower()

            if not authentihash['SHA256'] and not authentihash['SHA1']:
                continue

            fixes.append((matched_fields, authentihash))

        if not fixes:
            continue

        # Read raw file content for text-based edits
        with open(yaml_file, 'r') as f:
            content = f.read()

        file_modified = False
        filename = os.path.basename(yaml_file)

        # Detect indent level for KnownVulnerableSamples entries
        # Could be "    SHA256:" (4 spaces) or "  SHA256:" (2 spaces)
        indent_match = re.search(r'^( +)SHA256:', content, re.MULTILINE)
        indent = indent_match.group(1) if indent_match else '    '

        for matched_fields, authentihash in fixes:
            for field, val in matched_fields.items():
                content_new, success = apply_text_edit(
                    content, field, val, authentihash, indent
                )
                if success:
                    content = content_new
                    file_modified = True
                    total_samples_fixed += 1
                    print(f"  [{filename}] Moved {field}: {val[:16]}... to Authentihash")
                    if authentihash['SHA256']:
                        print(f"    Authentihash SHA256: {authentihash['SHA256']}")
                    if authentihash['SHA1']:
                        print(f"    Authentihash SHA1:  {authentihash['SHA1']}")
                    break  # Only one field per sample needs moving

        if file_modified:
            modified_files.append(yaml_file)
            if not dry_run:
                with open(yaml_file, 'w') as f:
                    f.write(content)

    return modified_files, total_samples_fixed


def main():
    parser = argparse.ArgumentParser(
        description='Fix authenticode hashes misclassified as file hashes in YAML driver files')
    parser.add_argument('--yaml-dir', default='yaml/',
                        help='Directory containing YAML driver files')
    parser.add_argument('--sipolicy', nargs='+',
                        default=[
                            '.context/attachments/SiPolicy_Enforced.xml',
                            '.context/attachments/SiPolicy_Enforced_Server2016.xml',
                            '.context/attachments/SiPolicy_Audit.xml',
                        ],
                        help='Path(s) to SiPolicy XML files')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be changed without modifying files')
    args = parser.parse_args()

    print("Parsing SiPolicy XML files...")
    for sp in args.sipolicy:
        if not os.path.exists(sp):
            print(f"  WARNING: {sp} not found, skipping")
    sipolicy_paths = [sp for sp in args.sipolicy if os.path.exists(sp)]

    all_hashes, groups = parse_sipolicy_hashes(sipolicy_paths)
    print(f"  Found {len(all_hashes)} unique deny hashes across {len(groups)} driver groups")

    print(f"\nScanning YAML files in {args.yaml_dir}...")
    if args.dry_run:
        print("  (DRY RUN - no files will be modified)\n")

    modified, total_fixed = process_yaml_files(
        args.yaml_dir, all_hashes, groups, dry_run=args.dry_run)

    print(f"\nSummary:")
    print(f"  Files modified: {len(modified)}")
    print(f"  Samples fixed:  {total_fixed}")

    if args.dry_run and modified:
        print(f"\n  Re-run without --dry-run to apply changes.")


if __name__ == '__main__':
    main()
