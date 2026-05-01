#!/usr/bin/env python3
"""
Compares LOLDrivers YAML data against the Microsoft Vulnerable Driver Blocklist
(SiPolicy_Enforced.xml) and computes HVCI bypass metrics.

Produces:
  1. HVCI metrics — how many samples load despite HVCI
  2. Overlap — LOLDrivers samples also in the MS blocklist
  3. Gap — LOLDrivers samples NOT in the MS blocklist
  4. MS-exclusive — MS blocklist entries not in LOLDrivers

Usage:
    python3 bin/blocklist_analysis.py [--yaml-dir yaml] [--sipolicy .context/SiPolicy_Enforced.xml]
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

import yaml

NS = '{urn:schemas-microsoft-com:sipolicy}'


def parse_sipolicy(xml_path):
    """Parse SiPolicy XML and extract deny hashes, file attribute rules, and signers.

    Microsoft blocks most drivers via file-attribute + signer rules (OriginalFilename
    / ProductName + version range), not just hashes. This parser extracts both so
    overlap calculations account for all deny mechanisms.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    auth_sha256s = set()
    auth_sha1s = set()
    hash_deny_count = 0
    filename_deny_count = 0
    driver_names = set()

    denied_filenames = set()
    fileattrib_filenames = set()
    fileattrib_count = 0

    for deny in root.iter(f'{NS}Deny'):
        hash_val = deny.get('Hash', '')
        friendly = deny.get('FriendlyName', '')
        filename = deny.get('FileName', '')

        if filename and not hash_val:
            filename_deny_count += 1
            denied_filenames.add(filename.lower().strip())
            continue

        if not hash_val:
            continue

        hash_val = hash_val.lower().strip()
        hash_deny_count += 1

        if '\\' in friendly:
            name_part = friendly.split('\\')[0].strip()
            driver_names.add(name_part.lower())
        elif friendly:
            name_part = friendly.split(' Hash')[0].strip()
            if name_part:
                driver_names.add(name_part.lower())

        if 'Hash Page' in friendly:
            continue
        elif 'Hash Sha256' in friendly:
            auth_sha256s.add(hash_val)
        elif 'Hash Sha1' in friendly:
            auth_sha1s.add(hash_val)

    for fa in root.iter(f'{NS}FileAttrib'):
        filename = fa.get('FileName', '').strip()
        if filename:
            fileattrib_filenames.add(filename.lower())
            fileattrib_count += 1

    all_denied_filenames = denied_filenames | fileattrib_filenames

    signer_deny_count = 0
    for scenario in root.iter(f'{NS}SigningScenario'):
        for denied in scenario.iter(f'{NS}DeniedSigners'):
            for _ in denied.iter(f'{NS}DeniedSigner'):
                signer_deny_count += 1

    return {
        'auth_sha256s': auth_sha256s,
        'auth_sha1s': auth_sha1s,
        'hash_deny_count': hash_deny_count,
        'filename_deny_count': filename_deny_count,
        'signer_deny_count': signer_deny_count,
        'unique_driver_names': driver_names,
        'denied_filenames': denied_filenames,
        'fileattrib_filenames': fileattrib_filenames,
        'all_denied_filenames': all_denied_filenames,
        'fileattrib_count': fileattrib_count,
    }


def load_loldrivers(yaml_dir):
    """Load all LOLDrivers YAML files and extract sample data."""
    samples = []
    driver_count = 0

    for root_dir, _, files in os.walk(yaml_dir):
        for fname in sorted(files):
            if not fname.endswith('.yaml'):
                continue
            fpath = os.path.join(root_dir, fname)
            with open(fpath, 'r') as f:
                data = yaml.safe_load(f)
            if not data or 'KnownVulnerableSamples' not in data:
                continue

            driver_count += 1
            driver_id = data.get('Id', fname)
            tags = data.get('Tags', [])
            category = data.get('Category', '')

            for sample in data['KnownVulnerableSamples']:
                auth = sample.get('Authentihash', {}) or {}
                auth_sha256 = (auth.get('SHA256') or '').lower().strip()
                auth_sha1 = (auth.get('SHA1') or '').lower().strip()
                flat_sha256 = (sample.get('SHA256') or '').lower().strip()
                hvci = str(sample.get('LoadsDespiteHVCI', '')).upper().strip()
                filename = sample.get('Filename') or (tags[0] if tags else '')
                original_filename = (sample.get('OriginalFilename') or '').strip()
                product = (sample.get('Product') or '').strip()
                internal_name = (sample.get('InternalName') or '').strip()

                samples.append({
                    'driver_id': driver_id,
                    'tags': tags,
                    'category': category,
                    'filename': filename,
                    'original_filename': original_filename,
                    'product': product,
                    'internal_name': internal_name,
                    'auth_sha256': auth_sha256,
                    'auth_sha1': auth_sha1,
                    'flat_sha256': flat_sha256,
                    'hvci': hvci,
                    'has_authentihash': bool(auth_sha256 or auth_sha1),
                })

    return samples, driver_count


def compute_metrics(samples, sipolicy):
    """Compute all metrics."""
    total_samples = len(samples)

    # HVCI metrics
    hvci_true = sum(1 for s in samples if s['hvci'] == 'TRUE')
    hvci_false = sum(1 for s in samples if s['hvci'] == 'FALSE')
    hvci_unknown = total_samples - hvci_true - hvci_false

    # Blocklist comparison — hash match OR file attribute match
    matched_samples = []
    unmatched_samples = []
    no_authentihash = []
    hash_matched = []
    filename_matched = []

    if sipolicy:
        denied_fns = sipolicy['all_denied_filenames']

        for s in samples:
            match_type = None

            if s['has_authentihash']:
                if s['auth_sha256'] and s['auth_sha256'] in sipolicy['auth_sha256s']:
                    match_type = 'hash'
                elif s['auth_sha1'] and s['auth_sha1'] in sipolicy['auth_sha1s']:
                    match_type = 'hash'

            if not match_type and denied_fns:
                sample_names = set()
                for field in ('original_filename', 'filename', 'internal_name'):
                    val = s.get(field, '')
                    if val:
                        sample_names.add(val.lower().strip())
                if sample_names & denied_fns:
                    match_type = 'filename'

            if match_type:
                matched_samples.append(s)
                if match_type == 'hash':
                    hash_matched.append(s)
                else:
                    filename_matched.append(s)
            elif not s['has_authentihash'] and not s.get('original_filename') and not s.get('filename'):
                no_authentihash.append(s)
            else:
                unmatched_samples.append(s)

        # MS-exclusive: hashes in blocklist not found in any LOLDrivers sample
        lol_auth_sha256s = {s['auth_sha256'] for s in samples if s['auth_sha256']}
        lol_auth_sha1s = {s['auth_sha1'] for s in samples if s['auth_sha1']}
        ms_exclusive_sha256 = sipolicy['auth_sha256s'] - lol_auth_sha256s
        ms_exclusive_sha1 = sipolicy['auth_sha1s'] - lol_auth_sha1s

    # Matched drivers (unique driver IDs that have at least one matched sample)
    matched_driver_ids = {s['driver_id'] for s in matched_samples} if sipolicy else set()
    unmatched_driver_ids = {s['driver_id'] for s in unmatched_samples} if sipolicy else set()
    exclusive_driver_ids = unmatched_driver_ids - matched_driver_ids

    # HVCI + blocklist cross-analysis
    hvci_bypass_in_blocklist = sum(
        1 for s in matched_samples if s['hvci'] == 'TRUE'
    ) if sipolicy else 0
    hvci_bypass_not_in_blocklist = sum(
        1 for s in unmatched_samples if s['hvci'] == 'TRUE'
    ) if sipolicy else 0

    matchable = total_samples - len(no_authentihash) if sipolicy else 0

    return {
        'total_samples': total_samples,
        'hvci': {
            'bypass_count': hvci_true,
            'blocked_count': hvci_false,
            'unknown_count': hvci_unknown,
            'bypass_pct': round(hvci_true / total_samples * 100, 1) if total_samples else 0,
        },
        'blocklist': {
            'ms_auth_sha256_count': len(sipolicy['auth_sha256s']) if sipolicy else 0,
            'ms_auth_sha1_count': len(sipolicy['auth_sha1s']) if sipolicy else 0,
            'ms_hash_deny_rules': sipolicy['hash_deny_count'] if sipolicy else 0,
            'ms_filename_deny_rules': sipolicy['filename_deny_count'] if sipolicy else 0,
            'ms_fileattrib_rules': sipolicy['fileattrib_count'] if sipolicy else 0,
            'ms_denied_filenames': len(sipolicy['all_denied_filenames']) if sipolicy else 0,
            'ms_signer_deny_count': sipolicy['signer_deny_count'] if sipolicy else 0,
            'ms_unique_driver_names': len(sipolicy['unique_driver_names']) if sipolicy else 0,
            'matchable_samples': matchable,
            'samples_without_any_matchable_field': len(no_authentihash) if sipolicy else 0,
            'overlap_total': len(matched_samples) if sipolicy else 0,
            'overlap_by_hash': len(hash_matched) if sipolicy else 0,
            'overlap_by_filename': len(filename_matched) if sipolicy else 0,
            'overlap_pct': round(len(matched_samples) / matchable * 100, 1) if matchable else 0,
            'overlap_drivers': len(matched_driver_ids),
            'loldrivers_exclusive_samples': len(unmatched_samples) if sipolicy else 0,
            'loldrivers_exclusive_pct': round(len(unmatched_samples) / matchable * 100, 1) if matchable else 0,
            'loldrivers_exclusive_drivers': len(exclusive_driver_ids),
            'ms_exclusive_sha256': len(ms_exclusive_sha256) if sipolicy else 0,
            'ms_exclusive_sha1': len(ms_exclusive_sha1) if sipolicy else 0,
        },
        'cross': {
            'hvci_bypass_in_blocklist': hvci_bypass_in_blocklist,
            'hvci_bypass_not_in_blocklist': hvci_bypass_not_in_blocklist,
        },
    }


def print_report(metrics, driver_count):
    """Print a human-readable report."""
    total = metrics['total_samples']
    h = metrics['hvci']
    b = metrics['blocklist']
    c = metrics['cross']

    print("=" * 70)
    print("  LOLDrivers vs Microsoft Vulnerable Driver Blocklist — Analysis")
    print("=" * 70)

    print(f"\n{'LOLDrivers Overview':}")
    print(f"  Total drivers (YAML files):        {driver_count}")
    print(f"  Total samples (hashes):            {total}")

    print(f"\n{'HVCI Bypass Analysis':}")
    print(f"  Load DESPITE HVCI (bypass):        {h['bypass_count']}  ({h['bypass_pct']}%)")
    print(f"  Blocked by HVCI:                   {h['blocked_count']}")
    if h['unknown_count']:
        print(f"  Unknown/untagged:                  {h['unknown_count']}")

    if b['ms_auth_sha256_count'] or b['ms_denied_filenames']:
        print(f"\nMicrosoft Vulnerable Driver Blocklist")
        print(f"  Hash-based deny rules:             {b['ms_hash_deny_rules']}")
        print(f"    Unique Authenticode SHA256:       {b['ms_auth_sha256_count']}")
        print(f"    Unique Authenticode SHA1:         {b['ms_auth_sha1_count']}")
        print(f"  Filename deny rules (<Deny>):      {b['ms_filename_deny_rules']}")
        print(f"  FileAttrib rules (signer+attr):    {b['ms_fileattrib_rules']}")
        print(f"  Unique denied filenames (combined): {b['ms_denied_filenames']}")
        print(f"  Certificate/signer denies:         {b['ms_signer_deny_count']}")

        print(f"\nCoverage Comparison (hash OR filename matching)")
        print(f"  Matchable samples:                    {b['matchable_samples']}")
        print(f"  Samples with no matchable fields:     {b['samples_without_any_matchable_field']}")
        print(f"  ---")
        print(f"  Overlap TOTAL (in BOTH):              {b['overlap_total']} samples across {b['overlap_drivers']} drivers  ({b['overlap_pct']}%)")
        print(f"    Matched by Authentihash:             {b['overlap_by_hash']}")
        print(f"    Matched by OriginalFilename/Name:    {b['overlap_by_filename']}")
        print(f"  LOLDrivers exclusive (NOT in MS):     {b['loldrivers_exclusive_samples']} samples across {b['loldrivers_exclusive_drivers']} drivers  ({b['loldrivers_exclusive_pct']}%)")
        print(f"  MS blocklist exclusive SHA256:         {b['ms_exclusive_sha256']} hashes not in LOLDrivers")
        print(f"  MS blocklist exclusive SHA1:           {b['ms_exclusive_sha1']} hashes not in LOLDrivers")

        print(f"\nHVCI + Blocklist Cross-Analysis")
        print(f"  HVCI bypass AND in MS blocklist:   {c['hvci_bypass_in_blocklist']}")
        print(f"  HVCI bypass NOT in MS blocklist:   {c['hvci_bypass_not_in_blocklist']}  <-- gap")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='LOLDrivers vs Microsoft Driver Blocklist analysis')
    parser.add_argument('--yaml-dir', default='yaml/',
                        help='Path to LOLDrivers YAML directory')
    parser.add_argument('--sipolicy', default='.context/SiPolicy_Enforced.xml',
                        help='Path to SiPolicy_Enforced.xml')
    parser.add_argument('--output', default='.context/blocklist_analysis_results.json',
                        help='Path to write JSON results')
    args = parser.parse_args()

    # Load LOLDrivers
    print("Loading LOLDrivers YAML files...")
    samples, driver_count = load_loldrivers(args.yaml_dir)
    print(f"  Loaded {len(samples)} samples from {driver_count} drivers")

    # Parse SiPolicy
    sipolicy = None
    if os.path.exists(args.sipolicy):
        print(f"\nParsing SiPolicy XML: {args.sipolicy}")
        sipolicy = parse_sipolicy(args.sipolicy)
        print(f"  Found {len(sipolicy['auth_sha256s'])} unique Authenticode SHA256 hashes")
        print(f"  Found {len(sipolicy['auth_sha1s'])} unique Authenticode SHA1 hashes")
    else:
        print(f"\nWARNING: SiPolicy XML not found at {args.sipolicy}")
        print("  Skipping blocklist comparison (HVCI metrics only)")

    # Compute metrics
    print("\nComputing metrics...")
    metrics = compute_metrics(samples, sipolicy)

    # Print report
    print_report(metrics, driver_count)

    # Write JSON
    output = {
        'driver_count': driver_count,
        **metrics,
    }
    # Convert sets to counts for JSON serialization
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to: {args.output}")


if __name__ == '__main__':
    main()
