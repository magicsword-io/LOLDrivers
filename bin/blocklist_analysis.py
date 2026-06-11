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
import re
import sys
import xml.etree.ElementTree as ET

import yaml

NS = '{urn:schemas-microsoft-com:sipolicy}'

_VER_MIN = (0, 0, 0, 0)
_VER_MAX = (65535, 65535, 65535, 65535)


def parse_version(v):
    """Parse 'A.B.C.D' (or shorter) into a 4-tuple of ints, padding with 0. None on failure."""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    parts = []
    for p in re.split(r'[.,]', s):
        p = p.strip()
        if not p.isdigit():
            return None
        parts.append(int(p))
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts[:4])


def version_match(sample_ver, ranges):
    """'unbounded' | 'in_range' | 'out_of_range' | 'unknown_version'."""
    for mn, mx in ranges:
        mn_unbounded = mn is None or mn == _VER_MIN
        mx_unbounded = mx is None or mx == _VER_MAX
        if mn_unbounded and mx_unbounded:
            return 'unbounded'
    if sample_ver is None:
        return 'unknown_version'
    for mn, mx in ranges:
        if mn is not None and sample_ver < mn:
            continue
        if mx is not None and sample_ver > mx:
            continue
        return 'in_range'
    return 'out_of_range'


_CN_RE = re.compile(r'(?:^|,)\s*CN=(.*?)(?=,\s*[A-Za-z][A-Za-z0-9.]*=|$)', re.IGNORECASE)


def extract_cn(subject):
    """Extract the lowercase CN= value, handling commas inside the CN value."""
    if not subject:
        return None
    m = _CN_RE.search(str(subject))
    if not m:
        return None
    cn = m.group(1).strip()
    return cn.lower() if cn else None


def sample_cert_chain(sample_signatures):
    """Return (set_of_TBS_lc, leaf_cn_lc_or_None) extracted from a Signatures field."""
    sigs = sample_signatures or []
    if not isinstance(sigs, list) or not sigs:
        return set(), None
    sig0 = sigs[0]
    if not isinstance(sig0, dict):
        return set(), None
    tbs_set = set()
    leaf_cn = None
    for c in sig0.get('Certificates') or []:
        if not isinstance(c, dict):
            continue
        tbs = c.get('TBS') or {}
        for k in ('SHA1', 'SHA256'):
            v = tbs.get(k)
            if v:
                tbs_set.add(str(v).lower().strip())
        if leaf_cn is None and not c.get('IsCA'):
            cn = extract_cn(c.get('Subject'))
            if cn:
                leaf_cn = cn
    return tbs_set, leaf_cn


def signer_chain_matches(tbs_set, leaf_cn, signer_only_rules):
    if not tbs_set:
        return False
    for cert_roots, cert_publisher, _sid in signer_only_rules:
        if not (tbs_set & cert_roots):
            continue
        if cert_publisher and cert_publisher != leaf_cn:
            continue
        return True
    return False


def parse_sipolicy(xml_path):
    """Parse SiPolicy XML and extract deny hashes plus filename rules with version ranges.

    Microsoft blocks most drivers via filename + version-range rules (often combined with
    a denied signer), not just hashes. This parser captures the version bounds so the
    matching logic can confirm a sample's actual FileVersion is inside what MS denies.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    auth_sha256s = set()
    auth_sha1s = set()
    hash_deny_count = 0
    filename_deny_count = 0
    fileattrib_count = 0
    driver_names = set()
    denied_filename_rules = {}

    def add_rule(fn, min_v, max_v):
        denied_filename_rules.setdefault(fn.lower().strip(), []).append(
            (parse_version(min_v), parse_version(max_v)))

    for deny in root.iter(f'{NS}Deny'):
        hash_val = deny.get('Hash', '')
        friendly = deny.get('FriendlyName', '')
        filename = deny.get('FileName', '')

        if filename and not hash_val:
            filename_deny_count += 1
            add_rule(filename, deny.get('MinimumFileVersion'), deny.get('MaximumFileVersion'))
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
            fileattrib_count += 1
            add_rule(filename, fa.get('MinimumFileVersion'), fa.get('MaximumFileVersion'))

    signers_by_id = {}
    for signer in root.iter(f'{NS}Signer'):
        sid = signer.get('ID')
        if not sid:
            continue
        cert_roots = set()
        for cr in signer.iter(f'{NS}CertRoot'):
            v = (cr.get('Value') or '').lower().strip()
            if v:
                cert_roots.add(v)
        cert_publisher = None
        for cp in signer.iter(f'{NS}CertPublisher'):
            v = (cp.get('Value') or '').strip()
            if v:
                cert_publisher = v.lower()
                break
        has_fa = next(iter(signer.iter(f'{NS}FileAttribRef')), None) is not None
        has_oem = next(iter(signer.iter(f'{NS}CertOemID')), None) is not None
        signers_by_id[sid] = (cert_roots, cert_publisher, has_fa, has_oem)

    signer_deny_count = 0
    signer_only_rules = []
    signer_constrained_by_filename = 0
    signer_constrained_by_oemid = 0
    for scenario in root.iter(f'{NS}SigningScenario'):
        for denied in scenario.iter(f'{NS}DeniedSigners'):
            for d in denied.iter(f'{NS}DeniedSigner'):
                signer_deny_count += 1
                sid = d.get('SignerId')
                info = signers_by_id.get(sid)
                if not info:
                    continue
                cert_roots, cert_publisher, has_fa, has_oem = info
                if not cert_roots:
                    continue
                if has_fa:
                    signer_constrained_by_filename += 1
                    continue
                if has_oem:
                    signer_constrained_by_oemid += 1
                    continue
                signer_only_rules.append((cert_roots, cert_publisher, sid))

    return {
        'auth_sha256s': auth_sha256s,
        'auth_sha1s': auth_sha1s,
        'hash_deny_count': hash_deny_count,
        'filename_deny_count': filename_deny_count,
        'fileattrib_count': fileattrib_count,
        'signer_deny_count': signer_deny_count,
        'signer_constrained_by_filename': signer_constrained_by_filename,
        'signer_constrained_by_oemid': signer_constrained_by_oemid,
        'unique_driver_names': driver_names,
        'denied_filename_rules': denied_filename_rules,
        'signer_only_rules': signer_only_rules,
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
                file_version = parse_version(sample.get('FileVersion'))
                product_version = parse_version(sample.get('ProductVersion'))

                tbs_set, leaf_cn = sample_cert_chain(sample.get('Signatures'))

                samples.append({
                    'driver_id': driver_id,
                    'tags': tags,
                    'category': category,
                    'filename': filename,
                    'original_filename': original_filename,
                    'file_version': file_version,
                    'product_version': product_version,
                    'auth_sha256': auth_sha256,
                    'auth_sha1': auth_sha1,
                    'flat_sha256': flat_sha256,
                    'hvci': hvci,
                    'has_authentihash': bool(auth_sha256 or auth_sha1),
                    'tbs_set': tbs_set,
                    'leaf_cn': leaf_cn,
                })

    return samples, driver_count


def compute_metrics(samples, sipolicy):
    """Compute all metrics."""
    total_samples = len(samples)

    # HVCI metrics
    hvci_true = sum(1 for s in samples if s['hvci'] == 'TRUE')
    hvci_false = sum(1 for s in samples if s['hvci'] == 'FALSE')
    hvci_unknown = total_samples - hvci_true - hvci_false

    # Blocklist comparison — hash > (filename + version-in-range) > signer-only
    matched_samples = []
    unmatched_samples = []
    no_matchable = []
    hash_matched = []
    filename_versioned = []
    filename_unbounded = []
    signer_matched = []
    excluded_out_of_range = []
    excluded_unknown_version = []

    if sipolicy:
        rules = sipolicy['denied_filename_rules']
        signer_rules = sipolicy['signer_only_rules']

        for s in samples:
            match_type = None
            verdict = None

            if s['has_authentihash']:
                if s['auth_sha256'] and s['auth_sha256'] in sipolicy['auth_sha256s']:
                    match_type = 'hash'
                elif s['auth_sha1'] and s['auth_sha1'] in sipolicy['auth_sha1s']:
                    match_type = 'hash'

            if not match_type and s['original_filename']:
                fn_lc = s['original_filename'].lower().strip()
                if fn_lc in rules:
                    sample_ver = s['file_version'] or s['product_version']
                    verdict = version_match(sample_ver, rules[fn_lc])
                    if verdict in ('unbounded', 'in_range'):
                        match_type = 'filename'

            if not match_type and signer_rules:
                if signer_chain_matches(s['tbs_set'], s['leaf_cn'], signer_rules):
                    match_type = 'signer'

            if match_type == 'hash':
                hash_matched.append(s)
                matched_samples.append(s)
            elif match_type == 'filename':
                if verdict == 'in_range':
                    filename_versioned.append(s)
                else:
                    filename_unbounded.append(s)
                matched_samples.append(s)
            elif match_type == 'signer':
                signer_matched.append(s)
                matched_samples.append(s)
            elif verdict == 'out_of_range':
                excluded_out_of_range.append(s)
                unmatched_samples.append(s)
            elif verdict == 'unknown_version':
                excluded_unknown_version.append(s)
                unmatched_samples.append(s)
            elif not s['has_authentihash'] and not s['original_filename']:
                no_matchable.append(s)
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

    matchable = total_samples - len(no_matchable) if sipolicy else 0

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
            'ms_denied_filenames': len(sipolicy['denied_filename_rules']) if sipolicy else 0,
            'ms_signer_deny_count': sipolicy['signer_deny_count'] if sipolicy else 0,
            'ms_signer_only_rules': len(sipolicy['signer_only_rules']) if sipolicy else 0,
            'ms_signer_constrained_by_oemid': sipolicy['signer_constrained_by_oemid'] if sipolicy else 0,
            'ms_unique_driver_names': len(sipolicy['unique_driver_names']) if sipolicy else 0,
            'matchable_samples': matchable,
            'samples_without_any_matchable_field': len(no_matchable) if sipolicy else 0,
            'overlap_total': len(matched_samples) if sipolicy else 0,
            'overlap_by_hash': len(hash_matched) if sipolicy else 0,
            'overlap_by_filename': (len(filename_versioned) + len(filename_unbounded)) if sipolicy else 0,
            'overlap_by_filename_versioned': len(filename_versioned) if sipolicy else 0,
            'overlap_by_filename_unbounded': len(filename_unbounded) if sipolicy else 0,
            'overlap_by_signer': len(signer_matched) if sipolicy else 0,
            'filename_excluded_out_of_range': len(excluded_out_of_range) if sipolicy else 0,
            'filename_excluded_unknown_version': len(excluded_unknown_version) if sipolicy else 0,
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
        print(f"  Hash-based deny rules:                   {b['ms_hash_deny_rules']}")
        print(f"    Unique Authenticode SHA256:             {b['ms_auth_sha256_count']}")
        print(f"    Unique Authenticode SHA1:               {b['ms_auth_sha1_count']}")
        print(f"  Filename deny rules (<Deny>):            {b['ms_filename_deny_rules']}")
        print(f"  FileAttrib rules (signer+attr):          {b['ms_fileattrib_rules']}")
        print(f"  Unique denied filenames (combined):       {b['ms_denied_filenames']}")
        print(f"  Denied signer entries (total):            {b['ms_signer_deny_count']}")
        print(f"    ↳ signer-only rules we enforce:          {b['ms_signer_only_rules']}")
        print(f"    ↳ skipped (CertOemID — not verifiable):  {b['ms_signer_constrained_by_oemid']}")

        print(f"\nCoverage Comparison (hash > filename+version > signer)")
        print(f"  Matchable samples:                       {b['matchable_samples']}")
        print(f"  Samples with no matchable fields:        {b['samples_without_any_matchable_field']}")
        print(f"  ---")
        print(f"  Overlap TOTAL (in BOTH):                 {b['overlap_total']} samples across {b['overlap_drivers']} drivers  ({b['overlap_pct']}%)")
        print(f"    Matched by Authentihash:                {b['overlap_by_hash']}")
        print(f"    Matched by OriginalFilename:            {b['overlap_by_filename']}")
        print(f"      ↳ in MS deny version range:            {b['overlap_by_filename_versioned']}")
        print(f"      ↳ MS rule unbounded (any version):     {b['overlap_by_filename_unbounded']}")
        print(f"    Matched by signer cert chain:           {b['overlap_by_signer']}")
        print(f"  Filename hits excluded (not counted as overlap):")
        print(f"    sample version OUTSIDE MS deny range:   {b['filename_excluded_out_of_range']}")
        print(f"    sample version unparseable/missing:     {b['filename_excluded_unknown_version']}")
        print(f"  LOLDrivers exclusive (NOT in MS):        {b['loldrivers_exclusive_samples']} samples across {b['loldrivers_exclusive_drivers']} drivers  ({b['loldrivers_exclusive_pct']}%)")
        print(f"  MS blocklist exclusive SHA256:           {b['ms_exclusive_sha256']} hashes not in LOLDrivers")
        print(f"  MS blocklist exclusive SHA1:             {b['ms_exclusive_sha1']} hashes not in LOLDrivers")

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
