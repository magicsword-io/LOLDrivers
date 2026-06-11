import yaml
import argparse
import sys
import re
import os
import json
import datetime
import io
import zipfile
import xml.etree.ElementTree as ET
import jinja2
import csv
import pandas as pd
import requests


def write_drivers_csv(drivers, output_dir, VERBOSE):
    output_file = os.path.join(output_dir, 'content', 'api', 'drivers.csv')
    
    header = ['Id', 'Author', 'Created', 'Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID',
              'OperatingSystem', 'Resources', 'Driver Description', 'Person', 'Handle', 'Detection',
              'KnownVulnerableSamples_MD5', 'KnownVulnerableSamples_SHA1', 'KnownVulnerableSamples_SHA256',
              'KnownVulnerableSamples_Publisher', 'KnownVulnerableSamples_Date',
              'KnownVulnerableSamples_Company', 'KnownVulnerableSamples_Description', 
              'KnownVulnerableSamples_Authentihash_MD5', 'KnownVulnerableSamples_Authentihash_SHA1', 'KnownVulnerableSamples_Authentihash_SHA256', 'Verified', 'Tags']
    rows = []
    for driver in drivers:
        if VERBOSE:
            print(f"Writing driver CSV: {driver['Id']}")

        md5s = [s['MD5'] for s in driver['KnownVulnerableSamples'] if 'MD5' in s]
        sha1s = [s['SHA1'] for s in driver['KnownVulnerableSamples'] if 'SHA1' in s]
        sha256s = [s['SHA256'] for s in driver['KnownVulnerableSamples'] if 'SHA256' in s]
        publishers = [s['Publisher'] for s in driver['KnownVulnerableSamples'] if 'Publisher' in s]
        dates = [s['Date'] for s in driver['KnownVulnerableSamples'] if 'Date' in s]
        companies = [s['Company'] for s in driver['KnownVulnerableSamples'] if 'Company' in s]
        descriptions = [s['Description'] for s in driver['KnownVulnerableSamples'] if 'Description' in s]
        authentihash_md5s = [s['Authentihash']['MD5'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]
        authentihash_sha1s = [s['Authentihash']['SHA1'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]
        authentihash_sha256s = [s['Authentihash']['SHA256'] for s in driver['KnownVulnerableSamples'] if 'Authentihash' in s]

        row = {
            'Id': driver.get('Id', ''),
            'Author': driver.get('Author', ''),
            'Created': driver.get('Created', ''),
            'Command': driver.get('Command', ''),
            'Description': driver.get('Description', ''),
            'Usecase': driver.get('Usecase', ''),
            'Category': driver.get('Category', ''),
            'Privileges': driver.get('Privileges', ''),
            'MitreID': driver.get('MitreID', ''),
            'OperatingSystem': driver.get('OperatingSystem', ''),
            'Resources': driver.get('Resources', ''),
            'Driver Description': driver.get('Driver Description', ''),
            'Person': driver.get('Person', ''),
            'Handle': driver.get('Handle', ''),
            'Detection': driver.get('Detection', ''),
            'KnownVulnerableSamples_MD5': ', '.join(str(md5) for md5 in md5s),
            'KnownVulnerableSamples_SHA1': ', '.join(str(sha1) for sha1 in sha1s),
            'KnownVulnerableSamples_SHA256': ', '.join(str(sha256) for sha256 in sha256s),
            'KnownVulnerableSamples_Publisher': ', '.join(str(publisher) for publisher in publishers),
            'KnownVulnerableSamples_Date': ', '.join(str(date) for date in dates),
            'KnownVulnerableSamples_Company': ', '.join(str(company) for company in companies),
            'KnownVulnerableSamples_Description': ', '.join(str(description) for description in descriptions),
            'KnownVulnerableSamples_Authentihash_MD5': ', '.join(str(md5) for md5 in authentihash_md5s),
            'KnownVulnerableSamples_Authentihash_SHA1': ', '.join(str(sha1) for sha1 in authentihash_sha1s),
            'KnownVulnerableSamples_Authentihash_SHA256': ', '.join(str(sha256) for sha256 in authentihash_sha256s),
            'Verified': driver.get('Verified', ''),
            'Tags': ', '.join(str(tag) for tag in driver['Tags'])                                  
        }

        rows.append(row)

    df = pd.DataFrame(rows, columns=header)
    df.to_csv(output_file, quoting=1, index=False)


SIPOLICY_NS = '{urn:schemas-microsoft-com:sipolicy}'
BLOCKLIST_URL = 'https://aka.ms/VulnerableDriverBlockList'

_VER_MIN = (0, 0, 0, 0)
_VER_MAX = (65535, 65535, 65535, 65535)


def parse_version(v):
    """Parse 'A.B.C.D' (or 'A.B.C', 'A.B', 'A') into a 4-tuple of ints, padding with 0.

    Returns None for None/empty/non-numeric inputs.
    """
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
    """Decide how a sample version relates to a list of (min, max) deny ranges.

    Returns one of:
      'unbounded'       — at least one rule has no effective version constraint
      'in_range'        — sample_ver falls inside at least one bounded rule
      'out_of_range'    — every bounded rule excludes sample_ver
      'unknown_version' — every rule is bounded but sample_ver couldn't be parsed
    """
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
    """Extract the lowercase CN= value from an X.509 Subject DN string.

    Handles CN values that contain commas by reading until the next attribute
    boundary (",<key>=") rather than splitting on every comma. None if absent.
    """
    if not subject:
        return None
    m = _CN_RE.search(str(subject))
    if not m:
        return None
    cn = m.group(1).strip()
    return cn.lower() if cn else None


def sample_signer_match(sample, signer_only_rules):
    """Return True if the sample's cert chain matches any signer-only deny rule.

    Each rule = (set_of_cert_root_hashes_lc, cert_publisher_lc_or_None). A match
    requires: at least one CA cert in the sample's chain has TBS.SHA1 or TBS.SHA256
    in the rule's cert-root set, AND if the rule specifies a cert publisher, the
    sample's leaf cert CN matches it case-insensitively.
    """
    sigs = sample.get('Signatures') or []
    if not isinstance(sigs, list) or not sigs:
        return False
    sig0 = sigs[0]
    if not isinstance(sig0, dict):
        return False
    certs = sig0.get('Certificates') or []
    if not certs:
        return False

    sample_tbs = set()
    leaf_cn = None
    for c in certs:
        if not isinstance(c, dict):
            continue
        tbs = c.get('TBS') or {}
        for k in ('SHA1', 'SHA256'):
            v = tbs.get(k)
            if v:
                sample_tbs.add(str(v).lower().strip())
        if leaf_cn is None and not c.get('IsCA'):
            cn = extract_cn(c.get('Subject'))
            if cn:
                leaf_cn = cn

    if not sample_tbs:
        return False

    for cert_roots, cert_publisher, _sid in signer_only_rules:
        if not (sample_tbs & cert_roots):
            continue
        if cert_publisher and cert_publisher != leaf_cn:
            continue
        return True
    return False


def download_sipolicy(cache_dir, sipolicy_override=None):
    """Download and extract SiPolicy_Enforced.xml from Microsoft's blocklist ZIP."""
    if sipolicy_override and os.path.exists(sipolicy_override):
        return sipolicy_override

    cache_path = os.path.join(cache_dir, 'SiPolicy_Enforced.xml')
    if os.path.exists(cache_path):
        return cache_path

    try:
        print("Downloading Microsoft Vulnerable Driver Blocklist...")
        resp = requests.get(BLOCKLIST_URL, timeout=30)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            target = None
            for name in zf.namelist():
                if name.endswith('SiPolicy_Enforced.xml') and 'Server2016' not in name:
                    target = name
                    break
            if not target:
                print("WARNING: SiPolicy_Enforced.xml not found in ZIP")
                return None
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_path, 'wb') as f:
                f.write(zf.read(target))
        print(f"  Saved to {cache_path}")
        return cache_path
    except Exception as e:
        print(f"WARNING: Failed to download blocklist: {e}")
        return None


def parse_sipolicy_hashes(xml_path):
    """Parse SiPolicy XML and extract deny hashes plus filename rules with version ranges.

    The MS Vulnerable Driver Blocklist denies binaries via three mechanisms:
      - <Deny> with Hash attribute (Authenticode SHA256/SHA1)
      - <Deny> with FileName + MinimumFileVersion / MaximumFileVersion
      - <FileAttrib> with FileName + version range, referenced by <DeniedSigners>
    Both filename mechanisms scope by version range; we capture those so callers
    can confirm the sample's actual version is inside what MS denies.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    auth_sha256s = set()
    auth_sha1s = set()
    hash_deny_count = 0
    filename_deny_count = 0
    fileattrib_count = 0
    denied_filename_rules = {}

    def add_rule(fn, min_v, max_v):
        denied_filename_rules.setdefault(fn.lower().strip(), []).append(
            (parse_version(min_v), parse_version(max_v)))

    for deny in root.iter(f'{SIPOLICY_NS}Deny'):
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

        if 'Hash Page' in friendly:
            continue
        elif 'Hash Sha256' in friendly:
            auth_sha256s.add(hash_val)
        elif 'Hash Sha1' in friendly:
            auth_sha1s.add(hash_val)

    for fa in root.iter(f'{SIPOLICY_NS}FileAttrib'):
        filename = fa.get('FileName', '').strip()
        if filename:
            fileattrib_count += 1
            add_rule(filename, fa.get('MinimumFileVersion'), fa.get('MaximumFileVersion'))

    signers_by_id = {}
    for signer in root.iter(f'{SIPOLICY_NS}Signer'):
        sid = signer.get('ID')
        if not sid:
            continue
        cert_roots = set()
        for cr in signer.iter(f'{SIPOLICY_NS}CertRoot'):
            v = (cr.get('Value') or '').lower().strip()
            if v:
                cert_roots.add(v)
        cert_publisher = None
        for cp in signer.iter(f'{SIPOLICY_NS}CertPublisher'):
            v = (cp.get('Value') or '').strip()
            if v:
                cert_publisher = v.lower()
                break
        has_file_attrib_ref = next(iter(signer.iter(f'{SIPOLICY_NS}FileAttribRef')), None) is not None
        has_cert_oem_id = next(iter(signer.iter(f'{SIPOLICY_NS}CertOemID')), None) is not None
        signers_by_id[sid] = (cert_roots, cert_publisher, has_file_attrib_ref, has_cert_oem_id)

    signer_deny_count = 0
    signer_only_rules = []
    signer_constrained_by_filename = 0
    signer_constrained_by_oemid = 0
    for scenario in root.iter(f'{SIPOLICY_NS}SigningScenario'):
        for denied in scenario.iter(f'{SIPOLICY_NS}DeniedSigners'):
            for d in denied.iter(f'{SIPOLICY_NS}DeniedSigner'):
                signer_deny_count += 1
                sid = d.get('SignerId')
                info = signers_by_id.get(sid)
                if not info:
                    continue
                cert_roots, cert_publisher, has_fa, has_oemid = info
                if not cert_roots:
                    continue
                if has_fa:
                    signer_constrained_by_filename += 1
                    continue
                if has_oemid:
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
        'denied_filename_rules': denied_filename_rules,
        'signer_only_rules': signer_only_rules,
    }


def compute_metrics(drivers, sipolicy_data):
    """Compute HVCI and blocklist comparison metrics from driver data.

    A sample is counted as covered by Microsoft's blocklist if any of:
      - its Authenticode SHA256/SHA1 is on MS's deny hash list, OR
      - its OriginalFilename matches an MS deny filename rule AND its FileVersion
        (or ProductVersion fallback) is inside one of that rule's declared ranges
        (or the rule is unbounded), OR
      - its signing cert chain contains a CA whose TBS hash is on MS's denied-signer
        list AND (if the deny rule specifies one) the leaf cert CN matches the MS
        publisher value. Only signer rules with no <FileAttribRef> are counted here;
        signer rules that scope by file attribute are already covered by the
        filename match above.

    Filename hits where MS scoped the deny to a version window and the sample's
    FileVersion falls outside it are NOT counted — surfaced as
    filename_excluded_out_of_range. Match priority: hash > filename > signer.
    """
    total_drivers = len(drivers)
    total_samples = 0
    hvci_true = 0
    hvci_false = 0
    matchable = 0
    overlap = 0
    overlap_by_hash = 0
    overlap_by_filename_versioned = 0
    overlap_by_filename_unbounded = 0
    overlap_by_signer = 0
    filename_excluded_out_of_range = 0
    filename_excluded_unknown_version = 0
    no_matchable_fields = 0

    rules = sipolicy_data.get('denied_filename_rules', {}) if sipolicy_data else {}
    signer_rules = sipolicy_data.get('signer_only_rules', []) if sipolicy_data else []

    for driver in drivers:
        for sample in driver.get('KnownVulnerableSamples', []):
            total_samples += 1
            hvci = str(sample.get('LoadsDespiteHVCI', '')).upper().strip()
            if hvci == 'TRUE':
                hvci_true += 1
            elif hvci == 'FALSE':
                hvci_false += 1

            if not sipolicy_data:
                continue

            auth = sample.get('Authentihash', {}) or {}
            auth_sha256 = (auth.get('SHA256') or '').lower().strip()
            auth_sha1 = (auth.get('SHA1') or '').lower().strip()
            orig_fn = (sample.get('OriginalFilename') or '').strip().lower()

            has_hash = bool(auth_sha256 or auth_sha1)
            has_name = bool(orig_fn)

            if not has_hash and not has_name:
                no_matchable_fields += 1
                continue

            matchable += 1
            matched = False
            filename_verdict = None

            if has_hash and ((auth_sha256 and auth_sha256 in sipolicy_data['auth_sha256s']) or
                    (auth_sha1 and auth_sha1 in sipolicy_data['auth_sha1s'])):
                matched = True
                overlap_by_hash += 1

            if not matched and has_name and orig_fn in rules:
                sample_ver = (parse_version(sample.get('FileVersion'))
                              or parse_version(sample.get('ProductVersion')))
                filename_verdict = version_match(sample_ver, rules[orig_fn])
                if filename_verdict == 'unbounded':
                    matched = True
                    overlap_by_filename_unbounded += 1
                elif filename_verdict == 'in_range':
                    matched = True
                    overlap_by_filename_versioned += 1

            if not matched and signer_rules and sample.get('Signatures'):
                if sample_signer_match(sample, signer_rules):
                    matched = True
                    overlap_by_signer += 1

            if not matched:
                if filename_verdict == 'out_of_range':
                    filename_excluded_out_of_range += 1
                elif filename_verdict == 'unknown_version':
                    filename_excluded_unknown_version += 1

            if matched:
                overlap += 1

    exclusive = matchable - overlap if sipolicy_data else 0

    metrics = {
        'total_drivers': total_drivers,
        'total_samples': total_samples,
        'hvci_bypass_count': hvci_true,
        'hvci_blocked_count': hvci_false,
        'hvci_bypass_pct': str(round(hvci_true / total_samples * 100, 1)) if total_samples else '0',
        'generated_at': datetime.datetime.now().strftime('%Y-%m-%d'),
    }

    if sipolicy_data:
        overlap_by_filename_total = (
            overlap_by_filename_versioned + overlap_by_filename_unbounded)
        metrics.update({
            'ms_blocklist_hash_count': len(sipolicy_data['auth_sha256s']),
            'ms_blocklist_filename_count': len(rules),
            'ms_blocklist_signer_count': sipolicy_data['signer_deny_count'],
            'ms_blocklist_signer_only_count': len(signer_rules),
            'overlap_count': overlap,
            'overlap_by_hash': overlap_by_hash,
            'overlap_by_filename': overlap_by_filename_total,
            'overlap_by_filename_versioned': overlap_by_filename_versioned,
            'overlap_by_filename_unbounded': overlap_by_filename_unbounded,
            'overlap_by_signer': overlap_by_signer,
            'filename_excluded_out_of_range': filename_excluded_out_of_range,
            'filename_excluded_unknown_version': filename_excluded_unknown_version,
            'overlap_pct': str(round(overlap / matchable * 100, 1)) if matchable else '0',
            'loldrivers_exclusive_count': exclusive,
            'loldrivers_exclusive_pct': str(round(exclusive / matchable * 100, 1)) if matchable else '0',
            'samples_without_matchable_fields': no_matchable_fields,
        })
    else:
        metrics.update({
            'ms_blocklist_hash_count': 'N/A',
            'ms_blocklist_filename_count': 'N/A',
            'ms_blocklist_signer_count': 'N/A',
            'ms_blocklist_signer_only_count': 'N/A',
            'overlap_count': 'N/A',
            'overlap_by_hash': 'N/A',
            'overlap_by_filename': 'N/A',
            'overlap_by_filename_versioned': 'N/A',
            'overlap_by_filename_unbounded': 'N/A',
            'overlap_by_signer': 'N/A',
            'filename_excluded_out_of_range': 'N/A',
            'filename_excluded_unknown_version': 'N/A',
            'overlap_pct': 'N/A',
            'loldrivers_exclusive_count': 'N/A',
            'loldrivers_exclusive_pct': 'N/A',
            'samples_without_matchable_fields': 'N/A',
        })

    return metrics


def write_metrics_json(metrics, output_dir):
    """Write metrics to a Hugo data file."""
    data_dir = os.path.join(output_dir, 'data')
    os.makedirs(data_dir, exist_ok=True)
    output_file = os.path.join(data_dir, 'metrics.json')
    with open(output_file, 'w') as f:
        json.dump(metrics, f, indent=2)
    return output_file


def generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in os.walk(REPO_PATH):
        for file in files:
                manifest_files.append((os.path.join(root, file)))

    drivers = []
    for manifest_file in manifest_files:
        driver = dict()
        if VERBOSE:
            print("processing driver {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)

        drivers.append(object)

    # write markdowns
    j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH), trim_blocks=True, autoescape=True, lstrip_blocks=False)
    d = datetime.datetime.now()
    template = j2_env.get_template('driver.md.j2')
    for driver in drivers:
        file_name = driver["Id"] + '.md'
        output_path = os.path.join(OUTPUT_DIR + '/content/drivers/' + file_name)
        output = template.render(driver=driver, time=str(d.strftime("%Y-%m-%d")))
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("site_gen.py wrote {0} drivers markdown to: {1}".format(len(drivers),OUTPUT_DIR + '/content/drivers/'))

    # write api csv
    write_drivers_csv(drivers, OUTPUT_DIR, VERBOSE)
    messages.append("site_gen.py wrote drivers CSV to: {0}".format(OUTPUT_DIR + '/content/api/drivers.csv'))

    # write api json
    with open(OUTPUT_DIR + '/content/api/' + 'drivers.json', 'w', encoding='utf-8') as f:
        json.dump(drivers, f, ensure_ascii=False, indent=4)
    messages.append("site_gen.py wrote drivers JSON to: {0}".format(OUTPUT_DIR + '/content/api/drivers.json'))

    # write listing csv
    with open(OUTPUT_DIR + '/content/' + 'drivers_table.csv', 'w') as f:
        writer = csv.writer(f)
        for driver in drivers:
            link = '[' + driver['Tags'][0] + '](drivers/' + driver["Id"] + '/)'
            if ('SHA256' not in driver['KnownVulnerableSamples'][0]) or (driver['KnownVulnerableSamples'][0]['SHA256'] is None ) or (driver['KnownVulnerableSamples'][0]['SHA256'] == ''):
                sha256='not available '
            else:
                sha256='[' + driver['KnownVulnerableSamples'][0]['SHA256'] + '](drivers/' + driver["Id"]+ '/)'
            writer.writerow([link, sha256, driver['Category'].capitalize(), driver['Created']])
    messages.append("site_gen.py wrote drivers table to: {0}".format(OUTPUT_DIR + '/content/drivers_table.csv'))

    # write top 5 publishers (kept for backward compatibility but no longer on landing page)
    # write_top_publishers(drivers, OUTPUT_DIR)
    # write_top_products(drivers, OUTPUT_DIR)

    return drivers, messages


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates loldrivers.io site", epilog="""
    This tool converts all loldrivers.io yamls and builds the site with all the supporting components.""")
    parser.add_argument("-p", "--path", required=False, default="yaml", help="path to loldriver yaml folder. Defaults to `yaml`")
    parser.add_argument("-o", "--output", required=False, default="loldrivers.io", help="path to the output directory for the site, defaults to `loldrivers.io`")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("--sipolicy", required=False, default=None, help="path to pre-downloaded SiPolicy_Enforced.xml (otherwise downloads from Microsoft)")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose


    TEMPLATE_PATH = os.path.join(REPO_PATH, '../bin/jinja2_templates')

    if VERBOSE:
        print("wiping the {0}/content/drivers/ folder".format(OUTPUT_DIR))

    # first clean up old drivers
    try:
        for root, dirs, files in os.walk(OUTPUT_DIR + '/content/drivers/'):
            for file in files:
                if file.endswith(".md") and not file == '_index.md':
                    os.remove(root + '/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)


    # also clean up API artifacts
    if os.path.exists(OUTPUT_DIR + '/content/api/drivers.json'):
        os.remove(OUTPUT_DIR + '/content/api/drivers.json')         
    if os.path.exists(OUTPUT_DIR + '/content/api/drivers.csv'):        
        os.remove(OUTPUT_DIR + '/content/api/drivers.csv')


    messages = []
    drivers, messages = generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE)

    # compute and write blocklist/HVCI metrics
    sipolicy_xml = download_sipolicy(OUTPUT_DIR, args.sipolicy)
    if sipolicy_xml:
        sipolicy_data = parse_sipolicy_hashes(sipolicy_xml)
        print(f"  SiPolicy: {len(sipolicy_data['auth_sha256s'])} unique SHA256, {len(sipolicy_data['auth_sha1s'])} unique SHA1 authenticode hashes")
    else:
        sipolicy_data = None
    metrics = compute_metrics(drivers, sipolicy_data)
    metrics_file = write_metrics_json(metrics, OUTPUT_DIR)
    messages.append(f"site_gen.py wrote metrics to: {metrics_file}")

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
