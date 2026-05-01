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
    """Parse SiPolicy XML and extract deny hashes, file attribute rules, and signer counts.

    Microsoft blocks most drivers via file-attribute + signer rules (OriginalFilename
    / ProductName + version range), not just hashes.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    auth_sha256s = set()
    auth_sha1s = set()
    hash_deny_count = 0
    filename_deny_count = 0
    denied_filenames = set()
    fileattrib_filenames = set()

    for deny in root.iter(f'{SIPOLICY_NS}Deny'):
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

        if 'Hash Page' in friendly:
            continue
        elif 'Hash Sha256' in friendly:
            auth_sha256s.add(hash_val)
        elif 'Hash Sha1' in friendly:
            auth_sha1s.add(hash_val)

    for fa in root.iter(f'{SIPOLICY_NS}FileAttrib'):
        filename = fa.get('FileName', '').strip()
        if filename:
            fileattrib_filenames.add(filename.lower())

    all_denied_filenames = denied_filenames | fileattrib_filenames

    signer_deny_count = 0
    for scenario in root.iter(f'{SIPOLICY_NS}SigningScenario'):
        for denied in scenario.iter(f'{SIPOLICY_NS}DeniedSigners'):
            for _ in denied.iter(f'{SIPOLICY_NS}DeniedSigner'):
                signer_deny_count += 1

    return {
        'auth_sha256s': auth_sha256s,
        'auth_sha1s': auth_sha1s,
        'hash_deny_count': hash_deny_count,
        'filename_deny_count': filename_deny_count,
        'signer_deny_count': signer_deny_count,
        'all_denied_filenames': all_denied_filenames,
    }


def compute_metrics(drivers, sipolicy_data):
    """Compute HVCI and blocklist comparison metrics from driver data."""
    total_drivers = len(drivers)
    total_samples = 0
    hvci_true = 0
    hvci_false = 0
    matchable = 0
    overlap = 0
    overlap_by_hash = 0
    overlap_by_filename = 0
    no_matchable_fields = 0

    denied_fns = sipolicy_data.get('all_denied_filenames', set()) if sipolicy_data else set()

    for driver in drivers:
        for sample in driver.get('KnownVulnerableSamples', []):
            total_samples += 1
            hvci = str(sample.get('LoadsDespiteHVCI', '')).upper().strip()
            if hvci == 'TRUE':
                hvci_true += 1
            elif hvci == 'FALSE':
                hvci_false += 1

            if sipolicy_data:
                auth = sample.get('Authentihash', {}) or {}
                auth_sha256 = (auth.get('SHA256') or '').lower().strip()
                auth_sha1 = (auth.get('SHA1') or '').lower().strip()
                orig_fn = (sample.get('OriginalFilename') or '').strip()
                filename = (sample.get('Filename') or '').strip()
                internal = (sample.get('InternalName') or '').strip()

                has_hash = bool(auth_sha256 or auth_sha1)
                has_name = bool(orig_fn or filename or internal)

                if not has_hash and not has_name:
                    no_matchable_fields += 1
                    continue

                matchable += 1
                matched = False

                if has_hash and ((auth_sha256 and auth_sha256 in sipolicy_data['auth_sha256s']) or
                        (auth_sha1 and auth_sha1 in sipolicy_data['auth_sha1s'])):
                    matched = True
                    overlap_by_hash += 1

                if not matched and denied_fns:
                    sample_names = set()
                    for val in (orig_fn, filename, internal):
                        if val:
                            sample_names.add(val.lower().strip())
                    if sample_names & denied_fns:
                        matched = True
                        overlap_by_filename += 1

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
        metrics.update({
            'ms_blocklist_hash_count': len(sipolicy_data['auth_sha256s']),
            'ms_blocklist_filename_count': len(denied_fns),
            'ms_blocklist_signer_count': sipolicy_data['signer_deny_count'],
            'overlap_count': overlap,
            'overlap_by_hash': overlap_by_hash,
            'overlap_by_filename': overlap_by_filename,
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
            'overlap_count': 'N/A',
            'overlap_by_hash': 'N/A',
            'overlap_by_filename': 'N/A',
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
