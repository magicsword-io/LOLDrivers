import argparse
import json
import os
import yaml

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose output')
parser.add_argument('--input', type=str, default='munin/vt-hash-db.json', help='path to munin JSON output file')
args = parser.parse_args()

# Load the JSON data from munin output file
with open(args.input, 'r') as f:
    data = json.load(f)

# Loop through each YAML file in the directory
for file_name in os.listdir('yaml'):
    if file_name.endswith('.yaml') or file_name.endswith('.yml'):
        file_path = os.path.join('yaml', file_name)
        # Load the YAML data from the file
        with open(file_path, 'r') as f:
            yaml_data = yaml.load(f, Loader=yaml.FullLoader)

        # Check and update hashes in YAML data
        updated = False
        for entry in yaml_data['KnownVulnerableSamples']:
            for vt_data in data:
                # Check if hashes match and update the missing fields accordingly
                hash_match = (
                    entry.get('SHA256') == vt_data['sha256']
                    or entry.get('SHA1') == vt_data['sha1']
                    or entry.get('MD5') == vt_data['md5']
                )
                if hash_match:
                    updated = True
                    if args.verbose:
                        print(f"Updating file: {file_path}")
                    if 'MD5' not in entry or not entry['MD5']:
                        entry['MD5'] = vt_data['md5']
                    if 'SHA1' not in entry or not entry['SHA1']:
                        entry['SHA1'] = vt_data['sha1']
                    if 'SHA256' not in entry or not entry['SHA256']:
                        entry['SHA256'] = vt_data['sha256']
                    if 'Signature' not in entry or not entry['Signature']:
                        entry['Signature'] = vt_data['signer'].split("; ")

        # Save the updated YAML data back to the file
        if updated:
            with open(file_path, 'w') as f:
                yaml.dump(yaml_data, f, sort_keys=False)

