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
        # Loop through each known vulnerable sample in the YAML data
        enriched = False
        for index, sample in enumerate(yaml_data['KnownVulnerableSamples']):
            # Add/update the missing hashes, signer, and vendor results in the YAML data
            for item in data:
                if sample.get('SHA256') == item.get('sha256', '') or sample.get('SHA1') == item.get('sha1', '') or sample.get('MD5') == item.get('md5', ''):
                    sample['SHA256'] = sample.get('SHA256', item.get('sha256', ''))
                    sample['SHA1'] = sample.get('SHA1', item.get('sha1', ''))
                    sample['MD5'] = sample.get('MD5', item.get('md5', ''))
                    sample['Signature'] = sample.get('Signature', item.get('signer', ''))
                    sample['VendorResults'] = sample.get('VendorResults', item.get('vendor_results', {}))
                    enriched = True
                    # Update the sample in the yaml_data
                    yaml_data['KnownVulnerableSamples'][index] = sample
                    break

        if args.verbose and enriched:
            print(f"Enriched: {file_path}")

        # Save the updated YAML data to the file
        with open(file_path, 'w') as f:
            yaml.dump(yaml_data, f)

