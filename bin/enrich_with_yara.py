import argparse
import os
import yaml
import re

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='enable verbose output')
args = parser.parse_args()

# Define the base URL for the GitHub repository and the full URLs for specific sigma and sysmon rules
base_url = "https://github.com/magicsword-io/LOLDrivers/blob/main/"
sigma_rules = [
    {"type": "sigma_hash", "value": base_url + "detections/sigma/driver_load_win_vuln_drivers.yml"},
    {"type": "sigma_names", "value": base_url + "detections/sigma/driver_load_win_vuln_drivers_names.yml"}
]
sysmon_rules = [
    {"type": "sysmon_hash_detect", "value": base_url + "detections/sysmon/sysmon_config_vulnerable_hashes.xml"},
    {"type": "sysmon_hash_block", "value": base_url + "detections/sysmon/sysmon_config_vulnerable_hashes_block.xml"}
]

# Define YARA rules files
yara_rules_files = [
    "yara-rules_mal_drivers_strict.yar", 
    "yara-rules_vuln_drivers_strict_renamed.yar", 
    "yara-rules_vuln_drivers.yar",
    "yara-rules_mal_drivers.yar",
    "yara-rules_vuln_drivers_strict.yar"
]

# Loop through each YAML file in the directory
for file_name in os.listdir('yaml'):
    if file_name.endswith('.yaml') or file_name.endswith('.yml'):
        file_path = os.path.join('yaml', file_name)

        # Load the YAML data from the file
        with open(file_path, 'r') as f:
            yaml_data = yaml.load(f, Loader=yaml.FullLoader)

        # Check and update detections in YAML data
        updated = False
        for entry in yaml_data['KnownVulnerableSamples']:
            sha256 = entry.get('SHA256')
        if sha256:
            for yara_file_name in yara_rules_files:
                yara_file_path = os.path.join('detections/yara', yara_file_name)

                # Load YARA rules from the file
                with open(yara_file_path, 'r') as f:
                    yara_rules = f.read()
                
                # Check if a rule exists for the specific sample
                if re.search(f'{sha256}', yara_rules):
                    yara_link = {"type": "yara_signature", "value": base_url + yara_file_path}
                    if yara_link not in yaml_data['Detection']:
                        updated = True
                        if args.verbose:
                            print(f"Updating file: {file_path}")
                        yaml_data['Detection'].append(yara_link)
                    break

        # Add specific sigma and sysmon rules to detections
        yaml_data['Detection'].extend(sigma_rules)
        yaml_data['Detection'].extend(sysmon_rules)

        # Save the updated YAML data back to the file
        if updated:
            with open(file_path, 'w') as f:
                yaml.dump(yaml_data, f, sort_keys=False)
