import csv
import os
import yaml

yaml_directory = '../yaml'
csv_file_path = 'hvci_drivers.csv'
paths = ["../yaml"]

class NoAliasDumper(yaml.Dumper):
    def ignore_aliases(self, data):
        return True

def get_hashes_from_csv(csv_file_path):

    allowed_drivers = []
    disallowed_drivers = []

    with open(csv_file_path, mode='r', newline='', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            if row['Status'] == "Allowed":
                row.pop('Status', None)
                allowed_drivers += [x for x in list(row.values()) if x]
            else:
                row.pop('Status', None)
                disallowed_drivers += [x for x in list(row.values()) if x]
            
    return allowed_drivers, disallowed_drivers

allowed_drivers, disallowed_drivers = get_hashes_from_csv(csv_file_path)

def yield_yaml_file(path_to_yaml_folder: list) -> str:
        for path_ in path_to_yaml_folder:
            for root, _, files in os.walk(path_):
                for file in files:
                    if file.endswith(".yaml"):
                        yield os.path.join(root, file)

for file in yield_yaml_file(paths):
    with open(file, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    vuln_samples = data['KnownVulnerableSamples']
    for index, sample in enumerate(vuln_samples):
        # We get the hashes of the sample
        md5 = sample.get('MD5') or ''
        sha1 = sample.get('SHA1') or ''
        sha256 = sample.get('SHA256') or ''

        if md5:
            if md5 in allowed_drivers:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'TRUE'
            else:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'FALSE'
        elif sha1:
            if sha1 in allowed_drivers:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'TRUE'
            else:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'FALSE'
        elif sha256:
            if sha256 in allowed_drivers:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'TRUE'
            else:
                data['KnownVulnerableSamples'][index]['LoadsDespiteHVCI'] = 'FALSE'
    with open(file, 'w') as outfile:
            yaml.dump(data, outfile, default_flow_style=False, sort_keys=False, Dumper=NoAliasDumper)

print("For better or for worse. THe script has finished executing :feels-good:")