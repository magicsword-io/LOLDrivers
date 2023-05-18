import csv
import yaml
import os
import uuid

def csv_to_yaml(csv_file_path, output_folder):
    with open(csv_file_path, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            filename = str(uuid.uuid4())
            cves = row["CVEs"].split("; ")
            yaml_data = {
                "Id": filename,
                "Author": "Michael Haag",
                "Created": "",
                "MitreID": "T1542",
                "Category": "Bootloaders",
                "Verified": "TRUE",
                "Commands": {
                    "Command": "",
                    "Description": f"This was provided by {row['Partner']} and revoked {row['Revocation List Date']}",
                    "Usecase": ["Persistence", "Defense Evasion"],
                    "Privileges": "",
                    "OperatingSystem": row["Architecture"]
                },
                "Resources": ["https://uefi.org/revocationlistfile"],
                "Acknowledgement": {
                    "Person": "",
                    "Handle": ""
                },
                "Detection": [{
                    "type": "",
                    "value": ""
                }],
                "KnownVulnerableSamples": [{
                    "Filename": row["Filename"],
                    "MD5": "",
                    "SHA1": "",
                    "SHA256": row["SHA 256 FLAT"],
                    "Signature": "",
                    "Date": "",
                    "Publisher": "",
                    "Company": "",
                    "Description": "",
                    "Product": "",
                    "ProductVersion": "",
                    "FileVersion": "",
                    "MachineType": row["Architecture"],
                    "OriginalFilename": "",
                    "Authentihash": {
                        "MD5": "",
                        "SHA1": "",
                        "SHA256": [row["PE256 Authenticode"]]
                    },
                    "InternalName": "",
                    "Copyright": "",
                    "Imports": "",
                    "ExportedFunctions": "",
                    "PDBPath": ""
                }],
                "Tags": [row["Filename"]],
                "CVE": cves
            }
            with open(os.path.join(output_folder, f'{filename}.yaml'), 'w') as yaml_file:
                yaml.dump(yaml_data, yaml_file, default_flow_style=False)

csv_to_yaml('dbx_info.csv', '../yaml')
