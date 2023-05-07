# Author(s): Nasreddine Bencherchali (@nas_bench) / Michael Haag (@M_haggis)
# Version: 0.4

import lief
from  datetime import datetime
import os
import argparse
import hashlib
import yaml

# Disable the logger globally 
# READ MORE: https://lief-project.github.io/doc/stable/api/python/index.html#logging
lief.logging.disable()

def get_hashes(driver_):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(driver_, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def yield_next_yaml_file_path(path_to_yml: str) -> str:
        for root, _, files in os.walk(path_to_yml):
            for file in files:
                yield os.path.join(root, file)

def get_yaml_part(file_path: str, part_name: str):
        yaml_dicts = get_yaml(file_path)
        for yaml_part in yaml_dicts:
            if part_name in yaml_part.keys():
                return yaml_part[part_name]
        return None

def get_yaml(file_path: str) -> list:
    data = []
    with open(file_path, encoding='utf-8') as f:
        yaml_data = yaml.safe_load(f)
        data.append(yaml_data)
    return data

def get_metadata(driver):

    """
        Generates a dict of metadata info extracted from driver
    """

    pe = lief.PE.parse(driver)
    
    if pe == None:
        return None, None, None, None
    
    metadata = {}

    md5, sha1, sha256 = get_hashes(driver)

    metadata["Name"] = pe.name
    metadata["Libraries"] = pe.libraries

    if pe.imported_functions:
        metadata['ImportedFunctions'] = [i.name for i in pe.imported_functions]
    else:
        metadata['ImportedFunctions'] = ''

    if pe.exported_functions:
        metadata['ExportedFunctions'] = [i.name for i in pe.exported_functions]
    else:
        metadata['ExportedFunctions'] = ''
    metadata["MD5"] = md5
    metadata["SHA1"] = sha1
    metadata["SHA256"] = sha256

    metadata['Machine'] = pe.header.machine.name

    metadata['AuthentihashMD5'] = pe.authentihash_md5.hex()
    metadata['AuthentihashSHA1'] = pe.authentihash_sha1.hex()
    metadata['AuthentihashSHA256'] = pe.authentihash_sha256.hex()

    try:
        version_info = pe.resources_manager.version.string_file_info.langcode_items[0].items

        metadata['CompanyName'] = version_info.get('CompanyName', b'').decode("utf-8")
        metadata['FileDescription'] = version_info.get('FileDescription', b'').decode("utf-8")
        metadata['InternalName'] = version_info.get('InternalName', b'').decode("utf-8")
        metadata['OriginalFilename'] = version_info.get('OriginalFilename', b'').decode("utf-8")
        metadata['FileVersion'] = version_info.get('FileVersion', b'').decode("utf-8")
        metadata['ProductName'] = version_info.get('ProductName', b'').decode("utf-8")
        metadata['LegalCopyright'] = version_info.get('LegalCopyright', b'').decode("utf-8")
        metadata['ProductVersion'] = version_info.get('ProductVersion', b'').decode("utf-8")

    except lief.not_found:
        metadata['CompanyName'] = ""
        metadata['FileDescription'] = ""
        metadata['InternalName'] = ""
        metadata['OriginalFilename'] = ""
        metadata['FileVersion'] = ""
        metadata['ProductName'] = ""
        metadata['LegalCopyright'] = ""
        metadata['ProductVersion'] = ""



    if len(pe.signatures) > 0:
        metadata['Signatures'] = []
        for sig in pe.signatures:

            sig_info = {'CertificatesInfo': '', 'SignerInfo': ''}
            # Getting the Cert information
            if len(sig.certificates) > 0:
                sig_info['Certificates'] = []
                for cert in sig.certificates:
                    tmp_cert_dict = {}
                    # TODO: Add more info
                    tmp_cert_dict['Subject'] = cert.subject.replace('\\', '').replace('-', ',') # We remove these special character for YAML
                    # Note: This long python foo is just to convert the date from a list to a string
                    tmp_cert_dict['ValidFrom'] = str(datetime.fromisoformat("-".join([str(i) if i >= 10 else '0'+str(i) for i in cert.valid_from[0:3]]) + " " + ":".join([str(i) if i >= 10 else '0'+str(i) for i in cert.valid_from[3:]])))
                    tmp_cert_dict['ValidTo'] = str(datetime.fromisoformat("-".join([str(i) if i >= 10 else '0'+str(i) for i in cert.valid_to[0:3]]) + " " + ":".join([str(i) if i >= 10 else '0'+str(i) for i in cert.valid_to[3:]])))
                    tmp_cert_dict['Signature'] = cert.signature.hex()
                    tmp_cert_dict['SignatureAlgorithmOID'] = cert.signature_algorithm

                    sig_info['Certificates'].append(tmp_cert_dict)

            # Getting Signer Information
            if len(sig.signers) > 0:
                sig_info['Signer'] = []
                for signer in sig.signers:
                    tmp_signer_dict = {}
                    tmp_signer_dict['SerialNumber'] = signer.serial_number.hex()
                    tmp_signer_dict['Issuer'] = signer.issuer.replace('\\', '').replace('-', ',') # We remove these special character for YAML

                    sig_info['Signer'].append(tmp_signer_dict)

            metadata['Signatures'].append(sig_info)

    else:
        metadata['Signatures'] = {}

    return metadata, md5, sha1, sha256

def enrich_yaml(file_path_, metadata_md5, metadata_sha1, metadata_sha256):
    global_enrich = False
    driver_yaml = get_yaml(file_path_)[0]
    if driver_yaml != None:
        if driver_yaml['KnownVulnerableSamples']:
            for sample in driver_yaml['KnownVulnerableSamples']:
                enrich = False
                metadata_ = ''
                #if sample['MD5'] or sample['SHA1'] or sample['SHA256']:
                if "MD5" in sample or "SHA1" in sample or "SHA256" in sample:
                    if sample.get('MD5', None) != "-":
                        try:
                            metadata_ = metadata_md5[sample['MD5']]
                            enrich = True
                        except KeyError:
                            pass
                    if sample.get('SHA1', None) != "-":
                        try:
                            metadata_ = metadata_sha1[sample['SHA1']]
                            enrich = True
                        except KeyError:
                            pass
                    if sample.get('SHA256', None) != "-":
                        try:
                            metadata_ = metadata_sha256[sample['SHA256']]
                            enrich = True
                        except KeyError:
                            pass
                if enrich:
                    global_enrich = True
                    sample['MD5'] = metadata_['MD5']
                    sample['SHA1'] = metadata_['SHA1']
                    sample['SHA256'] = metadata_['SHA256']
                    sample['Authentihash'] = {
                        'MD5':metadata_['AuthentihashMD5'],
                        'SHA1': metadata_['AuthentihashSHA1'],
                        'SHA256': metadata_['AuthentihashSHA256']
                    }
                    sample['Description'] = metadata_['FileDescription']
                    sample['Company'] = metadata_['CompanyName']
                    sample['InternalName'] = metadata_['InternalName']
                    sample['OriginalFilename'] = metadata_['OriginalFilename']
                    sample['FileVersion'] = metadata_['FileVersion']
                    sample['Product'] = metadata_['ProductName']
                    sample['ProductVersion'] = metadata_['ProductVersion']
                    sample['Copyright'] = metadata_['LegalCopyright']
                    sample['MachineType'] = metadata_['Machine']
                    sample['Imports'] = metadata_['Libraries']
                    sample['ExportedFunctions'] = metadata_['ExportedFunctions']
                    sample['ImportedFunctions'] = metadata_['ImportedFunctions']
                    sample['Signatures'] = metadata_['Signatures']
    else:
        print(f"[*] ERROR - There Was an Error Enriching The File: {file_path_}")

    if global_enrich:
        with open(file_path_, 'w') as outfile:
            yaml.dump(driver_yaml, outfile, default_flow_style=False, sort_keys=False)
            print(f"    [*] NOTICE - The File {file_path_} Was Enriched")
    else:
        print(f"    [*] NOTICE - No enrichment was performed on {file_path_}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description='Metadata Extractor')
    parser.add_argument('-d', help='Path to input directory (Vuln drivers folder; recursive)', metavar='vuln-drivers-folder', required=True)
    parser.add_argument('-yaml', help='Path to YAML directory', metavar='yaml-folder', required=True)

    # TODO: Add verbose mode
    # parser.add_argument('-v', help='Get audit and logging details for every rule', action="store_true")
    args = parser.parse_args()

    # Init vars
    metadata_md5 = {}
    metadata_sha1 = {}
    metadata_sha256 = {}

    if os.path.isdir(args.d) and os.path.isdir(args.yaml):
        path_to_rules = args.d
        path_to_yamls = args.yaml
    else:
        print("The path provided isn't a directory")
        exit(1)

    drivers_list = []
    metadata_list = []

    for root, _, files in os.walk(path_to_rules):
        for file in files:
            drivers_list.append(os.path.join(root, file))

    print(f"[*] NOTICE - Extracting Metadata Information From the Drivers...")
    for driver in drivers_list:
        result, md5, sha1, sha256 = get_metadata(driver)
        if result != None:
            metadata_list.append(result)
            metadata_md5[md5] = result
            metadata_sha1[sha1] = result
            metadata_sha256[sha256] = result

    print(f"[*] NOTICE - Starting Enrichment Process...")
    for file in yield_next_yaml_file_path(path_to_yamls):
        enrich_yaml(file, metadata_md5, metadata_sha1, metadata_sha256)