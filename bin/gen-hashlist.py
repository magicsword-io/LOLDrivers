import yaml
import os

path_to_yml = "../yaml"
path_to_yml = os.path.join(os.path.dirname(os.path.realpath(__file__)), path_to_yml)

def yield_next_rule_file_path(path_to_yml: str) -> str:
        for root, _, files in os.walk(path_to_yml):
            for file in files:
                yield os.path.join(root, file)

def get_yaml_part(file_path: str, part_name: str):
        yaml_dicts = get_yaml(file_path)
        for yaml_part in yaml_dicts:
            if part_name in yaml_part.keys():
                return yaml_part[part_name]
        return None

def get_yaml(file_path: str) -> dict:
    data = []
    with open(file_path, encoding='utf-8') as f:
        yaml_parts = yaml.safe_load_all(f)
        for part in yaml_parts:
            data.append(part)
    return data


def gen_hashes():
    md5_list = []
    sha1_list = []
    sha256_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
        if known_vuln_samples:
            for i in known_vuln_samples:
                if i['MD5']:
                    md5_list.append(i['MD5'])
                if i['SHA1']:
                    sha1_list.append(i['SHA1'])
                if i['SHA256']:
                    sha256_list.append(i['SHA256'])

    if md5_list:
        with open('hashes/samples.md5', 'w') as f: 
            for i in md5_list:
                f.write(i + "\n")
    
    if sha1_list:
        with open('hashes/samples.sha1', 'w') as f: 
            for i in sha1_list:
                f.write(i + "\n")
    
    if sha256_list:
        with open('hashes/samples.sha256', 'w') as f:
            for i in sha256_list:
                f.write(i + "\n")
    

if __name__ == "__main__":
    gen_hashes()