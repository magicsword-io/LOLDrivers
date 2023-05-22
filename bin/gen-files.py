import yaml
import os
from datetime import date


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

def gen_names_list():
    """
        Generates list of driver names
    """
    names_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        driver_name = get_yaml_part(file_path=file, part_name="Tags")[0]
        if driver_name:
            names_list.append(driver_name)
    
    # Remove leading and trailing spaces as well as any duplicates
    names_list = list(set([i.lstrip().strip().lower() for i in names_list]))

    return names_list

def gen_hashes_lists():
    """
        Generates lists of hashes
    """
    md5_list = []
    sha1_list = []
    sha256_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
        if known_vuln_samples:
            for i in known_vuln_samples:
                if 'MD5' in i:
                    if i['MD5'] != "-":
                        md5_list.append(i['MD5'])
                if 'SHA1' in i:
                    if i['SHA1'] != "-":
                        sha1_list.append(i['SHA1'])
                if 'SHA256' in i:
                    if i['SHA256'] != "-":
                        sha256_list.append(i['SHA256'])
    
    # Remove leading and trailing spaces as well as any duplicates
    md5_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in md5_list]))))
    sha1_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha1_list]))))
    sha256_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha256_list]))))

    return md5_list, sha1_list, sha256_list

def gen_authentihash_lists():
    """
        Generates lists of authentihash
    """
    authentihash_md5_list = []
    authentihash_sha1_list = []
    authentihash_sha256_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
        if known_vuln_samples:
            for i in known_vuln_samples:
                if 'Authentihash' in i:
                    for key, value in i['Authentihash'].items():
                        if key == "MD5" and value != "-":
                            authentihash_md5_list.append(value)
                        if key == "SHA1" and value != "-":
                            if i['SHA1'] != "-":
                                authentihash_sha1_list.append(value)
                        if key == "SHA256" and value != "-":
                            if i['SHA256'] != "-":
                                authentihash_sha256_list.append(value)
    
    # Remove leading and trailing spaces as well as any duplicates
    authentihash_md5_list = list(set([i.lstrip().strip().lower() for i in authentihash_md5_list]))
    authentihash_sha1_list = list(set([i.lstrip().strip().lower() for i in authentihash_sha1_list]))
    authentihash_sha256_list = list(set([i.lstrip().strip().lower() for i in authentihash_sha256_list]))

    return authentihash_md5_list, authentihash_sha1_list, authentihash_sha256_list

def gen_hashes_files(md5_list, sha1_list, sha256_list):
    """
        Generates hash samples files
    """
    
    if md5_list:
        with open('detections/hashes/samples.md5', 'w') as f: 
            for i in md5_list:
                if i != "-":
                    f.write(i + "\n")
    
    if sha1_list:
        with open('detections/hashes/samples.sha1', 'w') as f: 
            for i in sha1_list:
                if i != "-":
                    f.write(i + "\n")
    
    if sha256_list:
        with open('detections/hashes/samples.sha256', 'w') as f:
            for i in sha256_list:
                if i != "-":
                    f.write(i + "\n")

    all_hashes = list(set(md5_list + sha1_list + sha256_list))
    if all_hashes:
        with open('detections/hashes/samples.all', 'w') as f:
            for i in all_hashes:
                if i != "-":
                    f.write(i + "\n")

def gen_authentihash_file(authentihash_md5_list, authentihash_sha1_list, authentihash_sha256_list):
    """
        Generates hash samples files
    """
    
    if authentihash_md5_list:
        with open('detections/hashes/authentihash_samples.md5', 'w') as f: 
            for i in authentihash_md5_list:
                if i != "-":
                    f.write(i + "\n")
    
    if authentihash_sha1_list:
        with open('detections/hashes/authentihash_samples.sha1', 'w') as f: 
            for i in authentihash_sha1_list:
                if i != "-":
                    f.write(i + "\n")
    
    if authentihash_sha256_list:
        with open('detections/hashes/authentihash_samples.sha256', 'w') as f:
            for i in authentihash_sha256_list:
                if i != "-":
                    f.write(i + "\n")

    all_hashes = list(set(authentihash_md5_list + authentihash_sha1_list + authentihash_sha256_list))
    if all_hashes:
        with open('detections/hashes/authentihash_samples.all', 'w') as f:
            for i in all_hashes:
                if i != "-":
                    f.write(i + "\n")

def gen_sysmon_driver_load_config(md5_list, sha1_list, sha256_list):
    """
        Generates sysmon driver load configuration
    """
    with open("detections/sysmon/sysmon_config_vulnerable_hashes.xml", "w") as f:
        f.write("<Sysmon schemaversion=\"4.30\">\n")
        f.write("	<EventFiltering>\n")
        f.write("		<RuleGroup name=\"\" groupRelation=\"or\">\n")
        f.write("			<DriverLoad onmatch=\"include\">\n")

        if md5_list:
            for i in md5_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">MD5=" + i + "</Hashes>\n")
        
        if sha1_list:
            for i in sha1_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">SHA1=" + i + "</Hashes>\n")
        
        if sha256_list:
            for i in sha256_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">SHA256=" + i + "</Hashes>\n")

        f.write("			</DriverLoad>\n")
        f.write("		</RuleGroup>\n")
        f.write("	</EventFiltering>\n")
        f.write("</Sysmon>\n")

def gen_sysmon_block_config(md5_list, sha1_list, sha256_list):
    """
        Generates sysmon blocking configuration
    """
    with open("detections/sysmon/sysmon_config_vulnerable_hashes_block.xml", "w") as f:
        f.write("<Sysmon schemaversion=\"4.82\">\n")
        f.write("	<EventFiltering>\n")
        f.write("		<RuleGroup name=\"\" groupRelation=\"or\">\n")
        f.write("			<FileBlockExecutable onmatch=\"include\">\n")

        if md5_list:
            for i in md5_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">MD5=" + i + "</Hashes>\n")
        
        if sha1_list:
            for i in sha1_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">SHA1=" + i + "</Hashes>\n")
        
        if sha256_list:
            for i in sha256_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">SHA256=" + i + "</Hashes>\n")

        f.write("			</FileBlockExecutable>\n")
        f.write("		</RuleGroup>\n")
        f.write("	</EventFiltering>\n")
        f.write("</Sysmon>\n")

def gen_sigma_rule_hashes(md5_list, sha1_list, sha256_list):
    """
        Generates DriverLoad SIGMA rule based on driver hashes
    """
    if md5_list or sha1_list or sha256_list:
        with open("detections/sigma/driver_load_win_vuln_drivers.yml", "w") as f:
            f.write("title: Vulnerable Driver Load\n")
            f.write("id: 7aaaf4b8-e47c-4295-92ee-6ed40a6f60c8\n")
            f.write("status: experimental\n")
            f.write("description: Detects the load of known vulnerable drivers by hash value\n")
            f.write("references:\n")
            f.write("    - https://loldrivers.io/\n")
            f.write("author: Nasreddine Bencherchali (Nextron Systems)\n")
            f.write("date: 2022/08/18\n")
            f.write("modified: " + date.today().strftime('%Y/%m/%d') + "\n")
            f.write("tags:\n")
            f.write("    - attack.privilege_escalation\n")
            f.write("    - attack.t1543.003\n")
            f.write("    - attack.t1068\n")
            f.write("logsource:\n")
            f.write("    product: windows\n")
            f.write("    category: driver_load\n")
            f.write("detection:\n")
            f.write("    selection_sysmon:\n")
            f.write("        Hashes|contains:\n")

            if md5_list:
                for i in md5_list:
                    f.write("            - 'MD5=" + i + "'\n")
            
            if sha1_list:
                for i in sha1_list:
                    f.write("            - 'SHA1=" + i + "'\n")
            
            if sha256_list:
                for i in sha256_list:
                    f.write("            - 'SHA256=" + i + "'\n")
            
            f.write("    selection_other:\n")

            if md5_list:
                f.write("        - md5:\n")
                for i in md5_list:
                    f.write("            - '" + i + "'\n")
            
            if sha1_list:
                f.write("        - sha1:\n")
                for i in sha1_list:
                    f.write("            - '" + i + "'\n")
            
            if sha256_list:
                f.write("        - sha256:\n")
                for i in sha256_list:
                    f.write("            - '" + i + "'\n")

            f.write("    condition: 1 of selection_*\n")
            f.write("falsepositives:\n")
            f.write("    - Unknown\n")
            f.write("level: high\n")

def gen_sigma_rule_names(names_list):
    """
        Generates DriverLoad SIGMA rule based on driver names
    """
    if names_list:
        with open("detections/sigma/driver_load_win_vuln_drivers_names.yml", "w") as f:
            f.write("title: Vulnerable Driver Load By Name\n")
            f.write("id: c316eac1-f3d8-42da-ad1c-66dcec5ca787\n")
            f.write("related:\n")
            f.write("    - id: 7aaaf4b8-e47c-4295-92ee-6ed40a6f60c8\n")
            f.write("      type: derived\n")
            f.write("status: experimental\n")
            f.write("description: Detects the load of known vulnerable drivers via their names only.\n")
            f.write("references:\n")
            f.write("    - https://loldrivers.io/\n")
            f.write("author: Nasreddine Bencherchali (Nextron Systems)\n")
            f.write("date: 2022/10/03\n")
            f.write("modified: " + date.today().strftime('%Y/%m/%d') + "\n")
            f.write("tags:\n")
            f.write("    - attack.privilege_escalation\n")
            f.write("    - attack.t1543.003\n")
            f.write("    - attack.t1068\n")
            f.write("logsource:\n")
            f.write("    product: windows\n")
            f.write("    category: driver_load\n")
            f.write("detection:\n")
            f.write("    selection:\n")
            f.write("        ImageLoaded|endswith:\n")

            for i in names_list:
                f.write("            - '\\" + i + "'\n")
        
            f.write("    condition: selection\n")
            f.write("falsepositives:\n")
            f.write("    - False positives may occur if one of the vulnerable driver names mentioned above didn't change its name between versions. So always make sure that the driver being loaded is the legitimate one and the non vulnerable version.\n")
            f.write("    - If you experience a lot of FP you could comment the driver name or its exact known legitimate location (when possible)\n")
            f.write("level: low\n")
    

if __name__ == "__main__":
    md5_list, sha1_list, sha256_list = gen_hashes_lists()
    authentihash_md5_list, authentihash_sha1_list, authentihash_sha256_list = gen_authentihash_lists()
    names_list = gen_names_list()
    gen_hashes_files(md5_list, sha1_list, sha256_list)
    gen_authentihash_file(authentihash_md5_list, authentihash_sha1_list, authentihash_sha256_list)
    gen_sysmon_driver_load_config(md5_list, sha1_list, sha256_list)
    gen_sysmon_block_config(md5_list, sha1_list, sha256_list)
    gen_sigma_rule_hashes(md5_list, sha1_list, sha256_list)
    gen_sigma_rule_names(names_list)
