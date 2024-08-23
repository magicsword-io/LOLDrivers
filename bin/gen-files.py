import yaml
import os
from datetime import date
import hashlib

path_to_yml = "../yaml"
path_to_yml = os.path.join(os.path.dirname(os.path.realpath(__file__)), path_to_yml)

###############################################################################
############################ HELPER FUNCTIONS #################################
###############################################################################

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

def gen_names_list(category_):
    """
        Generates list of driver names
    """
    names_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        category = get_yaml_part(file_path=file, part_name="Category")
        driver_name = get_yaml_part(file_path=file, part_name="Tags")[0]
        if category_.lower() == category.lower():
            if driver_name:
                names_list.append(driver_name)
    
    # Remove leading and trailing spaces as well as any duplicates
    names_list = list(set([i.lstrip().strip().lower() for i in names_list]))

    return names_list

###############################################################################
############################ GENERATE HASHES LISTS##############################
###############################################################################

def gen_hashes_lists(category_):
    """
        Generates lists of hashes
    """
    md5_list = []
    sha1_list = []
    sha256_list = []
    imphash_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        category = get_yaml_part(file_path=file, part_name="Category")
        if category_.lower() == category.lower():
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
                    if 'Imphash' in i:
                        if i['Imphash'] != "-":
                            imphash_list.append(i['Imphash'])
    
    # Remove leading and trailing spaces as well as any duplicates
    md5_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in md5_list]))))
    sha1_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha1_list]))))
    sha256_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha256_list]))))
    imphash_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in imphash_list]))))

    return md5_list, sha1_list, sha256_list, imphash_list

def gen_authentihash_lists(category_):
    """
        Generates lists of authentihash
    """
    authentihash_md5_list = []
    authentihash_sha1_list = []
    authentihash_sha256_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
        category = get_yaml_part(file_path=file, part_name="Category")
        if category_.lower() == category.lower():
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

def gen_loadsdespitehvci_lists(category_):
    """
        Generates lists of hashes for LoadsDespiteHVCI being TRUE
    """
    md5_list = []
    sha1_list = []
    sha256_list = []
    imphash_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        category = get_yaml_part(file_path=file, part_name="Category")
        if category_.lower() == category.lower():
            known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
            if known_vuln_samples:
                for i in known_vuln_samples:
                    loads_despite_hvci = i.get('LoadsDespiteHVCI', 'FALSE')
                    if loads_despite_hvci == 'TRUE':
                        if 'MD5' in i and i['MD5'] != "-":
                            md5_list.append(i['MD5'])
                        if 'SHA1' in i and i['SHA1'] != "-":
                            sha1_list.append(i['SHA1'])
                        if 'SHA256' in i and i['SHA256'] != "-":
                            sha256_list.append(i['SHA256'])
                        if 'Imphash' in i and i['Imphash'] != "-":
                            imphash_list.append(i['Imphash'])

    md5_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in md5_list]))))
    sha1_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha1_list]))))
    sha256_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in sha256_list]))))
    imphash_list = list(filter(None,list(set([i.lstrip().strip().lower() for i in imphash_list]))))

    return md5_list, sha1_list, sha256_list, imphash_list


def gen_loadsdespitehvci_authentihash_lists(category_):
    """
        Generates lists of authentihash of samples that load despite hvci
    """
    authentihash_md5_list = []
    authentihash_sha1_list = []
    authentihash_sha256_list = []
    for file in yield_next_rule_file_path(path_to_yml):
        known_vuln_samples = get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
        category = get_yaml_part(file_path=file, part_name="Category")
        if category_.lower() == category.lower():
            if known_vuln_samples:
                for i in known_vuln_samples:
                    loads_despite_hvci = i.get('LoadsDespiteHVCI', 'FALSE')
                    if loads_despite_hvci == 'TRUE':
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


###############################################################################
############################ GENERATE SAMPLE FILES ############################
###############################################################################

def gen_hashes_files(md5_list, sha1_list, sha256_list, imphash_list, name):
    """
        Generates hash samples files
    """
    directory = 'detections/hashes/'
    os.makedirs(directory, exist_ok=True)  # Create the directory if it doesn't exist
    
    if md5_list:
        with open(f'detections/hashes/{name}.md5', 'w') as f: 
            for i in md5_list:
                if i != "-":
                    f.write(i + "\n")
    
    if sha1_list:
        with open(f'detections/hashes/{name}.sha1', 'w') as f: 
            for i in sha1_list:
                if i != "-":
                    f.write(i + "\n")
    
    if sha256_list:
        with open(f'detections/hashes/{name}.sha256', 'w') as f:
            for i in sha256_list:
                if i != "-":
                    f.write(i + "\n")

    if imphash_list:
        with open(f'detections/hashes/{name}.imphash', 'w') as f:
            for i in imphash_list:
                if i != "-":
                    f.write(i + "\n")

    all_hashes = list(set(md5_list + sha1_list + sha256_list))
    if all_hashes:
        with open(f'detections/hashes/{name}.all', 'w') as f:
            for i in all_hashes:
                if i != "-":
                    f.write(i + "\n")

def gen_authentihash_file(authentihash_md5_list, authentihash_sha1_list, authentihash_sha256_list, name):
    """
        Generates hash samples files
    """
    
    if authentihash_md5_list:
        with open(f'detections/hashes/{name}.md5', 'w') as f: 
            for i in authentihash_md5_list:
                if i != "-":
                    f.write(i + "\n")
    
    if authentihash_sha1_list:
        with open(f'detections/hashes/{name}.sha1', 'w') as f: 
            for i in authentihash_sha1_list:
                if i != "-":
                    f.write(i + "\n")
    
    if authentihash_sha256_list:
        with open(f'detections/hashes/{name}.sha256', 'w') as f:
            for i in authentihash_sha256_list:
                if i != "-":
                    f.write(i + "\n")

    all_hashes = list(set(authentihash_md5_list + authentihash_sha1_list + authentihash_sha256_list))
    if all_hashes:
        with open(f'detections/hashes/{name}.all', 'w') as f:
            for i in all_hashes:
                if i != "-":
                    f.write(i + "\n")

###############################################################################
############################ GENERATE SYSMON CONFIGS ##########################
###############################################################################

def gen_sysmon_driver_load_config(md5_list, sha1_list, sha256_list, imphash_list, name, rule_group_name):
    """
        Generates sysmon driver load configuration
    """
    directory = 'detections/sysmon/'
    os.makedirs(directory, exist_ok=True)  # Create the directory if it doesn't exist

    with open(f"detections/sysmon/{name}.xml", "w") as f:
        f.write("<Sysmon schemaversion=\"4.30\">\n")
        f.write("	<EventFiltering>\n")
        f.write("		<RuleGroup name=\"%s\" groupRelation=\"or\">\n" % rule_group_name)
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

        if imphash_list:
            for i in imphash_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">IMPHASH=" + i + "</Hashes>\n")

        f.write("			</DriverLoad>\n")
        f.write("		</RuleGroup>\n")
        f.write("	</EventFiltering>\n")
        f.write("</Sysmon>\n")

def gen_sysmon_block_config(md5_list, sha1_list, sha256_list, imphash_list, name, rule_group_name):
    """
        Generates sysmon blocking configuration
    """
    with open(f"detections/sysmon/{name}.xml", "w") as f:
        f.write("<Sysmon schemaversion=\"4.82\">\n")
        f.write("	<EventFiltering>\n")
        f.write("		<RuleGroup name=\"%s\" groupRelation=\"or\">\n" % rule_group_name)
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
        
        if imphash_list:
            for i in imphash_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">IMPHASH=" + i + "</Hashes>\n")

        f.write("			</FileBlockExecutable>\n")
        f.write("		</RuleGroup>\n")
        f.write("	</EventFiltering>\n")
        f.write("</Sysmon>\n")

def gen_sysmon_exe_detect_config(md5_list, sha1_list, sha256_list, imphash_list, name, rule_group_name):
    """
        Generates sysmon executable detection configuration
    """
    with open(f"detections/sysmon/{name}.xml", "w") as f:
        f.write("<Sysmon schemaversion=\"4.82\">\n")
        f.write("	<EventFiltering>\n")
        f.write("		<RuleGroup name=\"%s\" groupRelation=\"or\">\n" % rule_group_name)
        f.write("			<FileExecutableDetected onmatch=\"include\">\n")

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
        
        if imphash_list:
            for i in imphash_list:
                if i != "-":
                    f.write("                <Hashes condition=\"contains\">IMPHASH=" + i + "</Hashes>\n")

        f.write("			</FileExecutableDetected>\n")
        f.write("		</RuleGroup>\n")
        f.write("	</EventFiltering>\n")
        f.write("</Sysmon>\n")

###############################################################################
############################ GENERATE SIGMA RULES #############################
###############################################################################

def gen_sigma_rule_hashes(md5_list, sha1_list, sha256_list, imphash_list, name, uuid, title, description):
    """
        Generates DriverLoad SIGMA rule based on driver hashes
    """
    directory = 'detections/sigma/'
    os.makedirs(directory, exist_ok=True)  # Create the directory if it doesn't exist
    if md5_list or sha1_list or sha256_list:
        with open(f"detections/sigma/{name}.yml", "w") as f:
            f.write(f"title: {title}\n")
            f.write(f"id: {uuid}\n")
            f.write("status: experimental\n")
            f.write(f"description: {description}\n")
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
            f.write("    selection:\n")
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
            
            if imphash_list:
                for i in imphash_list:
                    f.write("            - 'IMPHASH=" + i + "'\n")

            f.write("    condition: selection\n")
            f.write("falsepositives:\n")
            f.write("    - Unknown\n")
            f.write("level: high\n")

def gen_sigma_rule_names(names_list, uuid, rule_name, rule_title, description, level):
    """
        Generates DriverLoad SIGMA rule based on driver names
    """
    if names_list:
        with open(f"detections/sigma/{rule_name}.yml", "w") as f:
            f.write(f"title: {rule_title}\n")
            f.write(f"id: {uuid}\n")
            f.write("status: experimental\n")
            f.write(f"description: {description}.\n")
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
            f.write(f"level: {level}\n")

###############################################################################
############################ GENERATE CLAMAV CONFIG ############################
###############################################################################

def gen_clamav_hash_list():
    """
    Generates ClamAV hash list in the format sha256_hash:filesize:signature_name.
    """
    drivers_path = 'drivers/' 
    output_dir = 'detections/av/'
    os.makedirs(output_dir, exist_ok=True)  # Create the directory if it doesn't exist
    hdb_file = os.path.join(output_dir, 'LOLDrivers.hdb')

    
    with open(hdb_file, 'w') as hdb:
        for root, _, files in os.walk(drivers_path):
            for file in files:
                if file.endswith('.bin'):
                    full_path = os.path.join(root, file)
                    with open(full_path, 'rb') as f:
                        data = f.read()
                        sha256_hash = hashlib.sha256(data).hexdigest()
                        filesize = os.path.getsize(full_path)
                        hdb.write(f'{sha256_hash}:{filesize}:{file}\n')

if __name__ == "__main__":
    
    #################### GOOTS LOVER ##############################################

    ###############################################################################
    ###################### GENERATING LISTS OF HASHES #############################
    ###############################################################################

    print("[+] Generating hash lists...")
    md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious = gen_hashes_lists("malicious")
    md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable = gen_hashes_lists("vulnerable driver")

    print("[+] Generating authentihash lists...")
    authentihash_md5_list_malicious, authentihash_sha1_list_malicious, authentihash_sha256_list_malicious = gen_authentihash_lists("malicious")
    authentihash_md5_list_vulnerable, authentihash_sha1_list_vulnerable, authentihash_sha256_list_vulnerable = gen_authentihash_lists("vulnerable driver")

    print("[+] Generating hvci load hash lists...")
    hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious = gen_loadsdespitehvci_lists("malicious")
    hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable = gen_loadsdespitehvci_lists("vulnerable driver")

    print("[+] Generating hvci load authentihash lists...")
    hvci_authentihash_md5_list_malicious, hvci_authentihash_sha1_list_malicious, hvci_authentihash_sha256_list_malicious = gen_loadsdespitehvci_authentihash_lists("malicious")
    hvci_authentihash_md5_list_vulnerable, hvci_authentihash_sha1_list_vulnerable, hvci_authentihash_sha256_list_vulnerable = gen_loadsdespitehvci_authentihash_lists("vulnerable driver")

    ###############################################################################
    ############################ GENERATING SAMPLES FILES #########################
    ###############################################################################

    # To generate a new list of hashes simply provide a list and the name of the file

    print("[+] Generating hash samples...")
    gen_hashes_files(md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable, "samples_vulnerable")
    gen_hashes_files(md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious, "samples_malicious")

    print("[+] Generating LoadsDespiteHVCI hash lists...")
    gen_hashes_files(hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable, "LoadsDespiteHVCI.samples_vulnerable")
    gen_hashes_files(hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious, "LoadsDespiteHVCI.samples_malicious")

    print("[+] Generating authentihash samples...")
    gen_authentihash_file(authentihash_md5_list_vulnerable, authentihash_sha1_list_vulnerable, authentihash_sha256_list_vulnerable, "authentihash_samples_vulnerable")
    gen_authentihash_file(authentihash_md5_list_malicious, authentihash_sha1_list_malicious, authentihash_sha256_list_malicious, "authentihash_samples_malicious")
    
    print("[+] Generating hvci load authentihash samples...")
    gen_authentihash_file(hvci_authentihash_md5_list_vulnerable, hvci_authentihash_sha1_list_vulnerable, hvci_authentihash_sha256_list_vulnerable, "LoadsDespiteHVCI.authentihash_samples_vulnerable")
    gen_authentihash_file(hvci_authentihash_md5_list_malicious, hvci_authentihash_sha1_list_malicious, hvci_authentihash_sha256_list_malicious, "LoadsDespiteHVCI.authentihash_samples_malicious")


    ###############################################################################
    ############################ GENERATING CLAMAV CONFIGS ########################
    ###############################################################################

    gen_clamav_hash_list()


    ###############################################################################
    ############################ GENERATING SYSMON CONFIGS ########################
    ###############################################################################
    
    print("[+] Generating Sysmon configurations for all samples...")

    # sysmon_config_vulnerable_hashes
    gen_sysmon_driver_load_config(md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable, "sysmon_config_vulnerable_hashes", "Vulnerable Driver Load")
    gen_sysmon_driver_load_config(md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious, "sysmon_config_malicious_hashes", "Malicious Driver Load")
    
    # sysmon_config_vulnerable_hashes_block
    gen_sysmon_block_config(md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable, "sysmon_config_vulnerable_hashes_block", "Vulnerable Driver Blocked")
    gen_sysmon_block_config(md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious, "sysmon_config_malicious_hashes_block", "Malicious Driver Blocked")

    # sysmon_config_vulnerable_hashes_exe_detect
    gen_sysmon_exe_detect_config(md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable, "sysmon_config_vulnerable_hashes_exe_detect", "Vulnerable Driver Drop Detected")
    gen_sysmon_exe_detect_config(md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious, "sysmon_config_malicious_hashes_exe_detect", "Malicious Driver Drop Detected")
    
    print("[+] Generating Sysmon configurations for samples that load despite HVCI...")

    # sysmon_config_vulnerable_hashes_hvci
    gen_sysmon_driver_load_config(hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable, "sysmon_config_vulnerable_hashes_hvci", "Vulnerable Driver Load")
    gen_sysmon_driver_load_config(hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious, "sysmon_config_malicious_hashes_hvci", "Malicious Driver Load")
    
    # sysmon_config_vulnerable_hashes_block_hvci
    gen_sysmon_block_config(hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable, "sysmon_config_vulnerable_hashes_block_hvci", "Vulnerable Driver Blocked")
    gen_sysmon_block_config(hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious, "sysmon_config_malicious_hashes_block_hvci", "Malicious Driver Blocked")

   # sysmon_config_vulnerable_hashes_exe_detect_hvci
    gen_sysmon_exe_detect_config(hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable, "sysmon_config_vulnerable_hashes_exe_detect_hvci", "Vulnerable Driver Drop Detected")
    gen_sysmon_exe_detect_config(hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious, "sysmon_config_malicious_hashes_exe_detect_hvci", "Malicious Driver Drop Detected")
    
    ###############################################################################
    ############################ GENERATING SIGMA RULES ###########################
    ###############################################################################

    names_list_malicious = gen_names_list("malicious")
    names_list_vulnerable = gen_names_list("vulnerable driver")

    print("[+] Generating Sigma rules...")
    
    # All Samples
    gen_sigma_rule_hashes(md5_list_vulnerable, sha1_list_vulnerable, sha256_list_vulnerable, imphash_list_vulnerable, "driver_load_win_vuln_drivers", "7aaaf4b8-e47c-4295-92ee-6ed40a6f60c8", "Vulnerable Driver Load", "Detects loading of known vulnerable driver via their hash.")
    gen_sigma_rule_hashes(md5_list_malicious, sha1_list_malicious, sha256_list_malicious, imphash_list_malicious, "driver_load_win_mal_drivers", "05296024-fe8a-4baf-8f3d-9a5f5624ceb2", "Malicious Driver Load", "Detects loading of known malicious drivers via their hash.")
    
    # Load Despite HVCI
    gen_sigma_rule_hashes(hvci_md5_list_vulnerable, hvci_sha1_list_vulnerable, hvci_sha256_list_vulnerable, hvci_imphash_list_vulnerable, "driver_load_win_vuln_drivers_hvci_load", "45b4716d-9845-463c-83d9-24c9652832ce", "Vulnerable Driver Load Despite HVCI", "Detects loading of known vulnerable driver via their hash whether or not HVCI (Hypervisor Code Integrity) is enabled.")
    gen_sigma_rule_hashes(hvci_md5_list_malicious, hvci_sha1_list_malicious, hvci_sha256_list_malicious, hvci_imphash_list_malicious, "driver_load_win_mal_drivers_hvci_load", "bd17303b-1003-437e-93e4-97f79c03aeb3", "Malicious Driver Load Despite HVCI", "Detects loading of known malicious drivers via their hash whether or not HVCI (Hypervisor Code Integrity) is enabled.")
    
    gen_sigma_rule_names(names_list_vulnerable, "72cd00d6-490c-4650-86ff-1d11f491daa1", "driver_load_win_vuln_drivers_names", "Vulnerable Driver Load By Name", "Detects loading of known vulnerable drivers via the file name of the drivers.", "low")
    gen_sigma_rule_names(names_list_malicious, "39b64854-5497-4b57-a448-40977b8c9679", "driver_load_win_mal_drivers_names", "Malicious Driver Load By Name", "Detects loading of known malicious drivers via the file name of the drivers.", "medium")

    print("[+] Finished...Happy Hunting")
