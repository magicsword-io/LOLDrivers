import yaml
import os
from datetime import date
import hashlib
import uuid

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

def _sanitize_rule_slug(value):
    if not value:
        return "unknown"
    allowed = []
    for ch in value.lower():
        if ch.isalnum():
            allowed.append(ch)
        else:
            allowed.append("_")
    slug = "".join(allowed).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug or "unknown"

def _normalize_date(value):
    if not value:
        return date.today().strftime('%Y/%m/%d')
    value = str(value).strip()
    if "-" in value:
        return value.replace("-", "/")
    return value

def _extract_driver_description(commands, known_samples):
    description = ""
    if isinstance(commands, dict):
        description = commands.get("Description") or ""
    elif isinstance(commands, list) and commands:
        for entry in commands:
            if isinstance(entry, dict) and entry.get("Description"):
                description = entry.get("Description")
                break
    if description:
        return str(description).strip()
    for sample in known_samples or []:
        sample_desc = sample.get("Description")
        if sample_desc:
            sample_desc = str(sample_desc).strip()
            if sample_desc:
                return sample_desc
    return ""

def _stable_rule_id(seed_base, rule_type):
    seed = f"loldrivers:sigma:per-driver:{seed_base}:{rule_type}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

def _collect_driver_hashes(known_samples):
    md5_list = []
    sha1_list = []
    sha256_list = []
    imphash_list = []
    for sample in known_samples or []:
        md5 = sample.get('MD5')
        sha1 = sample.get('SHA1')
        sha256 = sample.get('SHA256')
        imphash = sample.get('Imphash')
        if md5 and md5 != "-":
            md5_list.append(md5.lower())
        if sha1 and sha1 != "-":
            sha1_list.append(sha1.lower())
        if sha256 and sha256 != "-":
            sha256_list.append(sha256.lower())
        if imphash and imphash != "-":
            imphash_list.append(imphash.lower())
    return (
        list(filter(None, list(set(md5_list)))),
        list(filter(None, list(set(sha1_list)))),
        list(filter(None, list(set(sha256_list)))),
        list(filter(None, list(set(imphash_list)))),
    )

def gen_sigma_rule_per_driver(file_path):
    yaml_id = get_yaml_part(file_path=file_path, part_name="Id")
    category = get_yaml_part(file_path=file_path, part_name="Category") or "unknown"
    tags = get_yaml_part(file_path=file_path, part_name="Tags") or []
    driver_name = tags[0] if tags else None
    author = get_yaml_part(file_path=file_path, part_name="Author") or "Unknown"
    created = get_yaml_part(file_path=file_path, part_name="Created")
    resources = get_yaml_part(file_path=file_path, part_name="Resources") or []
    commands = get_yaml_part(file_path=file_path, part_name="Commands")
    known_samples = get_yaml_part(file_path=file_path, part_name="KnownVulnerableSamples") or []
    md5_list, sha1_list, sha256_list, imphash_list = _collect_driver_hashes(known_samples)

    if not driver_name and not (md5_list or sha1_list or sha256_list or imphash_list):
        return False

    category_value = (category or "").lower()
    if category_value == "malicious":
        category_code = "win_mal"
        category_slug = "malicious"
    else:
        category_code = "win_vuln"
        category_slug = "vulnerable"

    name_for_slug = driver_name or yaml_id or "unknown"
    if driver_name:
        trimmed = driver_name.strip()
        if trimmed.lower().endswith(".sys"):
            trimmed = trimmed[:-4]
        name_for_slug = trimmed or name_for_slug

    rule_slug = _sanitize_rule_slug(name_for_slug)[:20]
    if not rule_slug:
        rule_slug = "unknown"
    rule_suffix = (yaml_id or rule_slug)[:8]
    if driver_name:
        rule_name = f"driver_load_{category_code}_{rule_slug}"
    else:
        rule_name = f"driver_load_{category_code}_{rule_slug}_{rule_suffix}"

    is_malicious = category_value == "malicious"
    level_hash = "high"
    level_name = "medium" if is_malicious else "low"

    display_name = driver_name or rule_slug
    driver_description = _extract_driver_description(commands, known_samples)

    references = []
    if yaml_id:
        references.append(f"https://www.loldrivers.io/drivers/{yaml_id}/")
    if isinstance(resources, list):
        for ref in resources:
            if ref:
                references.append(ref)

    tags = [
        "attack.privilege_escalation",
        "attack.t1543.003",
        "attack.t1068",
        f"loldrivers.{category_slug}",
    ]

    def _write_rule(output_name, title, rule_id, description_text, detection_lines, condition, rule_level):
        with open(f"{directory}{output_name}.yml", "w") as f:
            f.write(f"title: {title}\n")
            if rule_id:
                f.write(f"id: {rule_id}\n")
            f.write("status: experimental\n")
            f.write("description: |\n")
            for line in description_text.splitlines():
                f.write("    " + line + "\n")
            f.write("references:\n")
            for ref in references:
                f.write(f"    - {ref}\n")
            f.write(f"author: {author}\n")
            f.write("date: " + _normalize_date(created) + "\n")
            f.write("modified: " + date.today().strftime('%Y/%m/%d') + "\n")
            f.write("tags:\n")
            for tag in tags:
                f.write(f"    - {tag}\n")
            f.write("logsource:\n")
            f.write("    product: windows\n")
            f.write("    category: driver_load\n")
            f.write("detection:\n")
            for line in detection_lines:
                f.write(line + "\n")
            f.write(f"    condition: {condition}\n")
            f.write("falsepositives:\n")
            f.write("    - Unknown\n")
            f.write(f"level: {rule_level}\n")

    has_hashes = bool(md5_list or sha1_list or sha256_list or imphash_list)
    has_name = bool(driver_name)

    seed_base = yaml_id or os.path.basename(file_path) or rule_name
    def _make_description(mode_label):
        base = f"Detects loading of driver {display_name} via {mode_label}."
        return f"{base}\n{driver_description}" if driver_description else base

    def _build_hash_lines():
        lines = ["    selection_hashes:", "        Hashes|contains:"]
        for label, items in (
            ("MD5", md5_list),
            ("SHA1", sha1_list),
            ("SHA256", sha256_list),
            ("IMPHASH", imphash_list),
        ):
            for item in items:
                lines.append(f"            - '{label}={item}'")
        return lines

    def _build_name_lines():
        normalized_name = driver_name.strip().lower()
        if not normalized_name.startswith("\\"):
            normalized_name = "\\" + normalized_name
        return [
            "    selection_name:",
            "        ImageLoaded|endswith:",
            f"            - '{normalized_name}'",
        ]

    if has_hashes:
        _write_rule(
            rule_name,
            f"Driver Load - {display_name}",
            _stable_rule_id(seed_base, "hash"),
            _make_description("hash"),
            _build_hash_lines(),
            "selection_hashes",
            level_hash,
        )

    if has_name:
        _write_rule(
            f"{rule_name}_names",
            f"Driver Load - {display_name}",
            _stable_rule_id(seed_base, "name"),
            _make_description("name"),
            _build_name_lines(),
            "selection_name",
            level_name,
        )

    return has_hashes or has_name

def gen_sigma_rules_per_driver():
    output_dir = 'detections/sigma-per-driver/'
    os.makedirs(output_dir, exist_ok=True)
    for entry in os.listdir(output_dir):
        entry_path = os.path.join(output_dir, entry)
        if os.path.isfile(entry_path):
            os.unlink(entry_path)
    generated = 0
    for file in yield_next_rule_file_path(path_to_yml):
        if gen_sigma_rule_per_driver(file):
            generated += 1
    print(f"[+] Generated {generated} per-driver Sigma rules.")

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

    gen_sigma_rules_per_driver()

    print("[+] Finished...Happy Hunting")
