import glob
import yaml
import argparse
import sys
import re
import os
import json
import datetime
import jinja2
from stix2 import FileSystemSource, Filter


def get_mitre_enrichment_new(attack, mitre_attack_id):
    for technique in attack:
        if mitre_attack_id == technique["external_references"][0]["external_id"]:
            mitre_attack = mitre_attack_object(technique, attack)
            return mitre_attack
    return []

def get_all_techniques(projects_path):
    path_cti = os.path.join(projects_path,'cti/enterprise-attack')
    fs = FileSystemSource(path_cti)
    all_techniques = get_techniques(fs)
    return all_techniques

def get_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)

def mitre_attack_object(technique, attack):
    mitre_attack = dict()
    mitre_attack['technique_id'] = technique["external_references"][0]["external_id"]
    mitre_attack['technique'] = technique["name"]
    mitre_attack['technique_description'] = technique['description']

    # process tactics
    tactics = []
    if 'kill_chain_phases' in technique:
        for tactic in technique['kill_chain_phases']:
            if tactic['kill_chain_name'] == 'mitre-attack':
                tactic = tactic['phase_name'].replace('-', ' ')
                tactics.append(tactic.title())

    mitre_attack['tactic'] = tactics
    return mitre_attack

def generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in os.walk(REPO_PATH):
        for file in files:
            if file.endswith(".yaml"):
                if VERBOSE:
                    messages.append("reading yaml: {0}".format(file))
                manifest_files.append((os.path.join(root, file)))

    drivers = []
    for manifest_file in manifest_files:
        driver = dict()
        if VERBOSE:
            print("processing driver {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        driver = object

        # enrich the mitre object
        mitre_attacks = []
        driver['mitre_attack'] = get_mitre_enrichment_new(attack, driver['MitreID'])

        drivers.append(driver)
    print(TEMPLATE_PATH)
    j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH), trim_blocks=False, autoescape=True, lstrip_blocks=True)
    # write markdown for atomics
    d = datetime.datetime.now()
    template = j2_env.get_template('driver.md.j2')
    for driver in drivers:
        file_name = os.path.splitext(driver["Name"])[0] + '.md'
        output_path = os.path.join(OUTPUT_DIR + '/content/drivers/' + file_name)
        #print(json.dumps(atomic, indent=4))
        output = template.render(driver=driver, time=str(d.strftime("%Y-%m-%d")))
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("site_gen.py wrote {0} driver documentation to: {1}".format(len(drivers),OUTPUT_DIR + '/content/drivers/'))

    return drivers, messages


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates Atomic Red Team Discovery page", epilog="""
    This tool converts all Atomic Red Team atomic yamls into the Atomic Red Team Discovery page.""")
    parser.add_argument("-p", "--path", required=False, default="yaml", help="path to loldriver yaml folder. Defaults to `yaml`")
    parser.add_argument("-o", "--output", required=False, default="loldrivers.io", help="path to the output directory for the site, defaults to `loldrivers.io`")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose


    TEMPLATE_PATH = os.path.join(REPO_PATH, '../bin/jinja2_templates')
    if VERBOSE:
        print("getting mitre enrichment data from cti")
    techniques = get_all_techniques('.')

    if VERBOSE:
        print("wiping the {0}/content/drivers/ folder".format(OUTPUT_DIR))

   # try:
   #     for root, dirs, files in walk(OUTPUT_DIR + '/content/drivers/'):
   #         for file in files:
   #             if file.endswith(".md") and not file == '_index.md':
   #                 remove(OUTPUT_DIR + '/content/drivers/' + file)
   # except OSError as e:
   #     print("error: %s : %s" % (file, e.strerror))
   #     sys.exit(1)

    messages = []
    drivers, messages = generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, techniques, messages, VERBOSE)

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
