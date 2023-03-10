import glob
import yaml
import argparse
import sys
import re
import os
import json
import datetime
import jinja2
import csv

def generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE):
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
        drivers.append(object)

    # write markdowns
    j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH), trim_blocks=False, autoescape=True, lstrip_blocks=True)
    d = datetime.datetime.now()
    template = j2_env.get_template('driver.md.j2')
    for driver in drivers:
        file_name = os.path.splitext(driver["Name"])[0] + '.md'
        output_path = os.path.join(OUTPUT_DIR + '/content/drivers/' + file_name)
        output = template.render(driver=driver, time=str(d.strftime("%Y-%m-%d")))
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("site_gen.py wrote {0} drivers markdown to: {1}".format(len(drivers),OUTPUT_DIR + '/content/drivers/'))

    # write api csv
    with open(OUTPUT_DIR + '/content/api/' + 'drivers.csv', 'w') as f:
        writer = csv.writer(f)

        # header
        writer.writerow(['Name','Author','Created','Command','Description','Usecase','Category','Privileges','MitreID','OperatingSystem','Resources','Driver Description','Person' \
                         ,'Handle','Detection','KnownHashes','Binary','Verified','Date','Publisher','Company','Description','Product','Product Version','File Version','Machine Type','Original Filename'])

        # write rows

        for driver in drivers:
            #get hashes
            hashes = []
            for s in driver['KnownVulnerableSamples']:
                hashes.append(s['SHA256'])
            # get link
            link = '[' + driver['Name'] + '](drivers/' + os.path.splitext(driver["Name"])[0].lower() + '/)'
            writer.writerow([link, driver['Author'], driver['Created'], driver['Commands']['Command'], driver['Commands']['Description'], driver['Commands']['Usecase'], driver['Category'], \
                             driver['Commands']['Privileges'],driver['MitreID'],driver['Commands']['OperatingSystem'],driver['Resources'],driver['driver_description'],driver['Acknowledgement']['Person'] \
                             ,driver['Acknowledgement']['Handle'],driver['Detection'],hashes,driver['Metadata']['binary'],driver['Metadata']['Verified'],driver['Metadata']['Date'], \
                                driver['Metadata']['Publisher'],driver['Metadata']['Company'],driver['Metadata']['Description'],driver['Metadata']['Product'],driver['Metadata']['ProductVersion'], \
                                    driver['Metadata']['FileVersion'],driver['Metadata']['MachineType'],driver['Metadata']['OriginalFilename']])


    # write api json
    with open(OUTPUT_DIR + '/content/api/' + 'drivers.json', 'w', encoding='utf-8') as f:
        json.dump(drivers, f, ensure_ascii=False, indent=4)

    # write listing csv
    with open(OUTPUT_DIR + '/content/' + 'drivers_table.csv', 'w') as f:
        writer = csv.writer(f)
        for driver in drivers:
            link = '[' + driver['Name'] + '](drivers/' + os.path.splitext(driver["Name"])[0].lower() + '/)'
            writer.writerow([link, driver['Author'], driver['Created'], driver['Commands']['Command']])

    # write top 10 publishers
    publishers = []
    counted_publishers = []

    # write top 10 publishers
    all_publishers = []
    # counted_publishers = []
    for driver in drivers:
        if driver['Metadata']['Publisher']:
            p = dict()
            p['name'] = driver['Name']
            p['publisher'] = driver['Metadata']['Publisher']
            all_publishers.append(p)


    for driver in drivers:
        if driver['Metadata']['Publisher']:
            if driver['Metadata']['Publisher'] in publishers:
                pass
            else:
                publishers.append(driver['Metadata']['Publisher'])

    for p in publishers:
        count = 0
        for driver in drivers:
            if p == driver['Metadata']['Publisher']:
                count += 1
        publisher = dict()
        publisher['name'] = p
        publisher['count'] = count
        counted_publishers.append(publisher)

    counted_sorted_publishers_top_10 = sorted(counted_publishers, key = lambda x : x['count'], reverse = True)[:10]



    with open(OUTPUT_DIR + '/content/' + 'drivers_top_10_publishers.csv', 'w') as f:
        writer = csv.writer(f)
        for p in counted_sorted_publishers_top_10:
            for i in range(p['count']): 
                writer.writerow([p['count'], p['name']])

    return drivers, messages


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates loldrivers.io site", epilog="""
    This tool converts all loldrivers.io yamls and builds the site with all the supporting components.""")
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
        print("wiping the {0}/content/drivers/ folder".format(OUTPUT_DIR))

    # first clean up old drivers
    try:
        for root, dirs, files in os.walk(OUTPUT_DIR + '/content/drivers/'):
            for file in files:
                if file.endswith(".md") and not file == '_index.md':
                    os.remove(root + '/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)


    # also clean up API artifacts
    if os.path.exists(OUTPUT_DIR + '/content/api/drivers.json'):
        os.remove(OUTPUT_DIR + '/content/api/drivers.json')         
    if os.path.exists(OUTPUT_DIR + '/content/api/drivers.csv'):        
        os.remove(OUTPUT_DIR + '/content/api/drivers.csv')


    messages = []
    drivers, messages = generate_doc_drivers(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, messages, VERBOSE)

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
