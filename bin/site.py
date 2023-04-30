import yaml
import argparse
import sys
import re
import os
import json
import datetime
import jinja2
import csv

def write_drivers_csv(drivers, output_dir):
    with open(os.path.join(output_dir, 'content', 'api', 'drivers.csv'), 'w') as f:
        writer = csv.writer(f)

        # header
        writer.writerow(['Id', 'Author', 'Created', 'Command', 'Description', 'Usecase', 'Category', 'Privileges', 'MitreID', 'OperatingSystem', 'Resources', 'Driver Description', 'Person',
                         'Handle', 'Detection', 'KnownVulnerableSamples_SHA256'])

        # write rows
        for driver in drivers:
            # get hashes
            hashes = [s['SHA256'] for s in driver['KnownVulnerableSamples']]

            # get link
            link = '[' + driver['Id'] + '](drivers/' + driver["Id"] + '/)'
            writer.writerow([link, driver['Author'], driver['Created'], driver['Commands']['Command'], driver['Commands']['Description'], driver['Commands']['Usecase'], driver['Category'],
                             driver['Commands']['Privileges'], driver['MitreID'], driver['Commands']['OperatingSystem'], driver['Resources'], driver['Acknowledgement']['Person'],
                             driver['Acknowledgement']['Handle'], driver['Detection'], hashes])


def write_top_products(drivers, output_dir, top_n=5):
    products_count = {}

    for driver in drivers:
        for hash_info in driver['KnownVulnerableSamples']:
            product_name = hash_info['Product']

            if not product_name:
                continue

            product_name = product_name.strip().replace(',', '')

            if product_name.lower() == 'n/a' or product_name.isspace():
                continue

            if product_name not in products_count:
                products_count[product_name] = 0

            products_count[product_name] += 1

    sorted_products = sorted(products_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

    with open(f"{output_dir}/content/drivers_top_{top_n}_products.csv", "w") as f:
        writer = csv.writer(f)

        for product, count in sorted_products:
            for _ in range(count):
                writer.writerow([count, product])

def write_top_publishers(drivers, output_dir, top_n=5):
    publishers_count = {}

    for driver in drivers:
        for hash_info in driver['KnownVulnerableSamples']:
            publisher_str = hash_info['Publisher']

            if not publisher_str:
                continue
            
            publishers = re.findall(r'\"(.*?)\"|([^,]+)', publisher_str)
            for publisher_tuple in publishers:
                publisher = next(filter(None, publisher_tuple)).strip()

                if publisher.lower() == 'n/a' or publisher.isspace() or publisher.lower() == 'ltd.':
                    continue

                if publisher not in publishers_count:
                    publishers_count[publisher] = 0

                publishers_count[publisher] += 1

    sorted_publishers = sorted(publishers_count.items(), key=lambda x: x[1], reverse=True)[:top_n]

    with open(f"{output_dir}/content/drivers_top_{top_n}_publishers.csv", "w") as f:
        writer = csv.writer(f)

        for publisher, count in sorted_publishers:
            for _ in range(count):
                writer.writerow([count, publisher])


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
    j2_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_PATH), trim_blocks=True, autoescape=True, lstrip_blocks=False)
    d = datetime.datetime.now()
    template = j2_env.get_template('driver.md.j2')
    for driver in drivers:
        file_name = driver["Id"] + '.md'
        output_path = os.path.join(OUTPUT_DIR + '/content/drivers/' + file_name)
        output = template.render(driver=driver, time=str(d.strftime("%Y-%m-%d")))
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("site_gen.py wrote {0} drivers markdown to: {1}".format(len(drivers),OUTPUT_DIR + '/content/drivers/'))

    # write api csv
    write_drivers_csv(drivers, OUTPUT_DIR)
    messages.append("site_gen.py wrote drivers CSV to: {0}".format(OUTPUT_DIR + '/content/api/drivers.csv'))

    # write api json
    with open(OUTPUT_DIR + '/content/api/' + 'drivers.json', 'w', encoding='utf-8') as f:
        json.dump(drivers, f, ensure_ascii=False, indent=4)
    messages.append("site_gen.py wrote drivers JSON to: {0}".format(OUTPUT_DIR + '/content/api/drivers.json'))

    # write listing csv
    with open(OUTPUT_DIR + '/content/' + 'drivers_table.csv', 'w') as f:
        writer = csv.writer(f)
        for driver in drivers:
            link = '[' + driver['Id'] + '](drivers/' + driver["Id"] + '/)'
            if driver['KnownVulnerableSamples'][0]['SHA256'] is None or driver['KnownVulnerableSamples'][0]['SHA256'] == "-" :
                sha256='not available '
            else:
                sha256='[' + driver['KnownVulnerableSamples'][0]['SHA256'] + '](drivers/' + driver["Id"]+ '/)'
            writer.writerow([link, sha256, driver['Created']])
    messages.append("site_gen.py wrote drivers table to: {0}".format(OUTPUT_DIR + '/content/drivers_table.csv'))

    # write top 5 publishers
    write_top_publishers(drivers, OUTPUT_DIR)
    messages.append("site_gen.py wrote drivers publishers to: {0}".format(OUTPUT_DIR + '/content/drivers_top_n_publishers.csv'))

    # write top 5 products
    write_top_products(drivers, OUTPUT_DIR)
    messages.append("site_gen.py wrote drivers products to: {0}".format(OUTPUT_DIR + '/content/drivers_top_n_products.csv'))

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
