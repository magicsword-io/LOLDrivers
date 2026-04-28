#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Generates YARA rules for a usable subset of the known vulnerable / malicious drivers
# Florian Roth
# March 2026

__version__ = "0.5.0"
__author__ = "Florian Roth"

import sys
import argparse
import binascii
import hashlib
import logging
import math
import os
import re
import platform
from pprint import pprint
import string
import yaml
import traceback
from datetime import datetime
from dataclasses import dataclass

import pefile


YARA_RULE_TEMPLATE = '''
rule $$$RULENAME$$$ {
	meta:
		description = "$$$DESCRIPTION$$$"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "$$$HASH$$$"
		date = "$$$DATE$$$"
		score = $$$SCORE$$$
	strings:
		$ = $$$STRINGS$$$
	condition:
		$$$STRICT$$$all of them$$$RENAMED$$$
}
'''

SKIP_DRIVERS = [
		"3748096bd604a91bc26b2aa1c6883fce.bin" # driver_290bc782.sys - see https://magicswordio.slack.com/archives/C0533A7USGM/p1751462576699979
		]

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
DEFAULT_DRIVER_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../../drivers/"))
DEFAULT_YAML_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../../yaml/"))
DEFAULT_OUTPUT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../../detections/yara/"))


@dataclass
class RuleBlock:
	name: str
	raw: str
	date: str
	detection_fingerprint: str


def normalize_rule_lines(lines):
	return "\n".join(line.rstrip() for line in lines).strip()


def split_rule_blocks(rule_text):
	rules = []
	current_rule = []
	for line in rule_text.splitlines():
		if line.startswith("rule "):
			if current_rule:
				rules.append("\n".join(current_rule).strip())
			current_rule = [line]
			continue
		if current_rule:
			current_rule.append(line)
			if line.strip() == "}":
				rules.append("\n".join(current_rule).strip())
				current_rule = []
	if current_rule:
		rules.append("\n".join(current_rule).strip())
	return [rule for rule in rules if rule]


def parse_rule_block(rule_text):
	rule_text = rule_text.strip()
	lines = rule_text.splitlines()
	if not lines:
		raise ValueError("Cannot parse empty rule block")
	rule_match = re.match(r"^rule\s+([A-Za-z0-9_]+)\s*\{$", lines[0].strip())
	if not rule_match:
		raise ValueError("Unexpected rule header: %s" % lines[0])
	rule_name = rule_match.group(1)
	meta_index = None
	strings_index = None
	condition_index = None
	for idx, line in enumerate(lines):
		stripped = line.strip()
		if stripped == "meta:":
			meta_index = idx
		elif stripped == "strings:":
			strings_index = idx
		elif stripped == "condition:":
			condition_index = idx
	if meta_index is None or strings_index is None or condition_index is None:
		raise ValueError("Rule %s is missing one of meta/strings/condition sections" % rule_name)
	meta_lines = lines[meta_index + 1:strings_index]
	strings_lines = lines[strings_index + 1:condition_index]
	condition_lines = lines[condition_index + 1:]
	if condition_lines and condition_lines[-1].strip() == "}":
		condition_lines = condition_lines[:-1]
	date_value = ""
	for meta_line in meta_lines:
		meta_match = re.match(r'^\s*date\s*=\s*"([^"]+)"\s*$', meta_line)
		if meta_match:
			date_value = meta_match.group(1)
			break
	detection_fingerprint = "%s\n--\n%s" % (
		normalize_rule_lines(strings_lines),
		normalize_rule_lines(condition_lines),
	)
	return RuleBlock(
		name=rule_name,
		raw=rule_text,
		date=date_value,
		detection_fingerprint=detection_fingerprint,
	)


def load_existing_rules(rule_path):
	if not os.path.exists(rule_path):
		return {}
	with open(rule_path, "r") as fh:
		rule_text = fh.read()
	existing_rules = {}
	for rule_block in split_rule_blocks(rule_text):
		parsed_rule = parse_rule_block(rule_block)
		existing_rules[parsed_rule.name] = parsed_rule
	return existing_rules


def set_rule_metadata_value(rule_text, key, value):
	lines = rule_text.strip().splitlines()
	meta_index = None
	strings_index = None
	for idx, line in enumerate(lines):
		stripped = line.strip()
		if stripped == "meta:":
			meta_index = idx
		elif stripped == "strings:":
			strings_index = idx
			break
	if meta_index is None or strings_index is None:
		raise ValueError("Cannot update metadata for malformed rule")
	new_meta_line = '\t\t%s = "%s"' % (key, value)
	for idx in range(meta_index + 1, strings_index):
		if re.match(r'^\s*%s\s*=' % re.escape(key), lines[idx]):
			lines[idx] = new_meta_line
			return "\n".join(lines).strip()
	insert_at = strings_index
	if key == "modified":
		for idx in range(meta_index + 1, strings_index):
			if re.match(r'^\s*date\s*=', lines[idx]):
				insert_at = idx + 1
				break
	lines.insert(insert_at, new_meta_line)
	return "\n".join(lines).strip()


def build_updated_rule(existing_rule, generated_rule, current_date):
	updated_rule = set_rule_metadata_value(generated_rule.raw, "date", existing_rule.date or current_date)
	updated_rule = set_rule_metadata_value(updated_rule, "modified", current_date)
	return RuleBlock(
		name=generated_rule.name,
		raw=updated_rule,
		date=existing_rule.date or current_date,
		detection_fingerprint=generated_rule.detection_fingerprint,
	)


def merge_rule_sets(existing_rules, generated_rules, current_date):
	existing_by_fingerprint = {}
	for existing_rule in existing_rules.values():
		existing_by_fingerprint.setdefault(existing_rule.detection_fingerprint, []).append(existing_rule)

	used_existing_rules = set()
	merged_rules = []
	rule_set_changed = len(existing_rules) == 0 and len(generated_rules) > 0
	for generated_rule in generated_rules:
		existing_rule = existing_rules.get(generated_rule.name)
		if existing_rule is not None:
			used_existing_rules.add(existing_rule.name)
			if existing_rule.detection_fingerprint == generated_rule.detection_fingerprint:
				merged_rules.append(existing_rule)
			else:
				rule_set_changed = True
				merged_rules.append(build_updated_rule(existing_rule, generated_rule, current_date))
			continue

		same_detection_rules = [
			rule for rule in existing_by_fingerprint.get(generated_rule.detection_fingerprint, [])
			if rule.name not in used_existing_rules
		]
		if same_detection_rules:
			existing_rule = same_detection_rules[0]
			used_existing_rules.add(existing_rule.name)
			Log.info(
				"[+] Keeping existing rule %s unchanged because generated rule %s has identical detection logic"
				% (existing_rule.name, generated_rule.name)
			)
			merged_rules.append(existing_rule)
			continue

		rule_set_changed = True
		merged_rules.append(generated_rule)

	for existing_rule in existing_rules.values():
		if existing_rule.name not in used_existing_rules:
			Log.info("[+] Preserving existing rule %s because no replacement was generated" % existing_rule.name)
			merged_rules.append(existing_rule)

	return [rule.raw for rule in sorted(merged_rules, key=lambda rule: rule.name)], rule_set_changed


def write_rule_file(rule_path, generated_rule_texts, current_date):
	existing_text = ""
	if os.path.exists(rule_path):
		with open(rule_path, "r") as fh:
			existing_text = fh.read()
	existing_rules = load_existing_rules(rule_path)
	generated_rules = [parse_rule_block(rule_text) for rule_text in generated_rule_texts]
	merged_rules, rule_set_changed = merge_rule_sets(existing_rules, generated_rules, current_date)
	if existing_text and not rule_set_changed:
		Log.info("[+] Keeping existing rule file unchanged: %s" % rule_path)
		return len(existing_rules)
	parent_dir = os.path.dirname(rule_path)
	if parent_dir:
		os.makedirs(parent_dir, exist_ok=True)
	with open(rule_path, "w") as fh:
		fh.write("\n\n".join(merged_rules))
		if merged_rules:
			fh.write("\n")
	return len(merged_rules)

def process_folders(input_folders, debug):
	input_files = []
	for d in input_folders:
		if not os.path.exists(d):
			Log.error("[E] Error: input directory '%s' doesn't exist" % d)
		else:
			for dirpath, dirnames, files in os.walk(d):
				for f in files:
					# Print processed file in debug mode
					Log.debug("Processing file: %s" % f)
					# Skip files that are in the SKIP_DRIVERS list
					if f in SKIP_DRIVERS:
						Log.debug("Skipping file %s as it is in the SKIP_DRIVERS list" % f)
						continue
					# if ".sys" in f:
					input_files.append(os.path.join(dirpath, f))
	return input_files

def process_yaml_files(input_folders, debug):
	input_files = []
	# print(input_folders)
	yaml_data_list = []
	for yaml_folder in input_folders:
		if not os.path.isdir(yaml_folder):
			Log.error("[E] Error: YAML input directory '%s' doesn't exist" % yaml_folder)
			continue
		for filename in os.listdir(yaml_folder):
			if filename.endswith('.yaml') or filename.endswith('.yml'):
				file_path = os.path.join(yaml_folder, filename)
				try:
					with open(file_path, 'r') as file:
						yaml_data = yaml.safe_load(file)
				except Exception as e:
					Log.error("Cannot process YAML file: %s (%s)" % (file_path, str(e)))
					if debug:
						traceback.print_exc()
					continue
				if not isinstance(yaml_data, dict):
					Log.info("Skipping YAML file without top-level mapping: %s" % file_path)
					continue
				samples = yaml_data.get('KnownVulnerableSamples')
				if not isinstance(samples, list):
					Log.info("Skipping YAML file without KnownVulnerableSamples list: %s" % file_path)
					continue
				yaml_data_list.append(yaml_data)
	return yaml_data_list

def process_files(input_files, debug):
	header_infos = []
	for f in input_files:
		Log.debug("Extracting PE header infos from: %s" % f)
		try:
			pe = pefile.PE(f)
		except pefile.PEFormatError as e:
			Log.error("Cannot process file: %s" % f)
			continue
			# Log.debug("Failed to process file %s with error: " % traceback.print_exc())
		# Getting the Version info values used for the YARA rules
		string_version_info = {}
		try:
			for fileinfo in pe.FileInfo[0]:
				if fileinfo.Key.decode() == 'StringFileInfo':
					for st in fileinfo.StringTable:
						for entry in st.entries.items():
							string_version_info[entry[0].decode()] = entry[1].decode()
		except Exception as e:
			if debug:
				traceback.print_exc()
				print("Attributes of PE object: ", dir(pe))
			Log.info("Couldn't extract any PE header infos for file %s and thus cannot generate a YARA rule for it. Error: %s" % (f, str(e)))

			#Log.info("Couldn't extract any PE header infos for file %s and thus cannot generate a YARA rule for it" % f)
			continue
		Log.debug("Extracted VersionInfo: %s" % string_version_info)

		# Generate a hash value for the file
		sha256_hash = ""
		m = hashlib.sha256()
		with open(f,"rb") as fh:
			bytes = fh.read() # read entire file as bytes
			sha256_hash = hashlib.sha256(bytes).hexdigest();
			Log.debug("Calculate hash for file %s which is %s" % (f, sha256_hash))
		
		# Get the file size
		file_stats = os.stat(f)
		file_size = int(math.ceil((file_stats.st_size / 1024) / 100.0)) * 100
		
		# Generate a dictionary that serves as an input for the YARA rule generation
		yara_rule_infos = {
			'file_names': [os.path.basename(f)],
			'sha256': [sha256_hash],
			'file_sizes': [file_size],
			'version_info': {
				'FileDescription': get_version_info(string_version_info, 'FileDescription'),
				'CompanyName': get_version_info(string_version_info, 'CompanyName'),
				'FileVersion': get_version_info(string_version_info, 'FileVersion'),
				'ProductVersion': get_version_info(string_version_info, 'ProductVersion'),
				'InternalName': get_version_info(string_version_info, 'InternalName'),
				'ProductName': get_version_info(string_version_info, 'ProductName'),
				'OriginalFilename': get_version_info(string_version_info, 'OriginalFilename'),
				'LegalCopyright': get_version_info(string_version_info, 'LegalCopyright'),
			}
		}

		# Check if the VersionInfo is the same as found in another file (avoid duplicates)
		is_duplicate = False
		for hi in header_infos:
			shared_items = {k: yara_rule_infos['version_info'][k] for k in yara_rule_infos['version_info'] if k in hi['version_info'] and yara_rule_infos['version_info'][k] == hi['version_info'][k]}
			if len(yara_rule_infos['version_info']) == len(shared_items):
				Log.debug("Duplicate found %s - duplicates: %s" % (f, hi['file_names']))
				is_duplicate = True
				hi['file_names'].append(os.path.basename(f))
				hi['sha256'].append(sha256_hash)
				hi['file_sizes'].append(file_size)

		#pprint(header_infos)
		if not is_duplicate:
			header_infos.append(yara_rule_infos)

	# Sort lists to get the same order across different Python versions and operating systems
	for hi in header_infos:
		for key, value in hi.items():
			if isinstance(value, list):
				hi[key] = sorted(value)

	return header_infos


def generate_yara_rules(header_infos, yaml_infos, debug, driver_filter, strict, renamed, current_date):
    rules = dict()

    # Loop over the header infos
    for hi in header_infos:
        # Get YAML info to determine the type of rule
        yaml_info = get_yaml_info_for_sample(hi['sha256'][0], yaml_infos)
        # If no YAML info is found, skip the rule generation
        if not yaml_info:
            Log.info("No YAML info found for %s - skipping YARA rule generation" % hi['file_names'])
            continue

        # Category and values
        type_driver = "vulnerable driver"
        type_string = "PUA_VULN"
        type_desc = "vulnerable"
        type_score = 40
        if renamed:
            type_score = 70
            type_string = "PUA_VULN_Renamed"

        # For malicious drivers
        if yaml_info.get('Category') == "malicious":
            type_driver = "malicious"
            type_string = "MAL_"
            type_desc = "malicious"
            type_score = 70
            if strict:
                type_score = 85

        # File names (use the file names in field 'Tags' otherwise use the driver file names)
        file_names = hi['file_names']
        if 'Tags' in yaml_info:
            file_names = yaml_info['Tags']

        # Apply filter
        if driver_filter != type_driver:
            continue

        # Generate Rule
        new_rule = YARA_RULE_TEMPLATE
        rule_name = generate_rule_name(hi['version_info'], type_string, hi['sha256'][0])
        Log.info("Generating YARA rule for %s - rule name %s" % (hi['file_names'], rule_name))
        new_rule = new_rule.replace('$$$RULENAME$$$', rule_name)
        description = generate_rule_description(type_desc, file_names, renamed)
        new_rule = new_rule.replace('$$$DESCRIPTION$$$', description)
        new_rule = new_rule.replace('$$$HASH$$$', '"\n\t\thash = "'.join(hi['sha256']))
        new_rule = new_rule.replace('$$$DATE$$$', current_date)
        new_rule = new_rule.replace('$$$FILENAMES$$$', ", ".join(file_names))
        new_rule = new_rule.replace('$$$SCORE$$$', str(type_score))
        string_values = generate_string_values(hi['version_info'])
        # if string values is empty or too small
        if len(string_values) < 3:
            Log.info("Number of extracted PE version info values is empty or not big enough - YARA rule generation skipped for %s" % hi['file_names'])
            continue
        new_rule = new_rule.replace('$$$STRINGS$$$', "\n\t\t$ = ".join(string_values))
        # Condition
        if strict:
            new_rule = new_rule.replace('$$$STRICT$$$', "uint16(0) == 0x5a4d and filesize < %dKB and " % max(hi['file_sizes']))
        else:
            new_rule = new_rule.replace('$$$STRICT$$$', '')
        if 'Tags' in yaml_info and renamed and len(yaml_info['Tags']) > 0:
            filename_string = generate_filename_string(yaml_info['Tags'])
            new_rule = new_rule.replace('$$$RENAMED$$$', filename_string)
        else:
            new_rule = new_rule.replace('$$$RENAMED$$$', '')

        Log.debug(new_rule)
        # Append rule to the list
        rules[rule_name] = new_rule

    return [rules[rule_name] for rule_name in sorted(rules)]


def generate_rule_description(type_desc, file_names, renamed):
	filenames = ", ".join(file_names)
	if renamed:
		return (
			"Detects renamed %s driver mentioned in LOLDrivers project using VersionInfo values from the PE header - %s. "
			"A match indicates an unexpected filename and should be treated as more suspicious, especially outside expected vendor or system driver paths."
		) % (type_desc, filenames)
	return (
		"Detects %s driver mentioned in LOLDrivers project using VersionInfo values from the PE header - %s. "
		"Investigate matches in context: expected filenames or standard vendor/system driver locations can be lower priority, while unexpected filenames or paths are more suspicious."
	) % (type_desc, filenames)



def generate_filename_string(tags):
	filename_expression = " and not filename icontains \"$VALUE$\""
	filenames = []
	expression = ""
	for t in tags:
		filenames.append(os.path.splitext(t)[0])
	# Compose the full expression
	if len(filenames) == 1:
		expression = filename_expression.replace('$VALUE$', filenames[0])
	else:
		for f in filenames:
			expression += filename_expression.replace('$VALUE$', f)
	return expression


def generate_string_values(version_info):
	string_values = []
	for field, value in version_info.items():
		if value: # if not empty
			field_hex = binascii.hexlify(field.encode('utf-16-le')).decode()
			value_hex = binascii.hexlify(value.encode('utf-16-le')).decode()
			search_value = "{ %s[1-8]%s } /* %s %s */" % (field_hex, value_hex, field, removeNonAsciiDrop(value))
			string_values.append(search_value)
	return string_values


def get_yaml_info_for_sample(sample_hash, yaml_infos):
	# Loop over YAML infos and find the sample using its hash
	for yi in yaml_infos:
		samples = yi.get('KnownVulnerableSamples')
		if not isinstance(samples, list):
			continue
		for sample_info in samples:
			if not isinstance(sample_info, dict):
				continue
			# print(sample_info)
			sample_hashes = []
			if 'MD5' in sample_info:
				sample_hashes.append(sample_info['MD5'])
			if 'SHA1' in sample_info:
				sample_hashes.append(sample_info['SHA1'])
			if 'SHA256' in sample_info:
				sample_hashes.append(sample_info['SHA256'])
			# if the driver's hash matches on of the hashes mentioned in the sample info in the YAML
			if sample_hash in sample_hashes:
				# return the info
				return yi
	# otherwise return nothing
	return None


def get_version_info(version_info, value):
	if value in version_info:
		return version_info[value]
	return ''


def generate_rule_name(version_info, type_string, hash_value):
	prefix = "%s_Driver" % type_string
	rid = hash_value[:4].upper()
	# Trying to use the values from the VersionInfo for sections of the name
	custom_rule_part = []
	custom_rule_string = ""
	if 'CompanyName' in version_info:
		custom_rule_part.append(removeNonAsciiDrop(version_info['CompanyName']))
	if 'InternalName' in version_info:
		custom_rule_part.append(removeNonAsciiDrop(version_info['InternalName']))
	if 'ProductName' in version_info:
		custom_rule_part.append(removeNonAsciiDrop(version_info['ProductName']))
	if 'ProductVersion' in version_info:
		custom_rule_part.append(removeNonAsciiDrop(version_info['ProductVersion']))
	# Compose the rule
	if not custom_rule_part:
		custom_rule_string = "Gen_%s" % rid
	else:
		custom_rule_string = "_".join(custom_rule_part).title()
	rule_name = "%s_%s_%s" % (prefix, custom_rule_string, rid)
	rule_name = re.sub(r'[_]{1,}', '_', rule_name)
	return rule_name


def removeNonAsciiDrop(s):
	nonascii = "error"
	try:
		# Generate a new string without non-ASCII characters
		printable = set(string.ascii_letters)
		nonascii = filter(lambda x: x in printable, s)
	except Exception as e:
		traceback.print_exc()
		pass
	return "".join(nonascii)


if __name__ == '__main__':
	# Parse Arguments
	parser = argparse.ArgumentParser(description='YARA Rule Generator for PE Header Info')
	parser.add_argument('-d', nargs='*', 
	                    help='Path to driver directories (can be used multiple times)',
	                    metavar='driver-files', default=[DEFAULT_DRIVER_DIR])
	parser.add_argument('-y', nargs='*', 
	                    help='Path to YAML files with information on the drivers (can be used multiple times)',
	                    metavar='yaml-files', default=[DEFAULT_YAML_DIR])
	parser.add_argument('-f', help="Write a log file)", metavar='log-file', default='yara-generator.log')
	parser.add_argument('-o', help="Output folder for rules", metavar='output-folder', default=DEFAULT_OUTPUT_DIR)
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

	args = parser.parse_args()

	# Logging
	logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
	logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
	Log = logging.getLogger(__name__)
	Log.setLevel(logging.INFO)
	if args.debug:
		Log.setLevel(logging.DEBUG)
	# File Handler
	fileHandler = logging.FileHandler(args.f)
	fileHandler.setFormatter(logFormatter)
	Log.addHandler(fileHandler)
	# Console Handler
	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	Log.addHandler(consoleHandler)

	# Walk the folders and get a list of all input files
	Log.info("[+] Processing %d driver folders" % len(args.d))
	file_paths = process_folders(args.d, args.debug)

	# Walk the YAML information folders and get a dictionary with meta data
	Log.info("[+] Processing %d YAML folders" % len(args.y))
	yaml_infos = process_yaml_files(args.y, args.debug)
	#pprint(yaml_infos[0])
	#sys.exit(1)

	# Process each file and extract the header info need for the YARA rules
	Log.info("[+] Processing %d sample files" % len(file_paths))
	file_infos = process_files(file_paths, args.debug)

	# Generate YARA rules and return them as list of their string representation
	Log.info("[+] Generating YARA rules from %d header infos" % len(file_infos))
	current_date = datetime.today().strftime('%Y-%m-%d')
	yara_rules_vulnerable_drivers = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=False, renamed=False, current_date=current_date)
	yara_rules_malicious_drivers = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="malicious",  strict=False, renamed=False, current_date=current_date)
	yara_rules_vulnerable_drivers_strict = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=True, renamed=False, current_date=current_date)
	yara_rules_malicious_drivers_strict = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="malicious",  strict=True, renamed=False, current_date=current_date)
	yara_rules_vulnerable_drivers_strict_renamed = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=True, renamed=True, current_date=current_date)

	# Write the output files
	# we write the recommended files to the root folder and other sets to a sub folder named 'other'
	output_file = os.path.join(args.o, 'other', 'yara-rules_vuln_drivers.yar')
	merged_count = write_rule_file(output_file, yara_rules_vulnerable_drivers, current_date)
	Log.info("[+] Writing %d YARA rules to the output file %s" % (merged_count, output_file))
	output_file = os.path.join(args.o, 'yara-rules_mal_drivers.yar')
	merged_count = write_rule_file(output_file, yara_rules_malicious_drivers, current_date)
	Log.info("[+] Writing %d YARA rules to the output file %s" % (merged_count, output_file))
	output_file = os.path.join(args.o, 'yara-rules_vuln_drivers_strict.yar')
	merged_count = write_rule_file(output_file, yara_rules_vulnerable_drivers_strict, current_date)
	Log.info("[+] Writing %d YARA rules to the output file %s" % (merged_count, output_file))
	output_file = os.path.join(args.o, 'other', 'yara-rules_mal_drivers_strict.yar')
	merged_count = write_rule_file(output_file, yara_rules_malicious_drivers_strict, current_date)
	Log.info("[+] Writing %d YARA rules to the output file %s" % (merged_count, output_file))
	output_file = os.path.join(args.o, 'other', 'yara-rules_vuln_drivers_strict_renamed.yar')
	merged_count = write_rule_file(output_file, yara_rules_vulnerable_drivers_strict_renamed, current_date)
	Log.info("[+] Writing %d YARA rules to the output file %s" % (merged_count, output_file))
