#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Generates YARA rules for a usable subset of the known vulnerable / malicious drivers
# Florian Roth
# May 2023

__version__ = "0.2.0"
__author__ = "Florian Roth"

import argparse
import binascii
import hashlib
import logging
import math
import os
import platform
import pprint
import string
import traceback
from datetime import datetime

import pefile
import shortuuid

YARA_RULE_TEMPLATE = '''
rule $$$RULENAME$$$ {
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "$$$HASH$$$"
		date = "$$$DATE$$$"
		score = 50
	strings:
		$ = $$$STRINGS$$$
	condition:
		$$$STRICT$$$all of them
}
'''


def process_folders(input_folders, debug):
	input_files = []
	# print(input_folders)
	for d in input_folders:
		if not os.path.exists(d):
			Log.error("[E] Error: input directory '%s' doesn't exist" % d)
		else:
			for dirpath, dirnames, files in os.walk(d):
				for f in files:
					# if ".sys" in f:
					input_files.append(os.path.join(dirpath, f))
	return input_files


def process_files(input_files, debug):
	header_infos = []
	for f in input_files:
		Log.debug("Extracting PE header infos from: %s" % f)
		try:
			pe = pefile.PE(f)
		except pefile.PEFormatError as e:
			Log.error("Cannot process file: %s" % f)
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
			Log.info("Couldn't extract any PE header infos for file %s and thus cannot generate a YARA rule for it" % f)
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
			'file_name': os.path.basename(f),
			'sha256': sha256_hash,
			'file_size': file_size,
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
		header_infos.append(yara_rule_infos)
	return header_infos


def generate_yara_rules(header_infos, strict, debug):
	rules = list()
	rule_names = []
	# Loop over the header infos 
	for hi in header_infos:
		# Generate Rule
		new_rule = YARA_RULE_TEMPLATE
		rule_name = generate_rule_name(hi['version_info'])
		Log.info("Generating YARA rule for %s - rule name %s" % (hi['file_name'], rule_name))
		new_rule = new_rule.replace('$$$RULENAME$$$', rule_name)
		new_rule = new_rule.replace('$$$HASH$$$', hi['sha256'])
		new_rule = new_rule.replace('$$$DATE$$$', datetime.today().strftime('%Y-%m-%d'))
		string_values = generate_string_values(hi['version_info'])
		# if string values is empty or too small
		if len(string_values) < 3:
			Log.info("Number of extracted PE version info values is empty or not big enough - YARA rule generation skipped for %s" % hi['file_name'])
			continue
		new_rule = new_rule.replace('$$$STRINGS$$$', "\n\t\t$ = ".join(string_values))
		# Condition
		if strict:
			new_rule = new_rule.replace('$$$STRICT$$$', "uint16(0) == 0x5a4d and filesize < %dKB and " % hi['file_size'])
		else:
			new_rule = new_rule.replace('$$$STRICT$$$', '')
		Log.debug(new_rule)
		# Append rule to the list
		rules.append(new_rule)
	return rules


def generate_string_values(version_info):
	string_values = []
	for field, value in version_info.items():
		if value: # if not empty
			field_hex = binascii.hexlify(field.encode('utf-16-be')).decode()
			value_hex = binascii.hexlify(value.encode('utf-16-be')).decode()
			search_value = "{ %s[1-8]%s } /* %s %s */" % (field_hex, value_hex, field, value)
			string_values.append(search_value)
	return string_values


def get_version_info(version_info, value):
	if value in version_info:
		return version_info[value]
	return ''


def generate_rule_name(version_info):
	prefix = "PUA_VULN_Driver"
	rid = shortuuid.ShortUUID().random(length=4)
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
		custom_rule_string = "_".join(custom_rule_part)
	rule_name = "%s_%s_%s" % (prefix, custom_rule_string, rid)
	rule_name = rule_name.replace('__', '_')
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
	parser.add_argument('-d', action='append', nargs='+', 
	  help='Path to input directory (can be used multiple times)', 
	  metavar='driver-files')
	parser.add_argument('-o', help="Output file", metavar='output-folder', default='./yara-rules.yar')
	parser.add_argument('--strict', action='store_true', default=False, help='Include magic header and filesize to make the rule more strict')
	parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

	args = parser.parse_args()

	# Logging
	logFormatter = logging.Formatter("[%(levelname)-5.5s] %(message)s")
	logFormatterRemote = logging.Formatter("{0} [%(levelname)-5.5s] %(message)s".format(platform.uname()[1]))
	Log = logging.getLogger(__name__)
	Log.setLevel(logging.INFO)
	if args.debug:
		Log.setLevel(logging.DEBUG)
	# Console Handler
	consoleHandler = logging.StreamHandler()
	consoleHandler.setFormatter(logFormatter)
	Log.addHandler(consoleHandler)

	# Walk the folders and get a list of all input files
	Log.info("[+] Processing %d input paths" % len(args.d[0]))
	file_paths = process_folders(args.d[0], args.debug)

	# Process each file and extract the header info need for the YARA rules
	Log.info("[+] Processing %d sample files" % len(file_paths))
	file_infos = process_files(file_paths, args.debug)

	# Generate YARA rules and return them as list of their string representation
	Log.info("[+] Generating YARA rules from %d header infos" % len(file_infos))
	yara_rules = generate_yara_rules(file_infos, args.strict, args.debug)

	# Write the output file
	with open(args.o, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules), args.o))
		fh.write("\n\n".join(yara_rules))
	