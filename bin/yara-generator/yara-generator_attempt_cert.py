#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Generates YARA rules for a usable subset of the known vulnerable / malicious drivers
# Florian Roth
# june 2023

__version__ = "0.4.1"
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
import pem
import asn1crypto.x509
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime

import pefile


YARA_RULE_TEMPLATE = '''
rule $$$RULENAME$$$ {
	meta:
		description = "Detects $$$TYPE$$$ driver mentioned in LOLDrivers project using VersionInfo values from the PE header - $$$FILENAMES$$$"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "$$$HASH$$$"
		date = "$$$DATE$$$"
		score = $$$SCORE$$$
	strings:
		$ = $$$STRINGS$$$
	condition:
		$$$STRICT$$$$$$CONDITION$$$$$$RENAMED$$$
}
'''

def process_folders(input_folders, debug):
	input_files = []
	print(input_folders)
	for d in input_folders:
		if not os.path.exists(d):
			Log.error("[E] Error: input directory '%s' doesn't exist" % d)
		else:
			for dirpath, dirnames, files in os.walk(d):
				for f in files:
					# if ".sys" in f:
					input_files.append(os.path.join(dirpath, f))
	return input_files

def process_yaml_files(input_folders, debug):
	input_files = []
	# print(input_folders)
	yaml_data_list = []
	for yaml_folder in input_folders:
		for filename in os.listdir(yaml_folder):
			if filename.endswith('.yaml') or filename.endswith('.yml'):
				file_path = os.path.join(yaml_folder, filename)
				with open(file_path, 'r') as file:
					yaml_data = yaml.safe_load(file)
					yaml_data_list.append(yaml_data)
	return yaml_data_list

def process_files(input_files, debug):
	header_infos = []
	pe_info_found = False
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
			pe_info_found = True
		except Exception as e:
			pe_info_found = False
			if debug:
				traceback.print_exc()
			Log.info("Couldn't extract any PE header infos for file %s" % f)
		Log.debug("Extracted VersionInfo: %s" % string_version_info)

		# Extract signing certificate information
		# only extract the information if no pe info was found
		cert_info_bytes_found = False
		cert_bytes = []
		if not pe_info_found:
			Log.debug("No PE header info found - trying to extract certificate info")
			Log.debug("Extracting certificate info from: %s" % f)
			try:
				pe = pefile.PE(f)
			except pefile.PEFormatError as e:
				Log.error("Cannot process file: %s" % f)
				continue
			if hasattr(pe, 'VS_FIXEDFILEINFO'):
				Log.debug("PE file has a VS_FIXEDFILEINFO structure")
				security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
				if security_dir.VirtualAddress != 0:
					Log.debug("PE file has a security directory")
					security_offset = security_dir.VirtualAddress
					security_size = security_dir.Size
					with open(f, 'rb') as file_handle:
							file_handle.seek(security_offset)
							signed_data = file_handle.read(security_size)
							try:
								# Skip the first 8 bytes which are the WIN_CERTIFICATE structure header
								signed_data = signed_data[8:]
								
								# Check if the data is PEM-encoded
								pem_certificates = pem.parse(signed_data)
								if pem_certificates:
									signed_data = pem_certificates[0].as_bytes()
								
								content_info = cms.ContentInfo.load(signed_data)
								for cert in content_info['content']['certificates']:
									if isinstance(cert.chosen, cms.Certificate):
											cert = x509.load_der_x509_certificate(cert.chosen.dump(), default_backend())

											# Extract the serial number, not before and not after dates
											serial_number_bytes = cert.serial_number.to_bytes((cert.serial_number.bit_length() + 7) // 8, byteorder='big')
											
											# Parse the certificate using asn1crypto to get raw bytes
											asn1_cert = asn1crypto.x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
											tbs_certificate = asn1_cert['tbs_certificate']
											
											# Extract the validity period
											not_before_bytes = tbs_certificate['validity']['not_before'].contents
											not_after_bytes = tbs_certificate['validity']['not_after'].contents
											
											# Add all bytes to the list
											cert_bytes.append(serial_number_bytes)
											cert_bytes.append(not_before_bytes)
											cert_bytes.append(not_after_bytes)

											# Set the flag to indicate that certificate info bytes were found
											cert_info_bytes_found = True
							except ValueError as e:
								Log.error(f"Error parsing CMS content for file {f}: {e}")
								if debug:
									traceback.print_exc()
							except Exception as e:
								Log.error(f"Unexpected error processing file {f}: {e}")
								if debug:
									traceback.print_exc()

			# Log the extracted certificate info
			if cert_info_bytes_found:
				Log.info("Certificate info found and extracted")
				Log.debug(f"Extracted Certificate Serial Number Bytes: {serial_number_bytes.hex()}")
				Log.debug(f"Extracted Certificate Not Before Bytes: {not_before_bytes.hex()}")
				Log.debug(f"Extracted Certificate Not After Bytes: {not_after_bytes.hex()}")

		# Log if certificate info has been found but no PE info
		if cert_info_bytes_found and not pe_info_found:
			Log.info("Certificate info found but no PE header info found for file %s" % f)

		# If no PE info and no cert info is found, skip the file
		if not pe_info_found and not pe_info_found:
			Log.info("No PE header info or certificate info found for file %s - skipping rule generation" % f)
			continue

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
			},
			'certificate_bytes': cert_bytes,
			'pe_info_found': pe_info_found,
			'cert_info_bytes_found': cert_info_bytes_found
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
	
	return header_infos


def generate_yara_rules(header_infos, yaml_infos, debug, driver_filter, strict, renamed):
	rules = list()

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
		# for malicious drivers
		if 'Category' in yaml_info:
			#print(yaml_info['Category'])
			if yaml_info['Category'] == "malicious":
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
		if driver_filter is not type_driver:
			continue

		# Generate Rule
		new_rule = YARA_RULE_TEMPLATE
		rule_name = generate_rule_name(hi['version_info'], type_string, hi['sha256'][0])
		Log.info("Generating YARA rule for %s - rule name %s" % (hi['file_names'], rule_name))
		new_rule = new_rule.replace('$$$RULENAME$$$', rule_name)
		new_rule = new_rule.replace('$$$HASH$$$', '"\n\t\thash = "'.join(hi['sha256']))
		new_rule = new_rule.replace('$$$DATE$$$', datetime.today().strftime('%Y-%m-%d'))
		new_rule = new_rule.replace('$$$FILENAMES$$$', ", ".join(file_names))
		new_rule = new_rule.replace('$$$SCORE$$$', str(type_score))
		if renamed:
			new_rule = new_rule.replace('$$$TYPE$$$', 'renamed %s' % type_desc)
		else:
			new_rule = new_rule.replace('$$$TYPE$$$', type_desc)
	
		# Generate the string values
		string_values = generate_string_values(hi)
		# If rule is based on PE header infos, then use "all of them" as condition
		if hi['pe_info_found']:
			new_rule = new_rule.replace('$$$CONDITION$$$', "all of them")
		elif hi['cert_info_bytes_found']:
			new_rule = new_rule.replace('$$$CONDITION$$$', "3 of them")

		# if string values is empty or too small
		if len(string_values) < 3:
			Log.info("Number of extracted PE version info / certificate bytes values is empty or not big enough - YARA rule generation skipped for %s" % hi['file_names'])
			continue
		new_rule = new_rule.replace('$$$STRINGS$$$', "\n\t\t$ = ".join(string_values))
		# Condition
		if strict:
			new_rule = new_rule.replace('$$$STRICT$$$', "uint16(0) == 0x5a4d and filesize < %dKB and " % max(hi['file_sizes']))
		else:
			new_rule = new_rule.replace('$$$STRICT$$$', '')
		if 'Tags' in yaml_info:
			if renamed and len(yaml_info['Tags']) > 0:
				filename_string = generate_filename_string(yaml_info['Tags'])
				new_rule = new_rule.replace('$$$RENAMED$$$', filename_string)
			else:
				new_rule = new_rule.replace('$$$RENAMED$$$', '') 
		else:
			new_rule = new_rule.replace('$$$RENAMED$$$', '') 

		Log.debug(new_rule)
		# Append rule to the list
		rules.append(new_rule)
	return rules


def generate_filename_string(tags):
	filename_expression = " and not filename matches /$VALUE$/i"
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


def generate_string_values(file_info):
	string_values = []
	# If the PE Version info was found
	if file_info['pe_info_found']:
		version_info = file_info['version_info']
		for field, value in version_info.items():
			if value: # if not empty
				field_hex = binascii.hexlify(field.encode('utf-16-be')).decode()
				value_hex = binascii.hexlify(value.encode('utf-16-be')).decode()
				search_value = "{ %s[1-8]%s } /* %s %s */" % (field_hex, value_hex, field, removeNonAsciiDrop(value))
				string_values.append(search_value)
	# If the certificate info bytes were found
	elif file_info['cert_info_bytes_found']:
		cert_bytes = file_info['certificate_bytes']
		for cert_byte in cert_bytes:
			string_values.append("{ %s }" % cert_byte.hex())
	return string_values


def get_yaml_info_for_sample(sample_hash, yaml_infos):
	# Loop over YAML infos and find the sample using its hash
	for yi in yaml_infos:
		for sample_info in yi['KnownVulnerableSamples']:
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
                    metavar='driver-files', default=['../../drivers/'])
	parser.add_argument('-y', nargs='*', 
                    help='Path to YAML files with information on the drivers (can be used multiple times)',
                    metavar='yaml-files', default=['../../yaml/'])
	parser.add_argument('-f', help="Write a log file)", metavar='log-file', default='yara-generator.log')
	parser.add_argument('-o', help="Output folder for rules", metavar='output-folder', default='../../detections/yara/')
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
	yara_rules_vulnerable_drivers = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=False, renamed=False)
	yara_rules_malicious_drivers = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="malicious",  strict=False, renamed=False)
	yara_rules_vulnerable_drivers_strict = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=True, renamed=False)
	yara_rules_malicious_drivers_strict = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="malicious",  strict=True, renamed=False)
	yara_rules_vulnerable_drivers_strict_renamed = generate_yara_rules(file_infos, yaml_infos, args.debug, driver_filter="vulnerable driver",  strict=True, renamed=True)

	# Write the output files
	# we write the recommended files to the root folder and other sets to a sub folder named 'other'
	output_file = os.path.join(args.o, 'other', 'yara-rules_vuln_drivers.yar')
	with open(output_file, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules_vulnerable_drivers), output_file))
		fh.write("\n".join(yara_rules_vulnerable_drivers))
	output_file = os.path.join(args.o, 'yara-rules_mal_drivers.yar')
	with open(output_file, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules_malicious_drivers), output_file))
		fh.write("\n".join(yara_rules_malicious_drivers))
	output_file = os.path.join(args.o, 'yara-rules_vuln_drivers_strict.yar')
	with open(output_file, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules_vulnerable_drivers_strict), output_file))
		fh.write("\n".join(yara_rules_vulnerable_drivers_strict))
	output_file = os.path.join(args.o, 'other', 'yara-rules_mal_drivers_strict.yar')
	with open(output_file, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules_malicious_drivers_strict), output_file))
		fh.write("\n".join(yara_rules_malicious_drivers_strict))
	output_file = os.path.join(args.o, 'other', 'yara-rules_vuln_drivers_strict_renamed.yar')
	with open(output_file, 'w') as fh:
		Log.info("[+] Writing %d YARA rules to the output file %s" % (len(yara_rules_vulnerable_drivers_strict_renamed), output_file))
		fh.write("\n".join(yara_rules_vulnerable_drivers_strict_renamed))
	# The single rules for each driver
	output_path_single_rules = os.path.join(args.o, '/single-rules')
