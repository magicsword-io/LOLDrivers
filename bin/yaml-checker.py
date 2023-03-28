import yaml
import os
import unittest
from colorama import init
from colorama import Fore


class TestRules(unittest.TestCase):

    path_to_yml = "../yaml"
    path_to_yml = os.path.join(os.path.dirname(os.path.realpath(__file__)), path_to_yml)

    def yield_next_rule_file_path(self, path_to_yml: str) -> str:
            for root, _, files in os.walk(path_to_yml):
                for file in files:
                    yield os.path.join(root, file)

    def get_yaml_part(self, file_path: str, part_name: str):
            yaml_dicts = self.get_yaml(file_path)
            for yaml_part in yaml_dicts:
                if part_name in yaml_part.keys():
                    return yaml_part[part_name]
            return None

    def get_yaml(self, file_path: str) -> dict:
        data = []
        with open(file_path, encoding='utf-8') as f:
            yaml_parts = yaml.safe_load_all(f)
            for part in yaml_parts:
                data.append(part)
        return data

    def test_mandatory_fields(self):
        """
            Checks mandatory fields in YAML document
        """
        
        for file in self.yield_next_rule_file_path(self.path_to_yml):

            faulty_yaml_list = []

            # Add or remove any field that are (not) mandatory
            name = self.get_yaml_part(file_path=file, part_name="Name")
            author = self.get_yaml_part(file_path=file, part_name="Author")
            created = self.get_yaml_part(file_path=file, part_name="Created")
            mitreid = self.get_yaml_part(file_path=file, part_name="MitreID")
            category = self.get_yaml_part(file_path=file, part_name="Category")
            verified = self.get_yaml_part(file_path=file, part_name="Verified")
            resources = self.get_yaml_part(file_path=file, part_name="Resources")
            known_vuln_samples = self.get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")

            if not name:
                print( Fore.RED + "YAML {} is missing the 'Name' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not author:
                print( Fore.RED + "YAML {} is missing the 'Author' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not created:
                print( Fore.RED + "YAML {} is missing the 'Created' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not mitreid:
                print( Fore.RED + "YAML {} is missing the 'MitreID' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not category:
                print( Fore.RED + "YAML {} is missing the 'Category' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not verified:
                print( Fore.RED + "YAML {} is missing the 'Verified' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not resources:
                print( Fore.RED + "YAML {} is missing the 'Resources' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            if not known_vuln_samples:
                print( Fore.RED + "YAML {} is missing the 'KnownVulnerableSamples' field".format(file))
                if file not in faulty_yaml_list:
                    faulty_yaml_list.append(file)
            
            self.assertEqual(faulty_yaml_list, [], Fore.RED + "There are YAML documents files which are missing mandatory fields")

    def test_hash_length(self):
        """
            Checks if the length of the HASH is valid
        """

        faulty_yaml_list = []

        for file in self.yield_next_rule_file_path(self.path_to_yml):
            known_vuln_samples = self.get_yaml_part(file_path=file, part_name="KnownVulnerableSamples")
            if known_vuln_samples:
                for i in known_vuln_samples:
                    if i['MD5']:
                        if i['MD5'] != "-":
                            if len(i['MD5']) != 32:
                                print( Fore.RED + "YAML {} has an invalid MD5 hash".format(file))
                                if file not in faulty_yaml_list:
                                        faulty_yaml_list.append(file)      
                    if i['SHA1']:
                        if i['SHA1'] != "-":
                            if len(i['SHA1']) != 40:
                                print( Fore.RED + "YAML {} has an invalid SHA1 hash".format(file))
                                if file not in faulty_yaml_list:
                                        faulty_yaml_list.append(file)  
                    if i['SHA256']:
                        if i['SHA256'] != "-":
                            if len(i['SHA256']) != 64:
                                print( Fore.RED + "YAML {} has an invalid SHA256 hash".format(file))
                                if file not in faulty_yaml_list:
                                        faulty_yaml_list.append(file)  

        self.assertEqual(faulty_yaml_list, [], Fore.RED + "There are YAML documents with incorrect hashes")

if __name__ == "__main__":
    init(autoreset=True)
    # Run the tests
    unittest.main()
