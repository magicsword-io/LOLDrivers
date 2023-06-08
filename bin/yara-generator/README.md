# YARA Rule Generator for the LOLDrivers Project

This YARA rule generator creates YARA rules for the vulnerable / malicious drivers collected in the LOLDrivers project.

## How does it work?

The generator processes the input samples and extract specific 'VersionInfo' values from the driver's PE headers. This includes e.g., the company name, file version, product version, description and other values. It then creates YARA rules that look for these specific values and uses a condition that's very permissive (`all of them`). This allows us to detect the drivers even if they are embedded in another file or loaded into memory.

The rule generator in version 0.4 generates five output files:

| File Name | Description | Score | 
| --- | --- | --- |
| yara-rules_vulnerable_drivers.yar | Contains rules to detect the vulnerable drivers without magic header and file size restrictions (possible false positives or malware that embeds them) | 50 |
| yara-rules_malicious_drivers.yar | Contains rules to detect the malicious drivers without magic header and file size restrictions (possible false positives or malware that embeds them) | 75 |
| yara-rules_vulnerable_drivers_strict.yar | Contains rules to detect the vulnerable drivers with magic header and file size restrictions  (less false positives) | 50 |
| yara-rules_malicious_drivers_strict.yar | Contains rules to detect the malicious drivers with magic header and file size restrictions (less false positives) | 85 |
| yara-rules_vulnerable_drivers_strict_renamed.yar | Contains rules to detect the vulnerable drivers with magic header and file size restrictions and filename checks (a renamed vulnerable driver is much more suspicious)[^1] | 70 |

[^1]: WARNING: these rules use the external variable `filename` which isn't available in every tool that uses YARA. It is e.g. used in [LOKI](https://github.com/Neo23x0/Loki/) and [THOR](https://www.nextron-systems.com/thor-lite/). 

## Requirements

* [Python 3.10](https://www.python.org/downloads/)
* [Poetry](https://python-poetry.org/docs/#installation)

## Setup

1. Install dependencies:

```
poetry install
```

2. Activate the virtual environment:

```
poetry shell
```

## Usage

```sh
usage: yara-generator.py [-h] [-d [driver-files ...]] [-y [yaml-files ...]] [-o output-folder] [--debug]

YARA Rule Generator for PE Header Info

options:
  -h, --help            show this help message and exit
  -d [driver-files ...]
                        Path to driver directories (can be used multiple times)
  -y [yaml-files ...]   Path to YAML files with information on the drivers (can be used multiple times)
  -o output-folder      Output folder for rules
  --debug               Debug output
```

## Examples

### Working on Linux / macOS

Generate the YARA rules and then use the command line tool YARA to scan the home folder using these rules:

```sh
python yara-generator.py -d ../../drivers/
```

Show debug output while generating the rules

```sh
python yara-generator.py -d ../../drivers/ --debug
```

### Working on Windows

Generate the YARA rules and then use the command line tool YARA to scan the drive C: using these rules:

```sh
python yara-generator.py -d ..\..\drivers\
```

Show debug output while generating the rules

```sh
python yara-generator.py -d ..\..\drivers\ --debug
```

## Example Output

Example rule generated from the binaries in the `./drivers` folder.

```yara
rule PUA_VULN_Driver_ASUSTekComputerInc_ATSZIOsys_ATSZIODriver__5kYV {
   meta:
      description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header"
      author = "Florian Roth"
      reference = "https://github.com/magicsword-io/LOLDrivers"
      hash = "c64d4ac416363c7a1aa828929544d1c1d78cf032b39769943b851cfc4c0faafc"
      date = "2023-05-12"
      score = 70
   strings:
      $ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004100540053005a0049004f0020004400720069007600650072 } /* FileDescription ATSZIO Driver */
      $ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004100530055005300540065006b00200043006f006d0070007500740065007200200049006e0063002e } /* CompanyName ASUSTek Computer Inc. */
      $ = { 00460069006c006500560065007200730069006f006e[1-8]0030002e0032002e0031002e0036 } /* FileVersion 0.2.1.6 */
      $ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0030002e0032002e0031002e0036 } /* ProductVersion 0.2.1.6 */
      $ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004100540053005a0049004f002e007300790073 } /* InternalName ATSZIO.sys */
      $ = { 00500072006f0064007500630074004e0061006d0065[1-8]004100540053005a0049004f0020004400720069007600650072 } /* ProductName ATSZIO Driver */
      $ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004100540053005a0049004f002e007300790073 } /* OriginalFilename ATSZIO.sys */
      $ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000310032 } /* LegalCopyright Copyright (C) 2012 */
   condition:
      all of them
}
```
