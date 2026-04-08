# YARA Rule Generator for the LOLDrivers Project

This YARA rule generator creates YARA rules for the vulnerable / malicious drivers collected in the LOLDrivers project.

## How does it work?

The generator processes the input samples and extract specific 'VersionInfo' values from the driver's PE headers. This includes e.g., the company name, file version, product version, description and other values. It then creates YARA rules that look for these specific values and uses a condition that's very permissive (`all of them`). This allows us to detect the drivers even if they are embedded in another file or loaded into memory.

The rule generator in version 0.5 generates five output files:

| File Name | Description | Score | 
| --- | --- | --- |
| yara-rules_vuln_drivers.yar | Contains rules to detect the vulnerable drivers without magic header and file size restrictions (possible false positives or malware that embeds them) | 40 |
| yara-rules_mal_drivers.yar | Contains rules to detect the malicious drivers without magic header and file size restrictions (possible false positives or malware that embeds them) | 70 |
| yara-rules_vuln_drivers_strict.yar | Contains rules to detect the vulnerable drivers with magic header and file size restrictions  (less false positives) | 50 |
| yara-rules_mal_drivers_strict.yar | Contains rules to detect the malicious drivers with magic header and file size restrictions (less false positives) | 85 |
| yara-rules_vuln_drivers_strict_renamed.yar | Contains rules to detect the vulnerable drivers with magic header and file size restrictions and filename checks (a renamed vulnerable driver is much more suspicious)[^1] | 70 |

[^1]: WARNING: these rules use the external variable `filename` which isn't available in every tool that uses YARA. It is e.g. used in [LOKI](https://github.com/Neo23x0/Loki/) and [THOR](https://www.nextron-systems.com/thor-lite/). 

## Requirements

* [pyenv](https://github.com/pyenv/pyenv)
* Python 3.10+ (tested with Python 3.13.5)
* `pip` (for `pefile` and `pyyaml`)

## Setup (pyenv + venv)

1. Initialize `pyenv` in `zsh`:

```sh
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init - zsh)"' >> ~/.zshrc
exec zsh
```

2. Create and activate a project virtual environment:

```sh
cd /path/to/LOLDrivers
pyenv install -s 3.13.5
pyenv local 3.13.5
python -m venv .venv
source .venv/bin/activate   # zsh/bash
# source .venv/bin/activate.fish   # fish shell
python -m pip install --upgrade pip
python -m pip install -r ./bin/yara-generator/requirements.txt
```

Shell-agnostic alternative (no activation required):

```sh
cd /path/to/LOLDrivers
python -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r ./bin/yara-generator/requirements.txt
```

3. Verify dependencies:

```sh
python -c "import yaml, pefile; print('deps-ok')"
```

## Usage

```sh
usage: yara-generator.py [-h] [-d [driver-files ...]] [-y [yaml-files ...]] [-f log-file] [-o output-folder] [--debug]

YARA Rule Generator for PE Header Info

options:
  -h, --help            show this help message and exit
  -d [driver-files ...]
                        Path to driver directories (can be used multiple times)
  -y [yaml-files ...]   Path to YAML files with information on the drivers (can be used multiple times)
  -f log-file           Write a log file
  -o output-folder      Output folder for rules
  --debug               Debug output
```

### Default paths

If no `-d`, `-y`, or `-o` values are given, defaults are resolved relative to the script location (`bin/yara-generator/`):

* Drivers: `../../drivers/`
* YAML metadata: `../../yaml/`
* Output: `../../detections/yara/`

This means running from the repository root or from the script directory works consistently.

### YAML validation

The generator skips YAML files that are invalid, do not parse to a top-level mapping, or do not contain a `KnownVulnerableSamples` list. Skipped files are reported in the log output.

## Examples

### Quick start (first run)

```sh
cd /path/to/LOLDrivers
python3 -m venv .venv
./.venv/bin/python -m pip install -r ./bin/yara-generator/requirements.txt
./.venv/bin/python ./bin/yara-generator/yara-generator.py
```

### Working on Linux / macOS

Generate the YARA rules (after setup/dependency install):

```sh
source .venv/bin/activate
python ./bin/yara-generator/yara-generator.py
```

Show debug output while generating the rules:

```sh
source .venv/bin/activate
python ./bin/yara-generator/yara-generator.py --debug
```

### Working on Windows

Generate the YARA rules and then use the command line tool YARA to scan the drive C: using these rules:

```sh
python .\bin\yara-generator\yara-generator.py
```

Show debug output while generating the rules

```sh
python .\bin\yara-generator\yara-generator.py --debug
```

## Troubleshooting

If you see:

```text
ModuleNotFoundError: No module named 'yaml'
```

then dependencies are missing in the active Python environment. Install them in your venv and run again:

```sh
./.venv/bin/python -m pip install -r ./bin/yara-generator/requirements.txt
./.venv/bin/python ./bin/yara-generator/yara-generator.py
```

If you see:

```text
source: Error while reading file '.venv/bin/activate'
```

you are likely using `fish` shell. Use either:

```sh
source .venv/bin/activate.fish
```

or run commands directly with `./.venv/bin/python` (shell-agnostic).

If you see:

```text
error: externally-managed-environment
```

you are installing into system/Homebrew Python. Use the virtualenv interpreter path (`./.venv/bin/python -m pip ...`) instead.

## Validate Rules Against Repo Samples

Automated validation (recommended):

```sh
./.venv/bin/python ./bin/yara-generator/validate-malicious-rules.py
```

Useful options:

```sh
# Reuse existing generated rules (skip regeneration)
./.venv/bin/python ./bin/yara-generator/validate-malicious-rules.py --skip-generate

# Write outputs to a custom folder
./.venv/bin/python ./bin/yara-generator/validate-malicious-rules.py --output-dir /tmp/yara-malicious-validation
```

The script writes hit files and a JSON summary (default: `/tmp/yara-malicious-validation/summary.json`).
It reports `intentionally skipped samples` separately (from `SKIP_DRIVERS`) and excludes them from `missing expected matches`.
It also reports root-cause breakdown for missing matches (`no PE FileInfo`, `insufficient VersionInfo strings`, `no YAML for grouped representative`, `grouped into vulnerable rule`).
When `--skip-generate` is used and no generator log exists yet, the script creates a temporary generator log under the output directory so missing matches can still be classified without rewriting the checked-in rule files.
The script exits with status `2` if `missing_reason_counts.unknown` is greater than `0`, which makes it suitable for CI.

Manual validation commands (equivalent workflow):

Run these commands from the repository root to confirm malicious-driver rules match malicious samples tracked in `yaml/`.

```sh
cd /path/to/LOLDrivers
./.venv/bin/python ./bin/yara-generator/yara-generator.py
```

Scan all driver samples with both malicious rule sets:

```sh
yara -r ./detections/yara/yara-rules_mal_drivers.yar ./drivers > /tmp/yara-mal-hits.txt
yara -r ./detections/yara/other/yara-rules_mal_drivers_strict.yar ./drivers > /tmp/yara-mal-strict-hits.txt
```

Quick hit counts:

```sh
wc -l /tmp/yara-mal-hits.txt /tmp/yara-mal-strict-hits.txt
awk '{print $2}' /tmp/yara-mal-hits.txt | sort -u | wc -l
awk '{print $2}' /tmp/yara-mal-strict-hits.txt | sort -u | wc -l
```

Get a full analytics summary (including missing/extra sets with hash-to-file mapping):

```sh
./.venv/bin/python ./bin/yara-generator/validate-malicious-rules.py --skip-generate --json-output
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
