# DEVELOPERS.md - Architecture & Maintenance Guide

This document is for maintainers and contributors working on LOLDrivers infrastructure, validation tooling, and workflows.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Data Structure](#data-structure)
- [Validation System](#validation-system)
- [Workflows & Automation](#workflows--automation)
- [Development Tools](#development-tools)
- [Maintenance Tasks](#maintenance-tasks)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Core Components

```
┌─ Data Layer
│  └─ yaml/                 # Driver records (UUID-indexed)
│  └─ bin/spec/             # Schema definitions
│
├─ Validation Layer
│  └─ bin/validate.py       # Schema validator
│  └─ Git hooks             # Local enforcement
│  └─ GitHub Actions        # Remote enforcement
│
├─ Generation Layer
│  └─ bin/gen-counter.py    # Statistics
│  └─ bin/gen-files.py      # Site generation
│  └─ bin/site.py           # Website builder
│
└─ Detection Layer
   └─ detections/           # Yara, Sigma, etc.
```

### Data Flow

1. **Contribution**: User submits driver via PR
2. **Validation**: Pre-commit hook validates locally
3. **Review**: Maintainers review for accuracy
4. **Merge**: PR merged to main branch
5. **CI/CD**: GitHub Actions rebuild detections & site
6. **Distribution**: Updated files available via CDN

---

## Data Structure

### YAML Schema

Located at `bin/spec/drivers.spec.json` (JSON Schema Draft-07)

#### Required Fields

```yaml
Id                      # UUIDv4 string (must match filename)
Author                  # Person/org who submitted
Created                 # ISO date (YYYY-MM-DD)
MitreID                 # MITRE ATT&CK technique ID
Category                # "vulnerable driver" or "malicious driver"
Verified                # "TRUE" or "FALSE"
Resources               # Array of URLs
```

#### Optional Fields

```yaml
CVE                     # Array of CVE IDs
Commands                # Exploitation/usage instructions
Acknowledgement         # Credit to discoverer
Tags                    # Alternative filenames
Detection               # Detection methods (Yara, Sigma, etc.)
KnownVulnerableSamples  # File hashes and metadata
```

### File Organization

- **Naming**: `{UUID}.yaml`
- **Location**: `yaml/`
- **Sorting**: Alphabetical by UUID (allows O(1) lookup)

### Sample Entry

```yaml
Id: 77363871-44a7-4d98-9fdc-46d7db0352f2
Tags:
  - athpexnt.sys
Author: Security Researcher
Created: '2024-01-31'
MitreID: T1068
Category: vulnerable driver
Verified: 'TRUE'
Commands:
  Command: sc.exe create athpexnt.sys binPath=C:\windows\temp\athpexnt.sys
  Description: Physical memory write via IOCTL
  Usecase: Privilege escalation
  Privileges: user
  OperatingSystem: Windows 10
Resources:
  - https://example.com/analysis
Detection: []
Acknowledgement:
  Person: John Doe
  Handle: '@johndoe'
KnownVulnerableSamples:
  - Filename: athpexnt.sys
    SHA256: fa0902daefbd9e716faaac8e854144ea0573e2a41192796f3b3138fe7a1d19f1
    MD5: bf77a19e1396d6d36e32ff8d23eb5d3f
```

---

## Validation System

### Validator (bin/validate.py)

**Purpose**: Ensure YAML files conform to schema and have correct structure.

**Checks Performed**:
1. YAML syntax is valid
2. All required fields present
3. Field types match schema
4. Filename matches UUID in `Id` field
5. Hash lengths correct (MD5: 32, SHA-1: 40, SHA-256: 64)
6. At least one hash per sample
7. UUID format valid (RFC 4122)

**Usage**:

```bash
# Validate all YAML files
poetry run python bin/validate.py -v

# Validate specific file(s)
poetry run python bin/validate.py yaml/77363871-44a7-4d98-9fdc-46d7db0352f2.yaml

# Get validation summary
poetry run python bin/validate.py -v 2>&1 | tail -20
```

**Output**:
- Exit code 0: All valid
- Exit code 1: Errors found
- Exit code 2: Setup error

### Git Hooks

Located in `bin/git-hooks/`

#### pre-commit

- Runs on `git commit`
- Validates staged YAML files only
- Can be bypassed with `git commit --no-verify`

#### pre-push

- Runs on `git push`
- Validates all YAML files
- Final safety check before remote push

#### Installation

```bash
bash bin/install-git-hooks.sh
```

### GitHub Actions

Located in `.github/workflows/`

#### validate-pr.yml

- Trigger: On every PR targeting `main`
- Actions:
  - Validates changed YAML files
  - Re-validates all if schema changes
  - Comments on PR if failures

#### auto-tag-issues.yml

- Trigger: When PR is opened
- Actions:
  - Extracts linked issues from PR body
  - Copies labels from linked issues to PR

#### stale-issues.yml

- Trigger: Daily at 00:00 UTC
- Actions:
  - Marks issues inactive 90+ days as `stale`
  - Closes issues inactive 120+ days
  - Similar for PRs (60/90 days)

---

## Workflows & Automation

### GitHub Actions Pipeline

```
PR Opened
  ├─ validate-pr.yml
  │  └─ Validate YAML schema
  ├─ auto-tag-issues.yml
  │  └─ Add labels from linked issues
  └─ [Run tests]

PR Merged to main
  ├─ validate.yml
  │  └─ Full validation
  ├─ generate-site.yml
  │  └─ Rebuild loldrivers.io
  ├─ generate-counter.yml
  │  └─ Update statistics
  └─ deploy.yml
     └─ Deploy to production

Daily (00:00 UTC)
  └─ stale-issues.yml
     └─ Mark/close inactive issues
```

### Environment Setup

**Requirements**:
- Python 3.11+
- Poetry 1.2+
- Git 2.30+

**Install**:
```bash
poetry install
bash bin/install-git-hooks.sh
```

---

## Development Tools

### validate.py

**Type**: Validation engine  
**Language**: Python 3  
**Dependencies**: PyYAML, jsonschema

**Key Functions**:
- `validate_schema()` – Validate against JSON schema
- `check_filename_matches_id()` – Verify UUID-filename match
- `check_hash_length()` – Verify hash field lengths
- `_load_schema()` – Load schema from JSON file

**Example Usage**:
```python
import subprocess
result = subprocess.run(
    ['poetry', 'run', 'python', 'bin/validate.py', '-v'],
    capture_output=True,
    text=True
)
```

### gen-counter.py

**Type**: Statistics generator  
**Language**: Python 3  
**Output**: Counter stats for metrics tracking

**Example**:
```bash
poetry run python bin/gen-counter.py
# Outputs: total drivers, vulnerable count, malicious count, etc.
```

### gen-files.py

**Type**: Detection rule generator  
**Language**: Python 3  
**Output**: Yara, Sigma, and other detection rules

**Example**:
```bash
poetry run python bin/gen-files.py
# Generates YARA rules from all driver entries
```

---

## Maintenance Tasks

### Daily

- Monitor PRs for validation failures
- Review opened issues for duplicates
- Check stale issue workflow results

### Weekly

- Review merged PRs for quality
- Update CONTRIBUTING.md if needed
- Check for new CVEs affecting drivers

### Monthly

- Run full validation suite
- Generate and review statistics
- Update documentation/README

### Quarterly

- Review schema for necessary changes
- Audit YAML files for data quality
- Update MITRE ATT&CK mappings
- Tag new releases

### Annually

- Review project governance
- Plan major feature additions
- Community feedback review

---

## Troubleshooting

### Common Issues

#### "Filename does not match Id"

**Cause**: YAML filename ≠ UUID in `Id` field

**Fix**:
```bash
# Rename file to match UUID
mv yaml/wrongname.yaml yaml/77363871-44a7-4d98-9fdc-46d7db0352f2.yaml
```

#### "MD5 length is not 32 characters"

**Cause**: Hash has typo or incorrect format

**Fix**:
```bash
# Verify hash length
echo -n "abc123..." | wc -c  # Should output 32 for MD5
```

#### "Missing required field"

**Cause**: Required field not in YAML

**Fix**: Add missing field from schema:
- `Id`, `Author`, `Created`, `MitreID`, `Category`, `Verified`, `Resources`, `Tags`

#### Pre-commit hook not running

**Cause**: Hook not installed or not executable

**Fix**:
```bash
bash bin/install-git-hooks.sh
chmod +x .git/hooks/pre-commit
```

#### Schema validation fails locally but passes on GitHub

**Cause**: Python version mismatch or missing dependencies

**Fix**:
```bash
poetry install
poetry run python bin/validate.py -v
```

### Debug Mode

Enable verbose output for troubleshooting:

```bash
poetry run python bin/validate.py -v yaml/FILENAME.yaml
# Shows detailed validation steps
```

### Checking Git Hook Status

```bash
# List installed hooks
ls -la .git/hooks/

# Test pre-commit hook
.git/hooks/pre-commit

# Test pre-push hook (dry-run)
.git/hooks/pre-push
```

---

## Best Practices

### For New Contributors

1. ✅ Read CONTRIBUTING.md first
2. ✅ Set up development environment locally
3. ✅ Install git hooks
4. ✅ Test validation before committing
5. ✅ Use PR template
6. ✅ Link related issues

### For Maintainers

1. ✅ Review PRs promptly (target: 48h)
2. ✅ Request changes for schema violations
3. ✅ Verify hash accuracy via VirusTotal/official sources
4. ✅ Check for duplicate drivers before merge
5. ✅ Update stale issues monthly
6. ✅ Monitor validation workflows
7. ✅ Keep dependencies updated
8. ✅ Document any schema changes

### For Data Quality

1. ✅ Require at least one verified hash
2. ✅ Cross-reference CVEs with official sources
3. ✅ Standardize category names
4. ✅ Include detection rules when available
5. ✅ Add proper attribution/acknowledgment
6. ✅ Ensure resources are stable/archivable

---

## Contributing to Infrastructure

### Adding a New Validation Check

1. Edit `bin/validate.py`
2. Add function to `validate_schema()`
3. Return error message if check fails
4. Update tests in CI
5. Document in DEVELOPERS.md

### Updating the Schema

1. Modify `bin/spec/drivers.spec.json`
2. Update YAML template
3. Update CONTRIBUTING.md examples
4. Run full validation: `poetry run python bin/validate.py -v`
5. Update DEVELOPERS.md

### Adding a New Workflow

1. Create `.github/workflows/yourworkflow.yml`
2. Add appropriate triggers
3. Document in DEVELOPERS.md
4. Test in branch before merge

---

## Resources

- **JSON Schema Draft-07**: https://json-schema.org/draft-07/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **GitHub Actions**: https://docs.github.com/en/actions
- **Poetry**: https://python-poetry.org/docs/
- **PyYAML**: https://pyyaml.org/wiki/PyYAMLDocumentation

---

**Last Updated**: 2024-01-31  
**Maintainer**: LOLDrivers Team
