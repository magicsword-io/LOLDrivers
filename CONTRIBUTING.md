# Contributing to LOLDrivers 🚗💨

First off, thank you for considering contributing to LOLDrivers! Your help is invaluable in keeping this project up-to-date and useful for the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Adding Drivers](#adding-drivers)
- [Naming Conventions](#naming-conventions)
- [YAML Validation](#yaml-validation)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Development Workflow](#development-workflow)

---

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Getting Started

### Prerequisites

- Python 3.11+
- Poetry (for dependency management)
- Git (for version control)

### Setup Your Development Environment

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/YOUR-USERNAME/LOLDrivers.git
   cd LOLDrivers
   ```

2. **Install dependencies with Poetry:**
   ```bash
   poetry install
   ```

3. **Install git hooks (for validation on commit/push):**
   ```bash
   bash bin/install-git-hooks.sh
   ```

4. **Verify setup:**
   ```bash
   poetry run python bin/validate.py -v
   ```

---

## Adding Drivers

### Overview

Drivers are documented in individual YAML files under the `yaml/` directory. Each file is named after the driver's unique UUID (e.g., `77363871-44a7-4d98-9fdc-46d7db0352f2.yaml`).

### Step 1: Use the Template

Start with the [YML-Template.yml](YML-Template.yml) as a reference. Here's a minimal example:

```yaml
Id: 77363871-44a7-4d98-9fdc-46d7db0352f2
Author: Your Name
Created: '2024-01-31'
MitreID: T1068
Category: vulnerable driver
Verified: 'TRUE'
Tags:
  - example.sys
Resources:
  - https://example.com/vulnerability
Commands:
  Command: sc.exe create example.sys binPath=C:\windows\temp\example.sys && sc.exe start example.sys
  Description: Load vulnerable driver
  Usecase: Privilege escalation
  Privileges: user
  OperatingSystem: Windows 10
Detection: []
Acknowledgement:
  Person: Your Name
  Handle: '@your_handle'
KnownVulnerableSamples:
  - Filename: example.sys
    SHA256: abc123...
```

### Step 2: Generate a UUID

Each driver file must have a unique UUID (v4). Generate one here: https://www.uuidgenerator.net/version4

**Important:** The filename must match the UUID exactly.

### Step 3: Populate Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `Id` | Unique UUID (must match filename) | `77363871-44a7-4d98-9fdc-46d7db0352f2` |
| `Author` | Your name or organization | `John Doe` |
| `Created` | Date discovered/submitted (YYYY-MM-DD) | `2024-01-31` |
| `MitreID` | MITRE ATT&CK technique | `T1068` (Abuse Elevation Control Mechanism) |
| `Category` | Type of driver | `vulnerable driver` or `malicious driver` |
| `Verified` | Validation status | `TRUE` or `FALSE` |
| `Resources` | URLs to CVEs, blog posts, PoCs | `https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234` |
| `Tags` | Alternative filenames | `["example.sys", "renamed.sys"]` |

### Step 4: Document the Vulnerability

Provide clear, technical details in the `Commands` section:

- **Command**: How to abuse/load the driver
- **Description**: What the command does
- **Usecase**: Attack scenario (e.g., "Privilege escalation", "Bypass code integrity")
- **Privileges**: Required privilege level (user, admin, kernel)
- **OperatingSystem**: Affected OS versions

Example:
```yaml
Commands:
  Command: sc.exe create athpexnt.sys binPath=C:\windows\temp\athpexnt.sys type=kernel && sc.exe start athpexnt.sys
  Description: Allows unprivileged users to write to arbitrary physical memory via IOCTL 0x81000000
  Usecase: Kernel-level code execution and privilege escalation
  Privileges: user
  OperatingSystem: Windows 10
```

### Step 5: Add Hash Information

Include at least **one** cryptographic hash (MD5, SHA-1, or SHA-256):

```yaml
KnownVulnerableSamples:
  - Filename: example.sys
    MD5: 778b7feea3c750d44745d3bf294bd4ce
    SHA1: 2261198385d62d2117f50f631652eded0ecc71db
    SHA256: 04a85e359525d662338cae86c1e59b1d7aa9bd12b920e8067503723dc1e03162
```

**Hash Length Validation:**
- MD5: 32 hex characters
- SHA-1: 40 hex characters
- SHA-256: 64 hex characters

### Step 6: Add Detection Methods

If available, add detection rules:

```yaml
Detection:
  - type: Yara
    value: https://github.com/magicsword-io/LOLDrivers/blob/main/detections/yara/...
  - type: Sigma
    value: https://github.com/magicsword-io/LOLDrivers/blob/main/detections/sigma/...
```

---

## Naming Conventions

### File Names
- **UUID format**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.yaml`
- **Example**: `77363871-44a7-4d98-9fdc-46d7db0352f2.yaml`
- **Rule**: Filename must exactly match the `Id` field

### Categories
Use standardized categories to ensure consistency:
- `vulnerable driver` – Legitimate driver with exploitable vulnerability
- `malicious driver` – Purpose-built malware/rootkit

### Tags
List all known filenames under which the driver is deployed:
```yaml
Tags:
  - primary_name.sys
  - alternate_name.dll
  - obfuscated_hash.sys
```

---

## YAML Validation

### Local Validation

Before committing, validate your YAML files:

```bash
# Validate specific file
poetry run python bin/validate.py yaml/77363871-44a7-4d98-9fdc-46d7db0352f2.yaml

# Validate all files in yaml/ directory
poetry run python bin/validate.py -v

# Validation runs automatically on:
# • git commit (pre-commit hook)
# • git push (pre-push hook)
```

### Validation Checks

The validator ensures:
- ✅ YAML is syntactically correct
- ✅ All required fields are present
- ✅ Field types match schema
- ✅ Filenames match UUID in `Id` field
- ✅ Hash lengths are correct
- ✅ At least one hash per sample
- ✅ UUID format is valid

### Common Errors

| Error | Solution |
|-------|----------|
| `Filename does not match Id` | Ensure file is named after the UUID |
| `MD5 length is not 32 characters` | Check hash for typos |
| `Missing required field` | Verify all required fields are present |
| `Invalid UUID format` | Use a valid UUIDv4 |

---

## Submitting Pull Requests

### Before You Submit

1. **Test locally:**
   ```bash
   poetry run python bin/validate.py -v
   ```

2. **Check for duplicates:**
   - Search [issues](https://github.com/magicsword-io/LOLDrivers/issues) for existing submissions
   - Verify driver isn't already in the database

3. **Use the PR template:**
   - Fill out all checklist items
   - Link related issues with `Closes #123`
   - Provide clear commit messages

### PR Workflow

1. **Create a branch:**
   ```bash
   git checkout -b feature/add-driver-athpexnt
   ```

2. **Make your changes:**
   ```bash
   # Add new YAML file
   cp YML-Template.yml yaml/77363871-44a7-4d98-9fdc-46d7db0352f2.yaml
   # Edit the file with driver details
   ```

3. **Commit with a descriptive message:**
   ```bash
   git add yaml/77363871-44a7-4d98-9fdc-46d7db0352f2.yaml
   git commit -m "Add athpexnt.sys (physical memory write vulnerability)

   - Driver: Qualcomm Atheros driver (athpexnt.sys)
   - Vulnerability: Unprivileged physical memory write via IOCTL 0x81000000
   - CVE: CVE-XXXX-XXXXX (if applicable)
   - References: https://example.com/analysis"
   ```

4. **Push and create PR:**
   ```bash
   git push origin feature/add-driver-athpexnt
   ```

### PR Checklist

Ensure your PR includes:

- [ ] Descriptive title: `Add [driver name]` or `Fix: [description]`
- [ ] Clear description of changes
- [ ] Link to related issue(s): `Closes #123`
- [ ] YAML validation passes
- [ ] All required fields populated
- [ ] At least one hash provided
- [ ] References to authoritative sources
- [ ] No sensitive data or malware samples

---

## Development Workflow

### Local Validation Hooks

Git hooks run automatically on commit/push. To bypass (not recommended):

```bash
git commit --no-verify  # Skip pre-commit hook
git push --no-verify    # Skip pre-push hook
```

### Uninstall Hooks

```bash
rm .git/hooks/{pre-commit,pre-push}
```

### Manual Validation Commands

```bash
# Full validation
poetry run python bin/validate.py -v

# Validate specific file
poetry run python bin/validate.py yaml/FILENAME.yaml

# Generate counter stats
poetry run python bin/gen-counter.py

# Generate site content
poetry run python bin/site.py
```

---

## Project Structure

```
LOLDrivers/
├── yaml/                      # Driver YAML files (indexed by UUID)
├── bin/                       # Utility scripts
│   ├── validate.py           # Schema validation
│   ├── gen-counter.py        # Statistics generator
│   ├── git-hooks/            # Git hook scripts
│   └── spec/
│       └── drivers.spec.json  # JSON schema definition
├── detections/               # Detection rules (Yara, Sigma, etc.)
├── .github/
│   ├── workflows/            # GitHub Actions
│   ├── ISSUE_TEMPLATE/       # Issue templates
│   └── PULL_REQUEST_TEMPLATE.md
├── CONTRIBUTING.md           # This file
├── DEVELOPERS.md             # Architecture & internals
└── YML-Template.yml          # Template for new drivers
```

---

## Getting Help

- **Questions?** Check [existing issues](https://github.com/magicsword-io/LOLDrivers/issues)
- **Need clarification?** Comment on an issue or ask in discussion threads
- **Found a bug?** [File a bug report](.github/ISSUE_TEMPLATE/bug-report.md)
- **Have a suggestion?** Open a [discussion](https://github.com/magicsword-io/LOLDrivers/discussions)

---

## Acknowledgment

Your contributions will be acknowledged in:
- Commit history
- Release notes (for significant contributions)
- Project documentation

Thank you for making LOLDrivers better! 🚀
