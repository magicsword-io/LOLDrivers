# LOLDrivers Developer Guide

This guide provides technical documentation for developers and maintainers working on the LOLDrivers project.

## Table of Contents

1. [Project Structure](#project-structure)
2. [Version Tracking System](#version-tracking-system)
3. [Development Setup](#development-setup)
4. [Scripts and Tools](#scripts-and-tools)
5. [Data Quality Standards](#data-quality-standards)
6. [CI/CD Pipeline](#cicd-pipeline)

---

## Project Structure

```
LOLDrivers/
├── yaml/                          # Individual driver YAML files
│   ├── {uuid}.yaml               # One file per driver, named by UUID
│   └── ...
├── drivers.json                  # Consolidated driver database (auto-generated)
├── bin/                          # Utility scripts
│   ├── validate.py              # Schema validation
│   ├── gen-counter.py           # Driver count generation
│   ├── hvcitag.py               # HVCI compatibility tagging
│   └── update-versions.py       # Version synchronization (NEW)
├── loldrivers.io/               # Web frontend
├── detections/                  # Detection rules (YARA, Sigma, etc.)
├── .github/workflows/           # CI/CD pipelines
│   └── update-driver-versions.yml  # Automated version updates (NEW)
└── [configuration files]
```

---

## Version Tracking System

The version tracking system keeps driver version metadata synchronized between individual YAML files and the consolidated `drivers.json` file.

### Overview

When a driver is added to LOLDrivers, its version information comes from PE (Portable Executable) headers in the binary:

- **ProductVersion**: Version reported by PE metadata (e.g., "1.3.2.17")
- **FileVersion**: File version from PE header (e.g., "1.3.2.17 built by: WinDDK")
- **CreationTimestamp**: When the binary was compiled (e.g., "2018-09-17 05:18:08")

This information is stored in the `KnownVulnerableSamples` section of each driver's YAML file.

The `drivers.json` file consolidates this data for easier consumption by external tools.

### Version Schema

Each driver in `drivers.json` includes a `version` field:

```json
{
  "{driver-uuid}": {
    "name": "iqvw64e.sys",
    "category": "vulnerable driver",
    "version": {
      "product": "1.3.2.17",
      "file": "1.3.2.17 built by: WinDDK",
      "timestamp": "2018-09-17T05:18:08",
      "verified": "2024-01-31T20:45:00.123456"
    }
  }
}
```

**Fields:**
- `product`: ProductVersion from PE headers (string, may be None)
- `file`: FileVersion from PE headers (string, may be None)
- `timestamp`: CreationTimestamp of the binary (ISO format)
- `verified`: When the version info was last synchronized (ISO format, UTC)

### Automated Synchronization

Version synchronization happens automatically through CI/CD:

#### How It Works

1. **Trigger**: Changes to YAML files or scheduled weekly run
2. **Script**: `bin/update-versions.py` scans all YAML files
3. **Process**:
   - Reads each driver's `KnownVulnerableSamples` section
   - Extracts ProductVersion, FileVersion, CreationTimestamp
   - Finds the latest sample (by timestamp)
   - Updates `drivers.json` with new metadata
4. **Commit**: Changes automatically committed and pushed to main branch
5. **Logging**: All changes logged for audit trail

#### CI/CD Pipeline

The GitHub Actions workflow `.github/workflows/update-driver-versions.yml`:

- **Trigger events**:
  - Push to `yaml/*.yaml` files
  - Changes to `drivers.json`
  - Manual trigger (workflow_dispatch)
  - Weekly schedule (Sundays at midnight UTC)

- **Steps**:
  1. Checkout repository
  2. Set up Python 3.11
  3. Install PyYAML dependency
  4. Run `bin/update-versions.py --verbose`
  5. Detect changes to `drivers.json`
  6. Auto-commit and push if changes exist
  7. Comment on PRs if applicable
  8. Upload version log artifact

### Manual Synchronization

To manually run version synchronization:

```bash
# Run with default paths (yaml/ and drivers.json)
python bin/update-versions.py

# Run with custom paths
python bin/update-versions.py --yaml-dir ./yaml --json-file ./drivers.json

# Run with verbose output
python bin/update-versions.py --verbose
```

**Exit Codes:**
- `0`: Success (updates made or no updates needed)
- `1`: Failure (errors occurred, check output)

### Adding a New Driver

When adding a new driver via YAML:

1. **Create YAML file**: Name it `{uuid}.yaml` where uuid is unique
2. **Add KnownVulnerableSamples**: Include all samples with complete metadata:
   ```yaml
   KnownVulnerableSamples:
   - Filename: driver.sys
     MD5: abc123...
     SHA1: def456...
     SHA256: ghi789...
     ProductVersion: "1.2.3.4"
     FileVersion: "1.2.3.4 built by: WinDDK"
     CreationTimestamp: "2020-01-15 10:30:45"
     # ... other fields ...
   ```
3. **Push changes**: CI/CD automatically updates `drivers.json`
4. **Verify**: Check that version info appears in `drivers.json`

### Updating Driver Versions

If a driver's version changes:

1. **Update YAML file**: Modify `KnownVulnerableSamples` with new sample
2. **Include all fields**: Ensure ProductVersion, FileVersion, CreationTimestamp are present
3. **Push to repository**: CI/CD pipeline handles the rest
4. **No manual JSON editing**: `drivers.json` updates automatically

### Troubleshooting

**Version info not showing in drivers.json?**

1. Check YAML syntax: `python -m yaml yaml/{uuid}.yaml`
2. Verify KnownVulnerableSamples section exists
3. Ensure at least one sample has ProductVersion/FileVersion/CreationTimestamp
4. Run manually: `python bin/update-versions.py --verbose`
5. Check git log for auto-commit from version update workflow

**Script fails with "YAML parsing error"?**

1. Validate YAML syntax using an online YAML parser
2. Check for mixed tabs/spaces (must be consistent)
3. Ensure proper indentation (2 spaces per level)
4. Run syntax check: `python3 -m py_compile bin/update-versions.py`

**drivers.json is out of sync?**

```bash
# Force re-synchronize all versions
python bin/update-versions.py --yaml-dir ./yaml --json-file ./drivers.json

# Review changes
git diff drivers.json

# Commit and push
git commit -m "chore(data): Re-synchronize driver versions"
git push
```

---

## Development Setup

### Prerequisites

- Python 3.10+
- Git
- (Optional) Poetry for dependency management

### Environment Setup

```bash
# Clone repository
git clone https://github.com/magicsword-io/LOLDrivers.git
cd LOLDrivers

# Install dependencies (using Poetry)
poetry install

# Or using pip
pip install PyYAML pandas Jinja2 stix2
```

### Linting and Validation

```bash
# Validate YAML schema
python bin/validate.py

# Check for duplicate hashes
python bin/check-duplicates.py

# Verify HVCI compatibility
python bin/hvcitag.py

# Update version metadata
python bin/update-versions.py
```

---

## Scripts and Tools

### bin/validate.py

Validates all driver YAML files against the project schema.

```bash
python bin/validate.py
```

**Features:**
- Checks YAML syntax
- Validates against schema
- Reports missing required fields
- Type checking

### bin/gen-counter.py

Generates driver count and statistics badge.

```bash
python bin/gen-counter.py
```

**Output:**
- Badge URL for README
- Total driver count
- Category statistics

### bin/hvcitag.py

Tags drivers with HVCI (Hypervisor-Protected Code Integrity) compatibility.

```bash
python bin/hvcitag.py
```

**Features:**
- Reads HVCI compatibility CSV
- Tags compatible drivers
- Updates YAML files

### bin/update-versions.py

Synchronizes version metadata from YAML to drivers.json.

```bash
python bin/update-versions.py [--json-file PATH] [--yaml-dir PATH] [--verbose]
```

**Features:**
- Scans YAML files
- Extracts version info
- Updates JSON metadata
- Logs all changes
- Defensive error handling

---

## Data Quality Standards

### YAML File Requirements

Every driver YAML file must include:

1. **Basic Information**
   - `Id`: UUID (unique identifier)
   - `Tags`: List of driver names/aliases
   - `Verified`: TRUE/FALSE
   - `Author`: Credit to discoverer
   - `Created`: Initial submission date

2. **Technical Details**
   - `Category`: Must be "vulnerable driver"
   - `MitreID`: Relevant MITRE ATT&CK technique
   - `CVE`: List of CVE identifiers
   - `Commands`: How to load/exploit the driver

3. **Sample Information** (KnownVulnerableSamples)
   - `Filename`: Original driver filename
   - `MD5`, `SHA1`, `SHA256`: All hash types
   - `ProductVersion`: From PE header
   - `FileVersion`: From PE header
   - `CreationTimestamp`: Compilation date
   - `Signature`: Digital signature info
   - `Certificates`: Signing certificates

4. **Detection Rules**
   - YARA signatures
   - Sigma rules
   - Sysmon configurations

### Version Information Requirements

For each vulnerable sample, include:

```yaml
KnownVulnerableSamples:
- Filename: driver.sys
  ProductVersion: "1.2.3.4"          # Required for version tracking
  FileVersion: "1.2.3.4 built by..."  # Required for version tracking
  CreationTimestamp: "2020-01-15"     # Required for version tracking
  # ... other required fields ...
```

**Note:** Missing version information will result in incomplete `drivers.json` entries. Ensure all three fields are present.

### Validation Checklist

- [ ] YAML syntax is valid
- [ ] All required fields present
- [ ] ProductVersion, FileVersion, CreationTimestamp included
- [ ] Hashes verified (MD5, SHA1, SHA256)
- [ ] CVE references are accurate
- [ ] Detection rules provided
- [ ] No duplicate hashes in database
- [ ] Schema validation passes

---

## CI/CD Pipeline

### Workflows

#### 1. Update Driver Versions (`update-driver-versions.yml`)

**Triggered by:**
- Push to yaml/*.yaml files
- Changes to drivers.json
- Schedule: Weekly Sunday midnight UTC
- Manual trigger

**Actions:**
- Runs `bin/update-versions.py`
- Auto-commits changes to drivers.json
- Comments on PRs with results

#### 2. Validation (existing)

**Triggered by:**
- Push to main/develop
- Pull requests

**Actions:**
- Validates YAML schema
- Checks for duplicate hashes
- Verifies detection rules

### Adding New Workflows

To add a new CI/CD workflow:

1. Create file: `.github/workflows/your-workflow.yml`
2. Follow GitHub Actions syntax
3. Test locally with `act`
4. Reference existing workflows as examples

---

## Contributing to Development

### Code Standards

- **Python**: PEP 8 compliant
- **Type Hints**: Required for new functions
- **Docstrings**: Google-style, with Args, Returns, Raises
- **Error Handling**: Specific exception types, defensive programming

### PR Process

1. Fork the repository
2. Create feature branch: `feature/your-feature`
3. Make changes and commit atomically
4. Push to fork
5. Create PR with clear description
6. Wait for CI checks to pass
7. Request maintainer review
8. Address feedback
9. Merge when approved

### Testing

Run before submitting PR:

```bash
# Validate YAML
python bin/validate.py

# Update versions
python bin/update-versions.py

# Check syntax
python3 -m py_compile bin/*.py

# Run linter (if available)
pylint bin/*.py
```

---

## References

- [GitHub Issues](https://github.com/magicsword-io/LOLDrivers/issues)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [YAML Template](YML-Template.yml)

---

**Last Updated:** 2024-01-31  
**Maintainer:** LOLDrivers Project Team  
**License:** Check LICENSE file for details
