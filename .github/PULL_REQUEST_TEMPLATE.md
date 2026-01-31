# Pull Request

## Description

<!-- Brief description of changes -->

## Type of Change

- [ ] New driver(s) added
- [ ] Driver data updated
- [ ] Bug fix
- [ ] Documentation update
- [ ] Workflow/tooling improvement
- [ ] Other (please describe)

## Related Issue(s)

<!-- Link issues with Closes, Fixes, or Related to -->
Closes #
Fixes #
Related to #

## Changes Made

<!-- Detailed list of changes -->

- 
- 

## Validation

- [ ] All YAML files pass schema validation
- [ ] Filenames match UUID in `Id` field
- [ ] Hash lengths are correct (MD5: 32, SHA-1: 40, SHA-256: 64)
- [ ] At least one hash provided per vulnerable sample
- [ ] Resources/references are valid URLs
- [ ] Category is standardized (use `vulnerable driver` or `malicious driver`)

## Driver Details (for new drivers)

If adding new driver(s), please confirm:

- [ ] Driver name clearly identified
- [ ] At least one cryptographic hash provided
- [ ] Vulnerability or malicious behavior described
- [ ] Required privileges documented
- [ ] Operating system compatibility specified
- [ ] References/resources provided
- [ ] Detection methods included (if available)

## Testing

<!-- Describe any local testing performed -->

- [ ] Ran `poetry run python bin/validate.py -v`
- [ ] Checked YAML syntax with linter
- [ ] Verified hashes match their algorithms

## Screenshots (Optional)

<!-- Add screenshots or code snippets if relevant -->

---

## Checklist

- [ ] I have read the CONTRIBUTING guidelines
- [ ] I have checked for duplicate drivers
- [ ] I have added sources for new data
- [ ] Code and YAML files follow project conventions
- [ ] I understand this PR may be updated by maintainers
