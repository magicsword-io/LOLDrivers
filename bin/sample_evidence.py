"""Static sample/evidence consistency checks; this module never loads a driver."""

import hashlib
import re
from pathlib import Path

from indicator_safety import Finding, RAW, SafetyError

POINTER = re.compile(rb"\Aversion https://git-lfs.github.com/spec/v1\r?\noid sha256:([a-f0-9]{64})\r?\nsize [1-9][0-9]*\r?\n\Z")


def check_samples(records, drivers_path):
    index = {}
    for driver in records:
        for i, sample in enumerate(driver["KnownVulnerableSamples"]):
            for algorithm in RAW:
                if algorithm in sample:
                    index.setdefault((algorithm, sample[algorithm].lower()), []).append((driver, i, sample))
    errors, review, checked, pointers = [], [], 0, 0
    for path in sorted(Path(drivers_path).rglob("*.bin")):
        data = path.read_bytes()
        pointer = POINTER.fullmatch(data) if len(data) < 1024 else None
        if pointer:
            actual = {"SHA256": pointer[1].decode()}
            pointers += 1
        else:
            actual = {a: hashlib.new(a.lower(), data).hexdigest() for a in RAW}
            checked += 1
        matches = {}
        for algorithm, value in actual.items():
            for driver, i, sample in index.get((algorithm, value), []):
                matches[(driver["Id"], i)] = driver, i, sample
        if not matches:
            review.append(Finding(str(path), "SHA256", actual["SHA256"], "unrelated-sample-review", "No raw digest links this binary to a catalog sample. Its bytes cannot create new blocking indicators; review attribution. Independently documented Authenticode rules retain their existing scope."))
        for driver, i, sample in matches.values():
            for algorithm, calculated in actual.items():
                declared = sample.get(algorithm)
                if declared and declared.lower() != calculated:
                    errors.append(Finding(f"yaml/{driver['Id']}.yaml", f"KnownVulnerableSamples[{i}].{algorithm}", declared, "sample-digest-mismatch", f"Reconcile sample evidence with {path.name}; calculated {algorithm}={calculated}. Do not fall back to a name or signer."))
    if errors:
        raise SafetyError(errors)
    return {"hydrated_binaries_checked": checked, "lfs_pointers_checked": pointers,
            "review_findings": [finding.__dict__ for finding in review]}
