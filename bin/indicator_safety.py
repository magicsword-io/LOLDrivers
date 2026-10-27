"""Offline indicator contract shared by every catalog consumer.

Only complete file/Authenticode digests are blocking indicators. Names are
explicitly hunting selectors; PE metadata, import hashes and certificates are
research evidence. Validation is performed before exclusion/normalization.
"""

from __future__ import annotations

import base64
import copy
import fnmatch
import hashlib
import json
import ntpath
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

LENGTHS = {"MD5": 32, "SHA1": 40, "SHA256": 64, "SHA384": 96, "SHA512": 128}
RAW = ("MD5", "SHA1", "SHA256")
PLACEHOLDERS = {"", "-", "n/a", "na", "none", "null", "unknown", "tbd", "todo"}
GENERIC = {"driver", "monitor", "dump", "test", "sample", "unknown", "null", "file",
           "ntoskrnl", "ntkrnlmp", "hal", "win32k", "kernel32", "ntdll", "svchost",
           "system", "setup", "update", "service", "winload", "disk", "acpi", "tcpip",
           "microsoft", "windows", "device", "windowsdriver", "sys", "exe", "dll"}
GENERIC.update({"cmd", "powershell", "pwsh", "services", "lsass", "explorer", "rundll32",
                "regsvr32", "dllhost", "winlogon", "wininit", "smss", "csrss", "wdf01000",
                "wdfldr", "fltmgr", "ndis", "dxgkrnl", "win32kbase", "win32kfull", "storport",
                "stornvme", "classpnp", "ntfs", "volmgr", "partmgr", "usb", "kernel", "filter"})


class CatalogLoader(yaml.SafeLoader):
    """Avoid ambiguous indicators hidden behind duplicate YAML mapping keys."""


def _unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError("catalog mapping", node.start_mark,
                                                    f"duplicate field {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


CatalogLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def load_yaml(stream):
    return yaml.load(stream, Loader=CatalogLoader)


@dataclass(frozen=True)
class Finding:
    source: str
    field: str
    value: object
    rule: str
    remediation: str

    def __str__(self):
        return (f"{self.source}: {self.field}={self.value!r} [{self.rule}]: "
                f"{self.remediation}")


class SafetyError(ValueError):
    def __init__(self, findings):
        self.findings = findings
        super().__init__("\n".join(map(str, findings)))


def fail(source, field, value, rule, remediation):
    raise SafetyError([Finding(str(source), field, value, rule, remediation)])


def digest(value, algorithm, source="<selector>", field="hash"):
    length = LENGTHS[algorithm]
    if (not isinstance(value, str) or not re.fullmatch(rf"[0-9a-fA-F]{{{length}}}", value)
            or len(set(value.lower())) == 1
            or value.lower() in {("0123456789abcdef" * 8)[:length], ("deadbeef" * 16)[:length]}):
        fail(source, field, value, "digest", f"Supply the actual {algorithm} ({length} hex characters); omit unavailable optional hashes.")
    return value.lower()


def generic_stem(stem):
    return stem in GENERIC or bool(re.fullmatch(r"(?:driver|monitor|dump|test|sample|unknown|file|kernel|service|setup|update)(?:32|64|x86|x64|amd64)?[0-9_-]*", stem))


def filename(value, source="<selector>", field="filename", *, reviewed=False):
    if not isinstance(value, str):
        fail(source, field, value, "filename", "Supply a driver-specific filename.")
    name = value.strip().strip("\"'").strip().replace("/", "\\").casefold()
    if (name in PLACEHOLDERS or any(ord(c) < 32 for c in name)
            or any(c in name for c in '%${}<>|"\'') or re.search(r"\[[^]]*\]", name)):
        fail(source, field, value, "filename", "Remove placeholders, templates and variable expansion; preserve evidence under ResearchEvidence.")
    # Validate what a Windows basename consumer sees, including trailing dots/spaces.
    name = ntpath.basename(name).rstrip(" .")
    stem, ext = ntpath.splitext(name)
    if name in {".sys", ".dll", ".exe", "filename.sys", "filename.exe", "filename.dll", "placeholder.sys", "example.sys"}:
        fail(source, field, value, "placeholder", "Replace extension-only names and template filenames with a documented driver identity.")
    literal = re.sub(r"[*? ._-]", "", stem)
    if not literal or ext in {".*", ""} and not literal:
        fail(source, field, value, "catch-all", "An extension or wildcard-only stem cannot identify a driver, even inside a specific directory.")
    if "*" in name or "?" in name:
        if not reviewed or len(re.sub(r"[^a-z]", "", literal)) < 4 or generic_stem(literal):
            fail(source, field, value, "wildcard-review", "Use an exact driver identity or a reviewed driver-specific pattern with positive and negative examples.")
    return name


def specific_name(value):
    name = filename(value)
    stem, ext = ntpath.splitext(name)
    return bool(ext in {".sys", ".dll", ".exe", ".dat"} and not generic_stem(stem))


def active(item):
    return item.get("DetectionScope", "active") != "context-only"


def _scope(item, source, field):
    scope = item.get("DetectionScope", "active")
    if scope not in {"active", "context-only"}:
        fail(source, field + ".DetectionScope", scope, "scope", "Use active or context-only.")
    if scope == "context-only" and not str(item.get("ContextReason") or "").strip():
        fail(source, field + ".ContextReason", item.get("ContextReason"), "scope", "Explain why this evidence must not produce a detection.")


def _hash_map(values, source, field, allowed=RAW):
    if not isinstance(values, dict):
        fail(source, field, values, "digest-type", "Use an algorithm-to-digest mapping, or omit unavailable evidence.")
    for algorithm, value in values.items():
        if algorithm not in allowed:
            fail(source, field + "." + str(algorithm), value, "digest-type", "Use a supported explicit hash algorithm; do not mix hash namespaces.")
        digest(value, algorithm, source, field + "." + algorithm)


@lru_cache(maxsize=16384)
def _certificate_check(encoded):
    """Parse embedded evidence, without doing network/chain trust validation."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    if isinstance(encoded, bytes):
        der = encoded
        cert = x509.load_der_x509_certificate(der)
    elif encoded.startswith("-----BEGIN CERTIFICATE-----"):
        cert = x509.load_pem_x509_certificate(encoded.encode("ascii"))
        der = cert.public_bytes(serialization.Encoding.DER)
    else:
        der = base64.b64decode("".join(encoded.split()), validate=True)
        cert = x509.load_der_x509_certificate(der)
    if cert.public_bytes(serialization.Encoding.DER) != der:
        raise ValueError("noncanonical DER or trailing certificate bytes")
    return cert, cert.public_bytes(serialization.Encoding.DER)


def validate_certificate(cert, source, field):
    if not isinstance(cert, dict):
        fail(source, field, cert, "certificate", "Use structured certificate evidence.")
    if "TBS" in cert:
        _hash_map(cert["TBS"], source, field + ".TBS", LENGTHS)
    for key in ("Thumbprint", "Fingerprint"):
        if key in cert:
            value = cert[key]
            if isinstance(value, dict):
                _hash_map(value, source, field + "." + key, LENGTHS)
            else:
                digest(value, "SHA1", source, field + "." + key)
    for key in ("ValidFrom", "ValidTo"):
        if key in cert:
            try:
                datetime.fromisoformat(str(cert[key]).replace("Z", "+00:00"))
            except ValueError:
                fail(source, field + "." + key, cert[key], "certificate-validity", "Provide the certificate's ISO validity time (expired historical certificates are allowed).")
    if cert.get("ValidFrom") and cert.get("ValidTo"):
        times = [datetime.fromisoformat(str(cert[k]).replace("Z", "+00:00")) for k in ("ValidFrom", "ValidTo")]
        times = [d.replace(tzinfo=d.tzinfo or timezone.utc) for d in times]
        if times[0] > times[1]:
            fail(source, field, cert, "certificate-validity", "ValidFrom must precede ValidTo.")
    embedded = [cert[k] for k in ("DER", "Base64", "PEM") if k in cert]
    if not embedded:
        return  # Legacy catalog has TBS and subject evidence, but no DER/provenance.
    try:
        parsed, der = _certificate_check(embedded[0])
        for extra in embedded[1:]:
            if _certificate_check(extra)[1] != der:
                raise ValueError("embedded representations disagree")
    except Exception as exc:
        fail(source, field + ".DER/Base64/PEM", "<embedded certificate>", "certificate-encoding", f"Supply a valid, consistent X.509 certificate: {exc}")
    for key, actual in (("Subject", parsed.subject), ("Issuer", parsed.issuer)):
        if key in cert and cert[key] != actual.rfc4514_string():
            fail(source, field + "." + key, cert[key], "certificate-identity", f"Reconcile evidence with embedded certificate ({actual.rfc4514_string()}); this is not a chain trust check.")
    for algorithm, declared in cert.get("TBS", {}).items():
        actual = hashlib.new(algorithm.lower(), parsed.tbs_certificate_bytes).hexdigest()
        if actual != declared.lower():
            fail(source, field + ".TBS." + algorithm, declared, "certificate-tbs", "Reconcile the declared TBS digest with the embedded certificate.")
    for key in ("Thumbprint", "Fingerprint"):
        declared = cert.get(key, {})
        if isinstance(declared, str):
            declared = {"SHA1": declared}
        for algorithm, value in declared.items():
            if hashlib.new(algorithm.lower(), der).hexdigest() != value.lower():
                fail(source, field + "." + key, value, "certificate-fingerprint", "Hash the complete DER certificate, separately from its TBS bytes.")
    before = parsed.not_valid_before_utc if hasattr(parsed, 'not_valid_before_utc') else parsed.not_valid_before.replace(tzinfo=timezone.utc)
    after = parsed.not_valid_after_utc if hasattr(parsed, 'not_valid_after_utc') else parsed.not_valid_after.replace(tzinfo=timezone.utc)
    for key, actual in (("ValidFrom", before), ("ValidTo", after)):
        if key in cert:
            declared = datetime.fromisoformat(str(cert[key]).replace("Z", "+00:00"))
            if declared.replace(tzinfo=declared.tzinfo or timezone.utc) != actual:
                fail(source, field + "." + key, cert[key], "certificate-validity", "Reconcile validity metadata with the embedded certificate; do not delete expired evidence.")


def validate_record(record, source="<record>"):
    if not isinstance(record, dict):
        fail(source, "$", record, "record", "Supply a YAML mapping.")
    _scope(record, source, "$")
    if not isinstance(record.get("Tags"), list) or not record["Tags"]:
        fail(source, "Tags", record.get("Tags"), "identity", "Keep at least one human-readable driver label.")
    if active(record):
        for i, tag in enumerate(record["Tags"]):
            # Labels without an extension are evidence too, but must never be wildcards/templates.
            filename(tag, source, f"Tags[{i}]")
    samples = record.get("KnownVulnerableSamples")
    if not isinstance(samples, list) or active(record) and not samples:
        fail(source, "KnownVulnerableSamples", samples, "hashless", "Supply a known affected sample with an exact file/Authenticode digest, or designate the record context-only with a reason.")
    for i, sample in enumerate(samples or []):
        field = f"KnownVulnerableSamples[{i}]"
        if not isinstance(sample, dict):
            fail(source, field, sample, "sample", "Use a sample mapping.")
        _scope(sample, source, field)
        for algorithm in RAW:
            if algorithm in sample:
                digest(sample[algorithm], algorithm, source, field + "." + algorithm)
        for key in ("Authentihash", "PageHash", "RichPEHeaderHash"):
            if key in sample:
                _hash_map(sample[key], source, field + "." + key)
        for algorithm in RAW:
            for prefix in ("Authentihash", "RichPEHeader", "PageHash"):
                key = prefix + algorithm
                if key in sample:
                    digest(sample[key], algorithm, source, field + "." + key)
            alias = "Authentihash" + algorithm
            if alias in sample and algorithm in sample.get("Authentihash", {}):
                if sample[alias].lower() != sample["Authentihash"][algorithm].lower():
                    fail(source, field + "." + alias, sample[alias], "digest-conflict", "Reconcile conflicting aliases for the same Authenticode digest.")
        if "Imphash" in sample:
            digest(sample["Imphash"], "MD5", source, field + ".Imphash")
        if active(record) and active(sample) and not (any(sample.get(k) for k in RAW) or authentihashes(sample)):
            fail(source, field, sample.get("Filename"), "hashless", "Supply an exact file/Authenticode digest; import/page/certificate hashes and names alone are insufficient. Otherwise use context-only and ContextReason.")
        for j, signature in enumerate(sample.get("Signatures") or []):
            if not isinstance(signature, dict):
                fail(source, field + ".Signatures", signature, "certificate", "Use structured signing evidence.")
            for n, cert in enumerate(signature.get("Certificates") or []):
                validate_certificate(cert, source, f"{field}.Signatures[{j}].Certificates[{n}]")
    if active(record) and not any(active(s) for s in samples):
        fail(source, "KnownVulnerableSamples", [], "hashless", "Designate the entire research-only record context-only.")
    for i, reviewed in enumerate(record.get("DetectionNames", [])):
        field = f"DetectionNames[{i}]"
        if (not isinstance(reviewed, dict) or reviewed.get("Reviewed") is not True
                or not reviewed.get("Reason") or not reviewed.get("PositiveExamples") or not reviewed.get("NegativeExamples")):
            fail(source, field, reviewed, "wildcard-review", "Require Reviewed: true, a driver-specific Reason and positive/negative example filenames.")
        pattern = filename(reviewed.get("Pattern"), source, field + ".Pattern", reviewed=True)
        if not specific_name(pattern.replace("*", "X").replace("?", "X")):
            fail(source, field, pattern, "generic-name", "Constrain the pattern to a specific driver identity.")
        for key, expected in (("PositiveExamples", True), ("NegativeExamples", False)):
            for example in reviewed[key]:
                if fnmatch.fnmatchcase(filename(example), pattern) != expected:
                    fail(source, field + "." + key, example, "wildcard-coverage", "Review examples against Windows-normalized basename matching.")
    return record


def authentihashes(sample):
    result = dict(sample.get("Authentihash") or {})
    result.update({a: sample["Authentihash" + a] for a in RAW if "Authentihash" + a in sample})
    return {a: v.lower() for a, v in result.items()}


def detection_record(record):
    """Internal projection. Never pass excluded samples to an output generator."""
    projected = dict(record)
    projected["KnownVulnerableSamples"] = [dict(s) for s in projected.get("KnownVulnerableSamples", []) if active(record) and active(s)]
    for sample in projected["KnownVulnerableSamples"]:
        for algorithm in RAW:
            if algorithm in sample:
                sample[algorithm] = sample[algorithm].lower()
        if authentihashes(sample):
            sample["Authentihash"] = authentihashes(sample)
    return projected


def detection_names(record):
    if not active(record) or not detection_record(record)["KnownVulnerableSamples"]:
        return []
    names = []
    # Tags[0] is the historical identity. Other tags include product labels.
    tag = record["Tags"][0]
    if specific_name(tag):
        names.append(filename(tag))
    names.extend(filename(p["Pattern"], reviewed=True) for p in record.get("DetectionNames", []))
    return sorted(set(names))


def public_record(record):
    """Move evidence outside active indicator fields, retaining the original data."""
    validate_record(record)
    result = copy.deepcopy(record)
    evidence = {"DetectionScope": "context-only", "Tags": result.pop("Tags"),
                "Detection": result.pop("Detection", [])}
    if "ResearchEvidence" in result:
        evidence["AdditionalEvidence"] = result.pop("ResearchEvidence")
    result["Tags"] = detection_names(record)
    result["IndicatorSemantics"] = "Exact file/Authenticode hashes only for blocking; Tags are hunting names. ResearchEvidence is context-only."
    result["ResearchEvidence"] = evidence
    result["KnownVulnerableSamples"] = []
    for sample in record.get("KnownVulnerableSamples", []):
        if not active(record) or not active(sample):
            evidence.setdefault("ExcludedSamples", []).append(copy.deepcopy(sample))
            continue
        hashes = {k: sample[k].lower() for k in RAW if k in sample}
        if authentihashes(sample):
            hashes["Authentihash"] = authentihashes(sample)
        hashes["ResearchEvidence"] = {**{
            k: copy.deepcopy(v) for k, v in sample.items()
            if k not in RAW and k != "Authentihash" and not k.startswith("Authentihash")}, "DetectionScope": "context-only"}
        result["KnownVulnerableSamples"].append(hashes)
    return json_evidence(result)


def json_evidence(value):
    """Keep DER bytes and YAML timestamps representable in public JSON."""
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: json_evidence(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_evidence(v) for v in value]
    return value


def load_catalog(directory):
    files = sorted({*Path(directory).glob("*.yaml"), *Path(directory).glob("*.yml")})
    if not files:
        fail(directory, "$", None, "catalog", "Supply a nonempty catalog directory.")
    records, findings, seen = [], [], set()
    for path in files:
        try:
            record = load_yaml(path.read_text(encoding="utf-8"))
            validate_record(record, path)
            if record.get("Id") != path.stem or record.get("Id") in seen:
                fail(path, "Id", record.get("Id"), "identity", "Id must match filename and be unique.")
            seen.add(record["Id"])
            records.append(record)
        except SafetyError as exc:
            findings.extend(exc.findings)
        except yaml.YAMLError as exc:
            findings.append(Finding(str(path), "$", "<YAML>", "parse", str(exc)))
    if findings:
        raise SafetyError(findings)
    return records
