"""Validate final selectors, independently of source-level validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from xml.etree import ElementTree as ET

import yaml

from detection_generation import NS, auth_hashes, raw_hashes
from indicator_safety import (LENGTHS, RAW, digest, detection_names, fail,
                              filename, specific_name, load_yaml)


def version(value, source, field):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
        fail(source, field, value, "version", "Require an explicit four-part version bound.")
    parsed = tuple(map(int, value.split(".")))
    if max(parsed) > 65535:
        fail(source, field, value, "version", "Each version component must be between 0 and 65535.")
    return parsed


class OutputValidator:
    def __init__(self, records, *, engines=True):
        self.raw = {a: set(v) for a, v in raw_hashes(records).items()}
        self.auth = {a: set(v) for a, v in auth_hashes(records).items()}
        self.names = {n for d in records for n in detection_names(d)}
        self.engines = engines
        self.count = 0

    def known_hash(self, value, algorithm, source, field, namespace="raw"):
        normalized = digest(value, algorithm, source, field)
        known = self.raw if namespace == "raw" else self.auth
        if normalized not in known[algorithm]:
            fail(source, field, value, "unknown-or-excluded-hash", f"Use an active catalog {namespace} digest; do not mix file, Authenticode, page, certificate or TBS hashes.")
        return normalized

    def hash_selector(self, value, source, field):
        if not isinstance(value, str) or "=" not in value:
            fail(source, field, value, "hash-selector", "Require ALGORITHM=complete-file-hash.")
        algorithm, value = value.split("=", 1)
        if algorithm not in RAW:
            fail(source, field, value, "hash-type", "Standalone import/page/certificate hashes are not whole-file attribution.")
        self.known_hash(value, algorithm, source, field)

    def sigma(self, path):
        text = Path(path).read_text()
        if self.engines:
            from sigma.rule import SigmaRule
            try:
                parsed = SigmaRule.from_yaml(text)
                # Force the established parser to construct the condition tree.
                for condition in parsed.detection.parsed_condition:
                    _ = condition.parsed
            except Exception as exc:
                fail(path, "detection", "<Sigma rule>", "sigma-backend", f"Resolve the pySigma parser error: {exc}")
        rule = load_yaml(text)
        detection = rule.get("detection", {}) if isinstance(rule, dict) else {}
        if set(detection) != {"selection", "condition"} or detection.get("condition") != "selection":
            fail(path, "detection.condition", detection, "sigma-condition", "This exporter supports a single nonempty selection. Extend validation before introducing new rule semantics.")
        selection = detection["selection"]
        if not isinstance(selection, dict) or len(selection) != 1:
            fail(path, "detection.selection", selection, "sigma-selector", "Require a nonempty, supported attributed selector.")
        key, values = next(iter(selection.items()))
        if not isinstance(values, list) or not values:
            fail(path, "detection.selection." + key, values, "empty-selector", "Remove the rule when no active selector remains.")
        for value in values:
            if key == "Hashes|contains":
                self.hash_selector(value, path, key)
            elif key == "ImageLoaded|endswith":
                if not isinstance(value, str) or not value.startswith("\\"):
                    fail(path, key, value, "filename-boundary", "Preserve the directory separator before an exact basename.")
                name = filename(value, path, key, reviewed=True)
                if name not in self.names or not specific_name(name.replace("*", "X").replace("?", "X")):
                    fail(path, key, value, "filename-scope", "Use an active driver-specific identity or reviewed scoped pattern; generic names need an AND constraint.")
            else:
                fail(path, key, values, "unsupported-selector", "Add validated semantics before using publisher, service, registry, network, or other selectors.")

    def sysmon(self, path, root):
        if root.tag != "Sysmon":
            fail(path, "$", root.tag, "xml-format", "Use a supported Sysmon or SiPolicy document.")
        if len(root) != 1 or root[0].tag != "EventFiltering" or any(e.tag != "RuleGroup" for e in root[0]):
            fail(path, "EventFiltering", "unsupported XML structure", "sysmon-structure", "Validate every filter: require RuleGroup-contained events with no hidden sibling selectors.")
        groups = root.findall("./EventFiltering/RuleGroup")
        if not groups:
            fail(path, "EventFiltering", None, "empty-selector", "Require explicit event selectors.")
        for group in groups:
            if group.get("groupRelation") != "or" or not len(group):
                fail(path, "RuleGroup", group.attrib, "sysmon-condition", "Require the supported OR of exact hash selectors.")
            for event in group:
                if event.tag not in {"DriverLoad", "FileBlockExecutable", "FileExecutableDetected"} or event.get("onmatch") != "include" or not len(event):
                    fail(path, event.tag, event.attrib, "sysmon-selector", "Empty or unsupported event filters can be unconditional.")
                for selector in event:
                    if selector.tag != "Hashes" or selector.get("condition") != "contains":
                        fail(path, selector.tag, selector.attrib, "sysmon-selector", "Only exact complete file hashes are supported.")
                    self.hash_selector(selector.text, path, event.tag + ".Hashes")

    def wdac(self, path, root):
        ns = {"w": NS}
        tag = lambda name: "{" + NS + "}" + name
        supported = {"SiPolicy", "VersionEx", "PlatformID", "Rules", "Rule", "Option", "EKUs",
                     "FileRules", "Allow", "Deny", "FileAttrib", "Signers", "Signer", "CertRoot",
                     "CertPublisher", "FileAttribRef", "SigningScenarios", "SigningScenario",
                     "ProductSigners", "FileRulesRef", "FileRuleRef", "DeniedSigners", "DeniedSigner",
                     "UpdatePolicySigners", "CiSigners", "CiSigner", "HvciOptions", "BasePolicyID", "PolicyID"}
        supported_tags = {tag(name) for name in supported}
        for element in root.iter():
            if element.tag not in supported_tags:
                fail(path, "XML.element", element.tag, "wdac-unsupported", "Extend validation before introducing policy elements with additional matching semantics.")
        for container in root.findall("w:FileRules", ns):
            if any(child.tag not in {tag("Allow"), tag("Deny"), tag("FileAttrib")} for child in container):
                fail(path, "FileRules", "unsupported rule", "wdac-structure", "Validate every active file rule; no hidden selectors.")
        ids = {}
        for element in root.iter():
            rid = element.get("ID")
            if rid:
                if rid in ids:
                    fail(path, "ID", rid, "wdac-reference", "Every policy ID must be unique.")
                ids[rid] = element
        baseline = {element.get("ID") for element in root.findall("w:FileRules/w:Allow", ns)
                    if element.get("FileName") == "*" and not set(element.attrib) - {"ID", "FileName", "FriendlyName"}}
        scenarios = root.findall("w:SigningScenarios/w:SigningScenario", ns)
        if not baseline or {s.get("Value") for s in scenarios} != {"131", "12"}:
            fail(path, "SigningScenarios", "missing deny-list baseline/scenario", "wdac-baseline", "A deny-list must explicitly allow unrelated files in both kernel and user-mode scenarios; absent baseline allows can implicitly block everything.")
        for scenario in scenarios:
            refs = {ref.get("RuleID") for ref in scenario.findall("w:ProductSigners/w:FileRulesRef/w:FileRuleRef", ns)}
            if not refs & baseline:
                fail(path, f"SigningScenario[{scenario.get('Value')}]", refs, "wdac-baseline", "Preserve a referenced baseline allow so unrelated drivers/products are not implicitly denied.")
        referenced, denied_signers = set(), set()
        for ref in root.findall(".//w:FileRuleRef", ns):
            rid = ref.get("RuleID")
            if rid not in ids or ids[rid].tag not in {tag("Allow"), tag("Deny")}:
                fail(path, "FileRuleRef.RuleID", rid, "wdac-reference", "Reference a defined file rule; never substitute a signer or file attribute.")
            referenced.add(rid)
        for ref in root.findall(".//w:DeniedSigner", ns):
            rid = ref.get("SignerId")
            if rid not in ids or ids[rid].tag != tag("Signer") or len(ref):
                fail(path, "DeniedSigner.SignerId", rid, "wdac-reference", "Use a defined scoped signer without unvalidated exceptions.")
            denied_signers.add(rid)
        for ref in root.findall(".//w:CiSigner", ns):
            if ref.get("SignerId") not in ids:
                fail(path, "CiSigner.SignerId", ref.get("SignerId"), "wdac-reference", "Reference a defined signer.")
        for deny in root.findall(".//w:Deny", ns):
            rid = deny.get("ID")
            if rid not in referenced:
                fail(path, "Deny.ID", rid, "wdac-reference", "Every deny must be referenced by its signing scenario.")
            if deny.get("Hash") is not None:
                friendly = deny.get("FriendlyName", "")
                match = re.fullmatch(r"Authenticode (SHA1|SHA256)", friendly)
                if not match or set(deny.attrib) - {"ID", "FriendlyName", "Hash"}:
                    fail(path, f"Deny[{rid}]", deny.attrib, "wdac-hash-type", "Declare exact Authenticode SHA1/SHA256 hashes. Page hashes require a separately validated backend; raw hashes/TBS are not interchangeable.")
                self.known_hash(deny.get("Hash"), match[1], path, f"Deny[{rid}].Hash", "auth")
            else:
                self.wdac_attributes(deny, path)
        for signer in root.findall(".//w:Signer", ns):
            rid = signer.get("ID")
            # Validate all declared signers, including currently unreferenced ones.
            roots = signer.findall("w:CertRoot", ns)
            publishers = signer.findall("w:CertPublisher", ns)
            attrs = signer.findall("w:FileAttribRef", ns)
            if len(roots) != 1 or len(publishers) != 1 or not attrs:
                fail(path, f"Signer[{rid}]", signer.attrib, "publisher-scope", "A certificate/CA/publisher alone can cover unrelated products. Require exact publisher AND file/product AND a bounded version interval.")
            value = publishers[0].get("Value")
            normalized = value.strip().strip("\"'").strip().casefold() if isinstance(value, str) else ""
            if (not normalized or normalized in {"unknown", "n/a", "none", "null", "publisher", "tbd"}
                    or any(c in value for c in "*?%${}")):
                fail(path, f"Signer[{rid}].CertPublisher", value, "publisher-identity", "Use an exact non-placeholder publisher identity.")
            cert_root = roots[0]
            value = cert_root.get("Value", "")
            if cert_root.get("Type") != "TBS" or len(value) not in {40, 64}:
                fail(path, f"Signer[{rid}].CertRoot", value, "certificate-type", "Keep TBS SHA1/SHA256 distinct from certificate fingerprints.")
            digest(value, "SHA1" if len(value) == 40 else "SHA256", path, f"Signer[{rid}].CertRoot")
            for ref in attrs:
                aid = ref.get("RuleID")
                if aid not in ids or ids[aid].tag != tag("FileAttrib"):
                    fail(path, f"Signer[{rid}].FileAttribRef", aid, "wdac-reference", "Preserve the AND link to a defined, scoped file attribute.")
                self.wdac_attributes(ids[aid], path)
            if rid not in denied_signers:
                fail(path, "Signer.ID", rid, "wdac-reference", "Remove unused signers or reference the fully constrained rule.")
        for attrs in root.findall(".//w:FileAttrib", ns):
            self.wdac_attributes(attrs, path)

    def wdac_attributes(self, element, path):
        allowed = {"ID", "FriendlyName", "FileName", "ProductName", "MinimumFileVersion", "MaximumFileVersion"}
        if set(element.attrib) - allowed or sum(k in element.attrib for k in ("FileName", "ProductName")) != 1:
            fail(path, str(element.get("ID")), element.attrib, "wdac-attribute-scope", "Require one exact identity and explicit version bounds. Extend validation before combining attributes or adding unsupported scopes.")
        identity = element.get("FileName") or element.get("ProductName")
        rid = element.get("ID")
        if identity is None:
            fail(path, f"{element.tag}[{rid}]", element.attrib, "wdac-identity", "Require an exact driver filename/product AND version bounds.")
        if element.get("FileName"):
            name = filename(identity, path, f"{rid}.FileName")
            if not specific_name(name):
                fail(path, f"{rid}.FileName", name, "generic-name", "Use a driver-specific exact PE identity.")
        elif not identity.strip() or any(c in identity for c in "*?%${}") or identity.strip().casefold() in {"microsoft windows", "microsoft windows operating system", "microsoftr windowsr operating system", "windows", "driver", "n/a", "unknown", "null", "none", "product"}:
            fail(path, f"{rid}.ProductName", identity, "generic-product", "Require a product-specific exact identity.")
        minimum = version(element.get("MinimumFileVersion"), path, f"{rid}.MinimumFileVersion")
        maximum = version(element.get("MaximumFileVersion"), path, f"{rid}.MaximumFileVersion")
        if minimum > maximum or maximum == (65535,) * 4:
            fail(path, f"{rid}.Version", (minimum, maximum), "wdac-version-scope", "Bound the deny to documented affected versions; minimum-only rules also deny future fixed versions.")

    def yara(self, path):
        import plyara
        text = Path(path).read_text()
        parser = plyara.Plyara()
        rules = parser.parse_string(text)
        if not rules:
            # A category can legitimately have no raw-file indicators.
            if re.sub(r'(?m)^\s*(?://.*|import "hash")\s*$', '', text).strip():
                fail(path, "$", text, "yara-empty", "Require a valid rule or an empty generated category.")
            return
        if self.engines:
            import yara
            yara.compile(source=text, externals={"filename": "unrelated.sys"})
        for rule in rules:
            tokens = rule.get("condition_terms", [])
            condition = " ".join(tokens)
            # Constrain the *entire* condition. A hash anywhere in an OR is not a guard.
            match = re.fullmatch(r'hash\s*\.\s*(md5|sha1|sha256)\s*\(\s*0\s*,\s*filesize\s*\)\s*==\s*"([a-fA-F0-9]+)"(.*)', condition)
            if not match:
                fail(path, rule["rule_name"], condition, "yara-attribution", "Require a complete raw-file hash as the mandatory condition; shared version strings alone are not attribution.")
            self.known_hash(match[2], match[1].upper(), path, rule["rule_name"])
            suffix = match[3].strip()
            if suffix:
                if not re.fullmatch(r'and not \( filename matches /(?:\\.|[^/])+/i(?: or filename matches /(?:\\.|[^/])+/i)* \)', suffix):
                    fail(path, rule["rule_name"], suffix, "yara-condition", "Only filename exclusions joined with AND may follow the required exact hash.")

    def validate(self, path):
        path = Path(path)
        self.count += 1
        suffix = path.suffix.lower()
        if suffix == ".xml":
            text = path.read_text(encoding="utf-8-sig")
            if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                fail(path, "$", "DTD/entity", "xml-entity", "Use a self-contained XML policy without external entities.")
            root = ET.fromstring(text)
            if root.tag == "{" + NS + "}SiPolicy":
                self.wdac(path, root)
            else:
                self.sysmon(path, root)
        elif suffix == ".yar":
            self.yara(path)
        elif suffix in {".yml", ".yaml"}:
            data = load_yaml(path.read_text())
            if isinstance(data, dict) and "queryText" in data:
                query = data["queryText"]
                matches = re.findall(r"files\.FILEDATA_HASH = '([a-f0-9]{64})'", query)
                if not matches or re.search(r"\b(?:true|like|contains)\b|\*", query, re.I):
                    fail(path, "queryText", query, "lql-attribution", "Use exact SHA256 equality predicates joined by OR.")
                for value in matches:
                    self.known_hash(value, "SHA256", path, "queryText")
                # Validate the filter, not hashes merely present in a comment/return clause.
                filter_text = re.search(r"filter\s*\{([^}]+)\}", query)
                if not filter_text or not re.fullmatch(r"\s*files\.FILEDATA_HASH = '[a-f0-9]{64}'(?:\s+OR\s+files\.FILEDATA_HASH = '[a-f0-9]{64}')*\s*", filter_text[1]):
                    fail(path, "queryText.filter", query, "lql-condition", "Reject unsupported or unconditional filter logic.")
            else:
                self.sigma(path)
        elif suffix == ".hdb":
            for i, line in enumerate(path.read_text().splitlines()):
                match = re.fullmatch(r"([a-f0-9]{64}):([1-9][0-9]*):([A-Za-z0-9_.-]+)", line)
                if not match:
                    fail(path, f"line[{i+1}]", line, "clamav-selector", "Require SHA256:positive-filesize:signature-name; no wildcard sizes or selectors.")
                self.known_hash(match[1], "SHA256", path, f"line[{i+1}]")
        elif suffix in {".md5", ".sha1", ".sha256", ".all", ".imphash"}:
            if suffix == ".imphash":
                fail(path, "$", path.name, "research-only", "Import hashes belong in ResearchEvidence, not standalone blocking feeds.")
            namespace = "auth" if "authentihash" in path.name else "raw"
            for i, line in enumerate(path.read_text().splitlines()):
                algorithm = suffix[1:].upper() if suffix != ".all" else {32: "MD5", 40: "SHA1", 64: "SHA256"}.get(len(line))
                if algorithm not in RAW:
                    fail(path, f"line[{i+1}]", line, "digest-length", "Use a complete digest with its documented algorithm/namespace.")
                self.known_hash(line, algorithm, path, f"line[{i+1}]", namespace)
