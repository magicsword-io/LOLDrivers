"""Adversarial controls for source contracts, final engines and reconciliation."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
from xml.etree import ElementTree as ET

import yaml
import yara
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bin"))
from api_exports import export_api_files
from detection_generation import (NS, build_outputs, generate, owned_paths,
                                  wdac_xml, write_outputs, yara_text)
from generated_safety import OutputValidator
from indicator_safety import (LENGTHS, RAW, SafetyError, detection_names, digest,
                              filename, load_catalog, public_record,
                              validate_certificate, validate_record, load_yaml)
from sample_evidence import check_samples


def file_hashes(data):
    return {a: hashlib.new(a.lower(), data).hexdigest() for a in RAW}


SAMPLE_BYTES = b"MZ\x90\x00" + b"synthetic affected AcmeDriver version 1.2.3.4\x00" * 60
UNRELATED_BYTES = b"MZ\x90\x00" + b"synthetic unrelated Windows disk.sys version 10.0.0.0\x00" * 60
AUTH = file_hashes(b"synthetic Authenticode image bytes (distinct from raw)")


def record():
    return {"Id": "11111111-2222-4333-8444-555555555555", "Tags": ["AcmeDriver.sys"],
            "Category": "vulnerable driver", "Verified": "TRUE", "Author": "Safety tests",
            "Created": "2026-01-01", "MitreID": "T1068", "Resources": [],
            "KnownVulnerableSamples": [{"Filename": "AcmeDriver.sys", **file_hashes(SAMPLE_BYTES),
                "Authentihash": AUTH, "Publisher": "Shared Vendor", "Product": "Acme Driver",
                "FileVersion": "1.2.3.4", "OriginalFilename": "AcmeDriver.sys"}]}


def parse_wdac(data):
    return ET.fromstring(data)


def scoped_signer_policy():
    return f'''<SiPolicy xmlns="{NS}">
    <FileRules><Allow ID="BASELINE" FileName="*"/><FileAttrib ID="ATTR" FileName="AcmeDriver.sys" MinimumFileVersion="1.2.0.0" MaximumFileVersion="1.2.3.4"/></FileRules>
    <Signers><Signer ID="SIGNER" Name="Shared Vendor"><CertRoot Type="TBS" Value="{hashlib.sha256(b'certificate TBS').hexdigest()}"/>
    <CertPublisher Value="Shared Vendor"/><FileAttribRef RuleID="ATTR"/></Signer></Signers>
    <SigningScenarios><SigningScenario ID="SCENARIO" Value="131"><ProductSigners><FileRulesRef><FileRuleRef RuleID="BASELINE"/></FileRulesRef><DeniedSigners><DeniedSigner SignerId="SIGNER"/></DeniedSigners></ProductSigners></SigningScenario>
    <SigningScenario ID="USERMODE" Value="12"><ProductSigners><FileRulesRef><FileRuleRef RuleID="BASELINE"/></FileRulesRef></ProductSigners></SigningScenario></SigningScenarios>
    </SiPolicy>'''


class SourceSafetyTests(unittest.TestCase):
    def test_catch_all_normalization_variants(self):
        for value in ("*", "*.*", "*.sys", "*.dll", "*.exe", "???.SYS", " ** .dll ",
                      '"*.SYS"', "'*.ExE'", r"C:\SpecificTool\*.sys", "C:/Tool/*.EXE",
                      r"%SystemRoot%\*.sys", r"${driver_dir}\*.sys", "{{driver}}.sys",
                      "", None, "unknown", "FILENAME.sys", "*.sys. "):
            with self.subTest(value=value), self.assertRaises(SafetyError):
                filename(value)

    def test_specific_path_case_quotes_normalize_to_safe_basename(self):
        self.assertEqual(filename(' "C:/Acme/ACMEDRIVER.SYS" '), "acmedriver.sys")

    def test_unreviewed_wildcard_fails(self):
        for value in ("AcmeDriver*.sys", "Acm?Driver.sys", "Microsoft*.sys", "driver??.sys"):
            with self.subTest(value=value), self.assertRaises(SafetyError):
                filename(value)

    def test_reviewed_scoped_wildcard_retained_with_examples(self):
        d = record()
        d["DetectionNames"] = [{"Pattern": "AcmeDriver*.sys", "Reviewed": True,
            "Reason": "Acme Driver family observed in affected samples",
            "PositiveExamples": ["AcmeDriver.sys", "AcmeDriver64.sys"],
            "NegativeExamples": ["disk.sys", "OtherProduct.sys", "ntoskrnl.exe"]}]
        validate_record(d)
        self.assertIn("acmedriver*.sys", detection_names(d))
        d["DetectionNames"][0]["NegativeExamples"] = ["AcmeDriver32.sys"]
        with self.assertRaisesRegex(SafetyError, "wildcard-coverage"):
            validate_record(d)

    def test_generic_names_do_not_become_standalone_selectors(self):
        for name in ("driver.sys", "monitor.sys", "ntoskrnl.exe", "disk.sys", "setup.exe", "driver64.sys", "cmd.exe", "services.exe", "win32kfull.sys"):
            d = record(); d["Tags"] = [name]
            validate_record(d)
            self.assertEqual(detection_names(d), [])
            self.assertTrue(public_record(d)["KnownVulnerableSamples"][0]["SHA256"])

    def test_all_digest_algorithms_lengths_types_and_placeholders(self):
        for algorithm, length in LENGTHS.items():
            valid = hashlib.new(algorithm.lower(), b"realistic digest fixture").hexdigest()
            self.assertEqual(digest(valid.upper(), algorithm), valid)
            for bad in (valid[:-1], valid + "0", "g" * length, "0" * length, "a" * length,
                        "deadbeef" * (length // 8), None, "", "-", "{{hash}}", " " + valid):
                with self.subTest(algorithm=algorithm, bad=bad), self.assertRaises(SafetyError):
                    digest(bad, algorithm)

    def test_authenticode_only_records_remain_active_and_distinct(self):
        d = record()
        for a in RAW:
            del d["KnownVulnerableSamples"][0][a]
        validate_record(d)
        root = parse_wdac(wdac_xml([d]))
        self.assertIn(AUTH["SHA256"].upper(), {n.get("Hash") for n in root.iter()})
        self.assertNotIn(file_hashes(SAMPLE_BYTES)["SHA256"].upper(), {n.get("Hash") for n in root.iter()})

    def test_hashless_and_import_or_page_or_cert_only_records_fail(self):
        for extra in ({}, {"Imphash": file_hashes(b"imports")["MD5"]},
                      {"PageHash": {"SHA256": file_hashes(b"page")["SHA256"]}},
                      {"Signatures": [{"Certificates": [{"TBS": {"SHA256": file_hashes(b"cert")["SHA256"]}}]}]}):
            d = record(); d["KnownVulnerableSamples"] = [{"Filename": "AcmeDriver.sys", **extra}]
            with self.subTest(extra=extra), self.assertRaisesRegex(SafetyError, "hashless"):
                validate_record(d)

    def test_invalid_hash_never_falls_back_to_name_or_publisher(self):
        d = record(); d["KnownVulnerableSamples"][0]["SHA256"] = "invalid"
        with self.assertRaisesRegex(SafetyError, "SHA256"):
            public_record(d)

    def test_legacy_authenticode_aliases_agree_or_fail(self):
        d = record(); s = d["KnownVulnerableSamples"][0]
        s["AuthentihashSHA256"] = AUTH["SHA256"].upper()
        validate_record(d)
        s["AuthentihashSHA256"] = file_hashes(b"wrong image")["SHA256"]
        with self.assertRaisesRegex(SafetyError, "digest-conflict"):
            validate_record(d)

    def test_context_scope_requires_reason_and_preserves_evidence(self):
        d = record(); d["DetectionScope"] = "context-only"
        with self.assertRaisesRegex(SafetyError, "ContextReason"):
            validate_record(d)
        d["ContextReason"] = "Historical sample, attribution needs review"
        public = public_record(d)
        self.assertEqual(public["KnownVulnerableSamples"], [])
        self.assertEqual(public["Tags"], [])
        self.assertEqual(public["ResearchEvidence"]["ExcludedSamples"], d["KnownVulnerableSamples"])

    def test_metadata_and_shared_signer_cannot_escape_context_section(self):
        d = record(); s = d["KnownVulnerableSamples"][0]
        s.update({"OriginalFilename": "*.sys", "Publisher": "*", "DetectionScope": "active",
                  "ServiceName": "*", "Registry": r"HKLM\SYSTEM\*", "Imports": ["ntoskrnl.exe"],
                  "Imphash": file_hashes(b"ubiquitous imports")["MD5"]})
        projected = public_record(d)["KnownVulnerableSamples"][0]
        self.assertEqual(set(projected), {*RAW, "Authentihash", "ResearchEvidence"})
        self.assertEqual(projected["ResearchEvidence"]["DetectionScope"], "context-only")
        self.assertEqual(projected["ResearchEvidence"]["Publisher"], "*")

    def test_duplicate_yaml_hash_keys_are_rejected(self):
        with self.assertRaisesRegex(yaml.YAMLError, "duplicate field"):
            load_yaml("SHA256: valid-looking\nSHA256: '*.*'\n")


class CertificateSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Shared Vendor")])
        # Deliberately expired: historical evidence remains valid research data.
        start = datetime(2018, 1, 1, tzinfo=timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(42).not_valid_before(start)
                .not_valid_after(start + timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        der = cert.public_bytes(serialization.Encoding.DER)
        cls.evidence = {"DER": base64.b64encode(der).decode(), "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(), "ValidFrom": "2018-01-01T00:00:00+00:00",
            "ValidTo": "2019-01-01T00:00:00+00:00",
            "Thumbprint": {a: hashlib.new(a.lower(), der).hexdigest() for a in RAW},
            "TBS": {a: hashlib.new(a.lower(), cert.tbs_certificate_bytes).hexdigest() for a in LENGTHS}}

    def test_expired_consistent_certificate_is_retained(self):
        validate_certificate(self.evidence, "fixture.yaml", "Signatures[0].Certificates[0]")

    def test_binary_der_and_wrapped_base64_are_supported(self):
        cert = copy.deepcopy(self.evidence)
        cert["DER"] = base64.b64decode(cert["DER"])
        validate_certificate(cert, "fixture.yaml", "certificate")
        d = record(); d["KnownVulnerableSamples"][0]["Signatures"] = [{"Certificates": [cert]}]
        exported = json.loads(json.dumps(public_record(d)))
        rendered = exported["KnownVulnerableSamples"][0]["ResearchEvidence"]["Signatures"][0]["Certificates"][0]
        self.assertEqual(base64.b64decode(rendered["DER"]), cert["DER"])
        cert["Base64"] = "\n".join(self.evidence["DER"][i:i+64] for i in range(0, len(self.evidence["DER"]), 64))
        validate_certificate(cert, "fixture.yaml", "certificate")

    def test_corrupt_encoding_identities_tbs_fingerprints_and_dates_fail(self):
        mutations = [("DER", "not base64!"), ("DER", base64.b64encode(b"not DER").decode()),
                     ("Subject", "CN=Different Vendor"), ("Issuer", "CN=Unrelated CA"),
                     ("ValidFrom", "2018-01-02"), ("ValidTo", "2017-01-01"),
                     ("TBS", {"SHA256": file_hashes(b"wrong TBS")["SHA256"]}),
                     ("Thumbprint", {"SHA256": file_hashes(b"wrong cert")["SHA256"]})]
        for key, bad in mutations:
            cert = copy.deepcopy(self.evidence); cert[key] = bad
            with self.subTest(field=key), self.assertRaises(SafetyError):
                validate_certificate(cert, "fixture.yaml", "certificate")


class FinalSelectorTests(unittest.TestCase):
    def setUp(self):
        self.record = record()
        self.validator = OutputValidator([self.record])
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def write(self, name, text):
        path = self.root / name; path.write_text(text); return path

    def test_native_yara_positive_and_unrelated_same_signer_negative(self):
        rules = yara.compile(source=yara_text([self.record], "vulnerable driver"))
        self.assertTrue(rules.match(data=SAMPLE_BYTES))
        self.assertFalse(rules.match(data=UNRELATED_BYTES))
        self.assertFalse(rules.match(data=SAMPLE_BYTES.replace(b"1.2.3.4", b"1.2.3.5")))
        # Empty/no PE metadata does not remove a mandatory exact hash.
        d = record(); d["KnownVulnerableSamples"][0] = file_hashes(SAMPLE_BYTES)
        self.assertTrue(yara.compile(source=yara_text([d], "vulnerable driver")).match(data=SAMPLE_BYTES))

    def test_yara_hash_or_unconditional_branch_fails(self):
        text = yara_text([self.record], "vulnerable driver")
        text = text.replace('hash.sha256(0, filesize) ==', 'true or hash.sha256(0, filesize) ==')
        with self.assertRaisesRegex(SafetyError, "yara-attribution"):
            self.validator.validate(self.write("unsafe.yar", text))

    def test_native_yara_renamed_hash_guard_stays_and(self):
        rules = yara.compile(source=yara_text([self.record], "vulnerable driver", renamed=True), externals={"filename": "AcmeDriver.sys"})
        self.assertFalse(rules.match(data=SAMPLE_BYTES))
        self.assertTrue(rules.match(data=SAMPLE_BYTES, externals={"filename": "renamed.sys"}))
        self.assertFalse(rules.match(data=UNRELATED_BYTES, externals={"filename": "renamed.sys"}))

    def test_sigma_generic_empty_hashes_templates_and_unknown_fields_fail(self):
        base = {"title": "Safety test", "id": "11111111-2222-4333-8444-555555555555", "logsource": {"product": "windows", "category": "driver_load"},
                "detection": {"selection": {}, "condition": "selection"}}
        for selection in ({"ImageLoaded|endswith": [r"\*.sys"]}, {"ImageLoaded|endswith": [r"\driver.sys"]},
                          {"Hashes|contains": ["SHA256=" + "0" * 64]}, {"Hashes|contains": []},
                          {"Hashes|contains": [None]}, {"ServiceName": ["*"]}, {"EventID": [6]},
                          {"ImageLoaded|endswith": [r"\${driver}.sys"]}, {"DestinationHostname": ["*.com"]}):
            base["detection"]["selection"] = selection
            with self.subTest(selection=selection), self.assertRaises(SafetyError):
                self.validator.validate(self.write("sigma.yml", yaml.safe_dump(base)))

    def test_wdac_generated_hashes_use_exact_authenticode_lengths_and_references(self):
        path = self.write("policy.xml", wdac_xml([self.record])); self.validator.validate(path)
        root = ET.parse(path).getroot()
        hashes_found = {n.get("Hash") for n in root.findall(f".//{{{NS}}}Deny")}
        self.assertEqual(hashes_found, {AUTH[a].upper() for a in ("SHA1", "SHA256")})
        for deny in root.findall(f".//{{{NS}}}Deny"):
            self.assertIn(len(deny.get("Hash")), (40, 64))
            refs = [r for r in root.findall(f".//{{{NS}}}FileRuleRef") if r.get("RuleID") == deny.get("ID")]
            self.assertEqual(len(refs), 2)
        # No different product from the same vendor can match an exact digest.
        self.assertNotIn(file_hashes(UNRELATED_BYTES)["SHA256"].upper(), hashes_found)

    def test_wdac_signer_requires_all_constraints_and_valid_reference(self):
        text = scoped_signer_policy()
        self.validator.validate(self.write("policy.xml", text))
        mutations = [text.replace('<FileAttribRef RuleID="ATTR"/>', ''),
                     text.replace('Value="Shared Vendor"', 'Value="*"'),
                     text.replace('Value="Shared Vendor"', 'Value=""'),
                     text.replace('FileName="AcmeDriver.sys"', 'FileName="*.sys"'),
                     text.replace('MaximumFileVersion="1.2.3.4"', ''),
                     text.replace('MinimumFileVersion="1.2.0.0"', 'MinimumFileVersion="2.0.0.0"'),
                     text.replace('RuleID="ATTR"', 'RuleID="MISSING"'),
                     text.replace('MaximumFileVersion="1.2.3.4"', 'MaximumFileVersion="{{version}}"')]
        for mutated in mutations:
            with self.subTest(xml=mutated), self.assertRaises(SafetyError):
                self.validator.validate(self.write("policy.xml", mutated))

    def test_wdac_raw_file_hash_is_not_authenticode(self):
        text = wdac_xml([self.record]).replace(AUTH["SHA256"].upper(), file_hashes(SAMPLE_BYTES)["SHA256"].upper())
        with self.assertRaisesRegex(SafetyError, "unknown-or-excluded-hash"):
            self.validator.validate(self.write("policy.xml", text))

    def test_wdac_bad_hash_lengths_and_dangling_rule_fail(self):
        text = wdac_xml([self.record])
        for mutated in (text.replace(AUTH["SHA256"].upper(), AUTH["SHA256"].upper()[:-1]),
                        text.replace('RuleID="ID_DENY_', 'RuleID="MISSING_')):
            with self.subTest(xml=mutated), self.assertRaises(SafetyError):
                self.validator.validate(self.write("policy.xml", mutated))

    def test_wdac_missing_baseline_cannot_implicitly_deny_unrelated_files(self):
        text = wdac_xml([self.record])
        text = text.replace('<FileRuleRef RuleID="ID_ALLOW_BASELINE" />', '')
        with self.assertRaisesRegex(SafetyError, "wdac-baseline"):
            self.validator.validate(self.write("policy.xml", text))

    def test_wdac_version_boundaries_and_missing_metadata(self):
        # Independent inclusive-bound oracle for the supported XML subset.
        root = parse_wdac(scoped_signer_policy())
        attr = root.find(f".//{{{NS}}}FileAttrib")
        minimum = tuple(map(int, attr.get("MinimumFileVersion").split('.')))
        maximum = tuple(map(int, attr.get("MaximumFileVersion").split('.')))
        for value, expected in (("1.1.65535.65535", False), ("1.2.0.0", True),
                                ("1.2.3.4", True), ("1.2.3.5", False), (None, False)):
            observed = value is not None and minimum <= tuple(map(int, value.split('.'))) <= maximum
            self.assertEqual(observed, expected)
        self.validator.validate(self.write("policy.xml", scoped_signer_policy()))

    def test_sysmon_empty_events_and_hashes_fail(self):
        for text in ('<Sysmon><EventFiltering><RuleGroup groupRelation="or"><DriverLoad onmatch="include"/></RuleGroup></EventFiltering></Sysmon>',
                     '<Sysmon><EventFiltering><RuleGroup groupRelation="or"><DriverLoad onmatch="include"><Hashes condition="contains">SHA256=*</Hashes></DriverLoad></RuleGroup></EventFiltering></Sysmon>'):
            with self.subTest(xml=text), self.assertRaises(SafetyError):
                self.validator.validate(self.write("sysmon.xml", text))


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        (self.root / "yaml").mkdir(); (self.root / "drivers").mkdir()
        self.record = record(); self.save()
        md5 = file_hashes(SAMPLE_BYTES)["MD5"]
        (self.root / "drivers" / (md5 + ".bin")).write_bytes(SAMPLE_BYTES)

    def save(self):
        self.source = self.root / "yaml" / (self.record["Id"] + ".yaml")
        self.source.write_text("# Source formatting must remain unchanged\n" + yaml.safe_dump(self.record, sort_keys=False))

    def generate(self):
        return generate(self.root / "yaml", self.root, self.root / "drivers")

    def test_generation_is_deterministic_offline_and_does_not_modify_source(self):
        original = self.source.read_bytes()
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            first = self.generate(); second = self.generate()
            export_api_files(self.root / "yaml", self.root / "api")
        self.assertEqual(first, second)
        self.assertEqual(original, self.source.read_bytes())
        self.assertEqual(first["detections/av/LOLDrivers.hdb"].split(":")[0], file_hashes(SAMPLE_BYTES)["SHA256"])

    def test_context_only_samples_excluded_from_every_actual_generator(self):
        self.record['Category'] = 'malicious'
        self.record['KnownVulnerableSamples'][0]['LoadsDespiteHVCI'] = 'TRUE'
        self.save()
        excluded = record(); excluded["Id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        excluded['Category'] = 'malicious'
        excluded["Tags"] = ["UnrelatedProduct.sys"]
        excluded["DetectionScope"] = "context-only"; excluded["ContextReason"] = "Unrelated sample evidence; review required"
        excluded["KnownVulnerableSamples"][0].update(file_hashes(UNRELATED_BYTES))
        excluded["KnownVulnerableSamples"][0]["Authentihash"] = file_hashes(b"excluded Authenticode")
        excluded["KnownVulnerableSamples"][0]['LoadsDespiteHVCI'] = 'TRUE'
        (self.root / "yaml" / (excluded["Id"] + ".yaml")).write_text(yaml.safe_dump(excluded))
        (self.root / "drivers" / (file_hashes(UNRELATED_BYTES)["MD5"] + ".bin")).write_bytes(UNRELATED_BYTES)
        outputs = self.generate()
        self.assertIn(file_hashes(SAMPLE_BYTES)['SHA256'], outputs['detections/lacework/LOLDriver_Malicious_Hashes.yaml'])
        self.assertIn(file_hashes(SAMPLE_BYTES)['SHA256'], outputs['detections/hashes/LoadsDespiteHVCI.samples_malicious.sha256'])
        for path, text in outputs.items():
            with self.subTest(path=path):
                self.assertNotIn(file_hashes(UNRELATED_BYTES)["SHA256"], text.lower())
                self.assertNotIn(file_hashes(b"excluded Authenticode")["SHA256"], text.lower())
                self.assertNotIn("unrelatedproduct.sys", text.lower())
        exported = export_api_files(self.root / "yaml", self.root / "api")
        context = next(d for d in exported if d["Id"] == excluded["Id"])
        self.assertEqual(context["KnownVulnerableSamples"], [])
        self.assertTrue(context["ResearchEvidence"]["ExcludedSamples"])

    def test_sample_level_exclusion_keeps_affected_sibling_active(self):
        excluded = {'Filename': 'UnrelatedProduct.sys', **file_hashes(UNRELATED_BYTES),
                    'Authentihash': file_hashes(b'excluded image'), 'DetectionScope': 'context-only',
                    'ContextReason': 'This sample needs independent attribution review'}
        self.record['KnownVulnerableSamples'].append(excluded); self.save()
        (self.root / 'drivers' / (file_hashes(UNRELATED_BYTES)['MD5'] + '.bin')).write_bytes(UNRELATED_BYTES)
        outputs = self.generate()
        for path, text in outputs.items():
            with self.subTest(path=path):
                self.assertNotIn(file_hashes(UNRELATED_BYTES)['SHA256'], text.lower())
                self.assertNotIn(file_hashes(b'excluded image')['SHA256'], text.lower())
        projected = public_record(self.record)
        self.assertEqual(len(projected['KnownVulnerableSamples']), 1)
        self.assertEqual(projected['KnownVulnerableSamples'][0]['SHA256'], file_hashes(SAMPLE_BYTES)['SHA256'])
        self.assertEqual(projected['ResearchEvidence']['ExcludedSamples'], [excluded])

    def test_stale_owned_rules_removed_manual_files_preserved(self):
        self.generate()
        manual = self.root / "detections/yara/manual.yar"; manual.write_text("// manual ownership\n")
        old_names = self.root / "detections/sigma/driver_load_win_vuln_drivers_names.yml"
        self.assertTrue(old_names.exists())
        self.record["DetectionScope"] = "context-only"; self.record["ContextReason"] = "Historical evidence only"
        self.save(); self.generate()
        self.assertFalse(old_names.exists())
        self.assertEqual(manual.read_text(), "// manual ownership\n")
        self.assertNotIn("rule LOLDrivers_", (self.root / "detections/yara/yara-rules_vuln_drivers_strict.yar").read_text())

    def test_refuses_to_overwrite_unowned_or_delete_outside_manifest(self):
        path = self.root / "detections/hashes"; path.mkdir(parents=True)
        (path / "manual.sha256").write_text("preserve")
        with self.assertRaisesRegex(SafetyError, "ownership"):
            write_outputs({"detections/hashes/manual.sha256": "replacement"}, self.root)
        (self.root / "detections/.generated-files.json").write_text(json.dumps({"owner": "LOLDrivers catalog generator v1", "files": ["../manual.py"]}))
        with self.assertRaisesRegex(SafetyError, "ownership"):
            owned_paths(self.root)

    def test_gate_detects_stale_unowned_rules_and_public_copy_disagreement(self):
        (self.root / "bin").mkdir()
        for name in ("gen-files.py", "detection_generation.py", "indicator_safety.py"):
            shutil.copyfile(ROOT / "bin" / name, self.root / "bin" / name)
        self.generate(); export_api_files(self.root / "yaml", self.root / "loldrivers.io/content/api")
        spec = importlib.util.spec_from_file_location("safety_gate", ROOT / "bin/validate-safety.py")
        gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
        gate.check(self.root)
        (self.root / "detections/sigma/stale.yml").write_text(yaml.safe_dump({"detection": {"selection": {"ImageLoaded|endswith": [r"\*.sys"]}, "condition": "selection"}}))
        with self.assertRaises(SafetyError):
            gate.check(self.root)
        (self.root / "detections/sigma/stale.yml").unlink()
        (self.root / "loldrivers.io/content/api/drivers.json").write_text("[]")
        with self.assertRaisesRegex(SafetyError, "public-copy"):
            gate.check(self.root)

    def test_corrupt_sample_hash_does_not_pass_with_another_valid_hash(self):
        self.record["KnownVulnerableSamples"][0]["SHA1"] = hashlib.sha1(b"unrelated file").hexdigest()
        with self.assertRaisesRegex(SafetyError, "sample-digest-mismatch"):
            check_samples([self.record], self.root / "drivers")

    def test_unlinked_sample_flagged_for_review_without_becoming_an_indicator(self):
        (self.root / "drivers/unlinked.bin").write_bytes(UNRELATED_BYTES)
        report = check_samples([self.record], self.root / "drivers")
        self.assertEqual(report["review_findings"][0]["rule"], "unrelated-sample-review")
        self.assertNotIn(file_hashes(UNRELATED_BYTES)["SHA256"], self.generate()["detections/av/LOLDrivers.hdb"])


class CatalogEngineControls(unittest.TestCase):
    def test_real_affected_driver_and_unrelated_product_from_same_leaf_signer(self):
        # Both are intentionally cataloged vulnerable products, not benign
        # waivers. The WDT policy must not expand to the unrelated CPUID product.
        first = yaml.safe_load((ROOT / "yaml/08adabb3-7336-43de-a980-e23a55081f19.yaml").read_text())
        second = yaml.safe_load((ROOT / "yaml/0f59ce3b-20ac-41ba-8010-2abc74827eb8.yaml").read_text())
        def leaf_hashes(driver):
            return {c["TBS"]["SHA256"] for s in driver["KnownVulnerableSamples"]
                    for sig in s.get("Signatures", []) for c in sig.get("Certificates", [])
                    if not c.get("IsCA") and c.get("IsCodeSigning") and c.get("TBS", {}).get("SHA256")}
        self.assertTrue(leaf_hashes(first) & leaf_hashes(second))
        targeted = ROOT / "drivers/3a00cd7cb37b2b4bfaa9e7715fdd13d5.bin"
        unrelated = ROOT / "drivers/8ff0f73158ec15de8e548b00608c5822.bin"
        rules = yara.compile(source=yara_text([first], first["Category"]))
        self.assertTrue(rules.match(filepath=str(targeted)))
        self.assertFalse(rules.match(filepath=str(unrelated)))
        blocked_auth = {e.get("Hash").lower() for e in parse_wdac(wdac_xml([first])).findall(f".//{{{NS}}}Deny")}
        self.assertTrue(any(s.get("Authentihash", {}).get("SHA256") in blocked_auth for s in first["KnownVulnerableSamples"]))
        self.assertFalse(any(s.get("Authentihash", {}).get("SHA256") in blocked_auth for s in second["KnownVulnerableSamples"]))

    def test_imported_signer_file_attributes_are_not_flattened_to_filename_denies(self):
        for module_name, filename_, function in (("site_generator", "site.py", "parse_sipolicy_hashes"),
                                                 ("blocklist_metrics", "blocklist_analysis.py", "parse_sipolicy")):
            spec = importlib.util.spec_from_file_location(module_name, ROOT / "bin" / filename_)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "policy.xml"; path.write_text(scoped_signer_policy())
                result = getattr(module, function)(path)
                self.assertNotIn("acmedriver.sys", result["denied_filename_rules"])


if __name__ == "__main__":
    unittest.main()
