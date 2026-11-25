import unittest
from copy import deepcopy
from appsecctl import remediation_audit as audit, scan_evidence


def finding(cve, name, version="1", fixed="2", severity="HIGH"):
    return {"VulnerabilityID": cve, "PkgName": name, "InstalledVersion": version,
            "FixedVersion": fixed, "Severity": severity}


def scan(phase, image, os_findings, app_findings, app_packages=True):
    iid = "sha256:" + ("a" if phase == "original" else "b") * 64
    return {"id": phase, "phase": phase, "status": "success", "image_ref": image,
            "raw_report": {"ArtifactType": "container_image", "Metadata": {"ImageID": iid},
                           "_appsec": {"verified": True, "image_id": iid, "scope": audit.SCOPE},
                           "Results": [
                               {"Class": "os-pkgs", "Type": "debian", "Target": image+" (debian 12.1)",
                                "Packages": [{"Name":"libc6","Version":"1"}], "Vulnerabilities":os_findings},
                               {"Class":"lang-pkgs","Type":"python-pkg","Target":"app/requirements.txt",
                                "Packages": [{"Name":"requests","Version":"2"}] if app_packages else [],
                                "Vulnerabilities":app_findings}]}}


def payload():
    original = scan("original", "test:1", [finding("CVE-1","libc6"), finding("CVE-2","libc6",fixed=""),
                   finding("CVE-3","libc6",severity="LOW")], [finding("CVE-4","requests")])
    patched = scan("patched", "test:patched", [finding("CVE-1","libc6",severity="LOW"),
                   finding("CVE-2","libc6",fixed=""), finding("CVE-5","libc6")], [], False)
    return {"scans":[original,patched], "patches":[{"status":"success",
            "local_image_ref":patched["image_ref"], "local_image_id":patched["raw_report"]["_appsec"]["image_id"],
            "execution_evidence":{"remediation_input":audit.input_manifest(scan_evidence.copa_report(original["raw_report"]))}}],
            "diffs":[{"original_scan_id":"original","patched_scan_id":"patched"}]}


class RemediationAuditTests(unittest.TestCase):
    def test_scope_and_coverage(self):
        result = audit.analyze(payload())
        self.assertEqual(result["input_status"], "matches_expected")
        self.assertEqual(result["expected_v2_input"]["finding_count"], 2)
        self.assertEqual(result["original_findings"], 4)
        self.assertEqual(result["introduced"], 1)
        self.assertEqual(result["cohorts"]["os_known_fix"]["remaining"], 1)
        self.assertEqual(result["cohorts"]["os_known_fix"]["disappearance_rate_pct"], 50.0)
        self.assertEqual(result["cohorts"]["application_known_fix"]["coverage_unknown"], 1)
        self.assertIsNone(result["cohorts"]["application_known_fix"]["disappearance_rate_pct"])
        self.assertFalse(result["scanner_metadata_match"])

    def test_missing_or_wrong_rescan_never_counts_disappearance(self):
        for key in ("patches","diffs"):
            p = payload()
            p[key] = []
            r = audit.analyze(p)
            self.assertEqual(r["comparison"], "unavailable")
            self.assertIsNone(r["cohorts"]["os_known_fix"]["remaining"])
        p = payload()
        p["scans"][1]["status"] = "failed"
        self.assertEqual(audit.analyze(p)["comparison"], "unavailable")

    def test_invalid_original(self):
        p = payload()
        p["scans"][0]["raw_report"]["Results"] = []
        self.assertEqual(audit.analyze(p)["status"], "original_unverified")

    def test_mixed_duplicate_is_not_attributed_to_os_known_fix(self):
        p = payload()
        p["scans"][0]["raw_report"]["Results"][0]["Vulnerabilities"].append(finding("CVE-1","libc6",fixed=""))
        r = audit.analyze(p)
        self.assertEqual(r["cohorts"]["ambiguous"]["original"], 2)
        self.assertEqual(r["cohorts"]["os_known_fix"]["original"], 1)
        self.assertEqual(r["input_status"], "mismatch")

    def test_manifest_stable_and_report_unmodified(self):
        p = payload()
        before = deepcopy(p)
        audit.analyze(p)
        self.assertEqual(p, before)
        report = p["scans"][0]["raw_report"]
        expected = scan_evidence.copa_report(report)
        self.assertEqual(audit.input_manifest(expected), audit.input_manifest(dict(reversed(list(expected.items())))))
