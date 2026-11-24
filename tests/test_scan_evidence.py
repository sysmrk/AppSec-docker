import unittest
from appsecctl import scan_evidence as evidence


class EvidenceTests(unittest.TestCase):
    def report(self):
        return {"ArtifactType": "container_image", "Metadata": {"ImageID": "sha256:test"},
                "Results": [{"Target": "nginx:1 (debian 13.1)", "Class": "os-pkgs", "Packages": [{"Name": "openssl", "Version": "1"}], "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "FixedVersion": "2"},
                    {"VulnerabilityID": "CVE-2", "PkgName": "libc"}]},
                    {"Target": "app/package-lock.json", "Class": "lang-pkgs",
                     "Vulnerabilities": [{"VulnerabilityID": "CVE-3", "PkgName": "foo", "FixedVersion": "2"}]}]}

    def test_empty_or_wrong_image_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "ImageID"):
            evidence.validate_report(self.report(), "sha256:other")
        report = self.report()
        report["Results"] = []
        with self.assertRaisesRegex(RuntimeError, "no scan targets"):
            evidence.validate_report(report, "sha256:test")

    def test_clean_os_target_is_valid(self):
        report = self.report()
        report["Results"] = [{"Target": "image (alpine 3.22)", "Class": "os-pkgs", "Packages": [{"Name": "busybox", "Version": "1"}]}]
        evidence.validate_report(report, "sha256:test")

    def test_copa_input_does_not_remove_full_scan_findings(self):
        report = self.report()
        filtered = evidence.copa_report(report)
        self.assertEqual(len(filtered["Results"]), 1)
        self.assertEqual(len(filtered["Results"][0]["Vulnerabilities"]), 1)
        self.assertEqual(len(report["Results"][0]["Vulnerabilities"]), 2)

    def test_eligibility_distinguishes_application_and_os(self):
        report = self.report()
        report["_appsec"] = {"verified": True, "image_id": "sha256:test"}
        scan = {"status": "success", "raw_report": report}
        result = evidence.patch_eligibility(scan)
        self.assertTrue(result["eligible"])
        self.assertEqual((result["os_fixable"], result["os_no_known_fix"], result["application_fixable"]), (1, 1, 1))
        report["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = "  "
        result = evidence.patch_eligibility(scan)
        self.assertEqual(result["code"], "NO_FIXABLE_OS")
        self.assertEqual(result["application_fixable"], 1)
        with self.assertRaises(evidence.NoFixableOS):
            evidence.copa_report(report)
        report["Results"][0]["Packages"] = []
        self.assertEqual(evidence.patch_eligibility(scan)["code"], "SCAN_EVIDENCE_INVALID")

    def test_os_target_tag_does_not_fake_fix(self):
        self.assertEqual(evidence.stable_target("nginx:1 (debian 13.1)"),
                         evidence.stable_target("nginx:patched (debian 13.2)"))
        self.assertNotEqual(evidence.stable_target("a/package-lock.json"), evidence.stable_target("b/package-lock.json"))

    def test_push_digest(self):
        digest = "sha256:" + "a"*64
        self.assertEqual(evidence.push_digest("tag: digest: "+digest+" size: 123"), digest)
        with self.assertRaises(RuntimeError):
            evidence.push_digest("unknown result")

    def test_os_target_without_inventory_is_not_a_clean_scan(self):
        report = self.report()
        report["Results"][0]["Packages"] = []
        with self.assertRaisesRegex(RuntimeError, "inventory missing"):
            evidence.validate_report(report, "sha256:test")
