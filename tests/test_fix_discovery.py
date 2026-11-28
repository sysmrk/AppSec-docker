import unittest
from appsecctl import fix_discovery as d

class FixDiscoveryTests(unittest.TestCase):
    def test_version_order_and_release_scope(self):
        self.assertTrue(d.ge("1:1.0-1","9.9-9"))
        self.assertFalse(d.ge("1.0~rc1","1.0"))
        self.assertEqual(d.classify({"releases":{"trixie":{"status":"resolved","fixed_version":"1.0-2"}}},"trixie","1.0-1")[0],"SAME_RELEASE_VENDOR_FIX_REPORTED")
        self.assertEqual(d.classify({"releases":{"trixie":{"status":"resolved","fixed_version":"0"}}},"trixie","1.0-1")[0],"VENDOR_NOT_AFFECTED_REVIEW")
        self.assertEqual(d.classify({"releases":{"trixie":{"status":"open"},"sid":{"status":"resolved","fixed_version":"2.0"}}},"trixie","1.0-1")[0],"NEWER_RELEASE_FIX_REPORTED")
        self.assertEqual(d.classify(None,"trixie","1.0-1")[0],"VENDOR_RECORD_MISSING")

    def test_source_identity_and_full_denominator(self):
        iid="sha256:"+"a"*64
        report={"ArtifactType":"container_image","Metadata":{"ImageID":iid,"OS":{"Family":"debian","Name":"13.8"}},
                "Results":[{"Class":"os-pkgs","Type":"debian","Target":"test","Packages":[
                    {"Name":"libfixture1","Version":"1.0","Release":"1","SrcName":"fixture","SrcVersion":"1.0","SrcRelease":"1","Arch":"amd64"}],
                    "Vulnerabilities":[{"PkgName":"libfixture1","InstalledVersion":"1.0-1","VulnerabilityID":"CVE-2026-1234","FixedVersion":""},
                     {"PkgName":"other","InstalledVersion":"1","VulnerabilityID":"TEMP-1234567-ABC"}]}]}
        tracker={"fixture":{"CVE-2026-1234":{"releases":{"trixie":{"status":"resolved","fixed_version":"1.0-2"}}}}}
        result=d.audit(report,tracker)
        self.assertEqual(result["summary"]["trivy"]["blank_fixed_version"],2)
        self.assertEqual(result["findings"][0]["category"],"SAME_RELEASE_VENDOR_FIX_REPORTED")
        self.assertEqual(result["findings"][1]["category"],"SOURCE_IDENTITY_UNVERIFIED")
        self.assertFalse(result["publication_authorized"])
        with self.assertRaisesRegex(ValueError,"identity"):
            d.audit(report,tracker,{"matches":[]})
