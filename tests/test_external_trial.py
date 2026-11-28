import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from appsecctl import external_trial as ext

class ExternalTrialTests(unittest.TestCase):
    def fixture(self):
        plan={"mirror":"tuna","inventory":{"curl":{"version":"1.0"}},"updates":{}}
        row={"package":"curl","installed_source":"curl","source_package":"curl","before":"1.0","candidate":"2.0",
             "status":"signed_binary_found","architecture":"amd64","sha256":"a"*64,"size":3,
             "operator_advisory_matches":[{"id":"CVE-2026-1234","advisory_url":"https://example.org/advisory"}]}
        repo={"id":"vendor","status":"completed","advisory_status":"operator_snapshot_matched","candidates":[row],
              "simulations":{"curl":{"status":"existing_package_upgrades_only","changes":{"curl":{"before":"1.0","after":"2.0"}}}}}
        return plan,{"status":"completed","policy_sha256":"b"*64,"repositories":[repo]}

    def test_selection_requires_exact_advisory_and_no_overlap(self):
        plan,catalog=self.fixture()
        self.assertEqual(ext.select(plan,catalog)["source"],"curl")
        plan["updates"]={"curl":{"before":"1.0","after":"1.1"}}
        self.assertIsNone(ext.select(plan,catalog))
        plan["updates"]={}
        catalog["repositories"][0]["candidates"][0]["operator_advisory_matches"]=[]
        self.assertIsNone(ext.select(plan,catalog))

    def test_exact_archive_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"curl.deb"
            p.write_bytes(b"abc")
            row={"sha256":hashlib.sha256(b"abc").hexdigest(),"size":3}
            self.assertEqual(ext.verify_archives(Path(tmp),[row]),{"curl.deb":row["sha256"]})
            p.write_bytes(b"xyz")
            with self.assertRaises(ValueError):
                ext.verify_archives(Path(tmp),[row])

    def test_archive_script_isolated(self):
        s=ext.archive_script(1,100)
        self.assertIn("/tmp/appsec-vendor-key.gpg",s)
        self.assertIn("apt-get -s --no-remove",s)
        self.assertIn("apt-get download",s)
        self.assertIn("cmp",s)
        self.assertNotIn("suite-backports",s)

    def test_matching_advisory_must_disappear(self):
        def report(cves):
            return {"raw_report":{"Results":[{"Class":"os-pkgs","Type":"debian","Vulnerabilities":[{"PkgName":"curl","VulnerabilityID":c} for c in cves]}]}}
        chosen={"claims":[("curl","CVE-2026-1234")]}
        self.assertEqual(ext.observed_claims([report(["CVE-2026-1234"]),report([])],chosen),[{"package":"curl","id":"CVE-2026-1234"}])
        self.assertEqual(ext.observed_claims([report(["CVE-2026-1234"]),report(["CVE-2026-1234"])],chosen),[])

    def test_disabled_never_selects(self):
        with patch.object(ext,"enabled",return_value=False),patch.object(ext,"select") as select:
            baseline={"candidate_image_id":"example"}
            self.assertEqual(ext.attempt({}, {}, {}, baseline, []),(baseline,{"status":"disabled"}))
            select.assert_not_called()
