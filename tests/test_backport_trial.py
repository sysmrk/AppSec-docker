import unittest
from appsecctl import backport_trial as t

class TrialTests(unittest.TestCase):
    def test_select_and_reject(self):
        p={"mirror":"tuna","inventory":{"libtest":{"version":"1.0"}},"updates":{}}
        row={"package":"libtest","installed_source":"test","source_package":"test","before":"1.0","candidate":"2.0~bpo13+1","status":"signed_binary_found","security_status":"unverified","sha256":"a"*64,"threshold_leads":[{"id":"CVE-test"}]}
        c={"status":"completed","mirror":"tuna","vendor_snapshot_sha256":"b"*64,"candidates":[row],"simulations":{"test":{"status":"existing_package_upgrades_only","changes":{"libtest":{"before":"1.0","after":"2.0~bpo13+1"}}}}}
        self.assertEqual(t.select(p,c)["source"],"test")
        row["security_status"]="UPSTREAM_REGRESSION_LEAD"
        self.assertIsNone(t.select(p,c))
        row["security_status"]="unverified"
        c["simulations"]["test"]["status"]="dependency_additions_not_authorized"
        self.assertIsNone(t.select(p,c))
    def test_exact_script(self):
        s=t.archive_script("trixie")
        self.assertIn("apt-get -s --no-remove",s)
        self.assertIn("cmp",s)
        self.assertIn("apt-get download",s)
        with self.assertRaises(ValueError):
            t.archive_script("sid")
