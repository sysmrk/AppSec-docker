import unittest
from appsecctl import approved_binaries as ab, alpine_discovery as apk

class ApprovedBinaryTests(unittest.TestCase):
    def policy(self):
        return {"schema":"appsec.approved-binaries/v1","repositories":[{"id":"vendor","url":"https://packages.example.org/debian","suite":"trixie","component":"main","keyring_sha256":"a"*64,"packages":["curl"]}]}

    def test_policy(self):
        self.assertEqual(ab.validate(self.policy())[0]["id"],"vendor")
        for url in ("http://example.org","https://user@example.org","https://example.org/a/../b","https://example.org/x\n"):
            p=self.policy()
            p["repositories"][0]["url"]=url
            with self.assertRaises(ValueError):
                ab.validate(p)
        p=self.policy()
        p["repositories"][0]["suite"]="sid"
        with self.assertRaises(ValueError):
            ab.validate(p)

    def test_isolated_probe(self):
        self.assertIn("/tmp/appsec-vendor-key.gpg",ab.PROBE)
        self.assertNotIn("suite-backports",ab.PROBE)
        self.assertIn("Acquire::AllowInsecureRepositories",ab.PROBE)

    def test_parse(self):
        output="@@PACKAGE\tcurl\t1.0\tcurl\t2.0\nPackage: curl\nVersion: 2.0\nArchitecture: amd64\nSHA256: "+"a"*64+"\nFilename: pool/main/c/curl/curl.deb\nSize: 123\n@@ENDPACKAGE\n@@COMPLETE\n"
        rows=ab.parse(output,{"curl":{"version":"1.0"}},["curl"])
        self.assertEqual(rows[0]["status"],"signed_binary_found")
        self.assertEqual(rows[0]["decision"],"REVIEW_REQUIRED")
        with self.assertRaises(ValueError):
            ab.parse(output,{"curl":{"version":"1.0"}},[])
        with self.assertRaises(ValueError):
            ab.parse(output.replace("@@COMPLETE",""),{"curl":{"version":"1.0"}},["curl"])

    def test_apk_review(self):
        result=apk.parse("(1/1) Upgrading busybox (1.36.1-r1 -> 1.36.1-r2)\nOK: 7 MiB in 16 packages\n@@COMPLETE\n")
        self.assertEqual(result["candidate_count"],1)
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(apk.parse("(1/1) Installing new-package (1.0-r0)\n@@COMPLETE\n")["status"],"review_required")
        with self.assertRaises(ValueError):
            apk.parse("OK: 7 MiB in 16 packages")

if __name__=="__main__":
    unittest.main()
