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
        output="@@PACKAGE\tcurl\t1.0\tcurl\t1.0\t2.0\nPackage: curl\nVersion: 2.0\nArchitecture: amd64\nSHA256: "+"a"*64+"\nFilename: pool/main/c/curl/curl.deb\nSize: 123\n@@ENDPACKAGE\n@@COMPLETE\n"
        rows=ab.parse(output,{"curl":{"version":"1.0"}},["curl"])["candidates"]
        self.assertEqual(rows[0]["status"],"signed_binary_found")
        self.assertEqual(rows[0]["decision"],"REVIEW_REQUIRED")
        with self.assertRaises(ValueError):
            ab.parse(output,{"curl":{"version":"1.0"}},[])
        with self.assertRaises(ValueError):
            ab.parse(output.replace("@@COMPLETE",""),{"curl":{"version":"1.0"}},["curl"])

    def test_exact_dependency_review(self):
        output="@@PACKAGE\tcurl\t1.0\tcurl\t1.0\t2.0\nPackage: curl\nVersion: 2.0\nArchitecture: amd64\nSHA256: "+"a"*64+"\nFilename: pool/main/c/curl/curl.deb\nSize: 123\n@@ENDPACKAGE\n@@SIM\tcurl\n@@EXIT 0\nInst curl [1.0] (2.0 Vendor [amd64])\n1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n@@ENDSIM\n@@COMPLETE\n"
        inv={"curl":{"version":"1.0"},"libfoo":{"version":"1.0"}}
        self.assertEqual(ab.parse(output,inv,["curl"])["candidates"][0]["dependency_status"],"existing_package_upgrades_only")
        extra=output.replace("1 upgraded","Inst libfoo [1.0] (2.0 Vendor [amd64])\n2 upgraded")
        self.assertEqual(ab.parse(extra,inv,["curl"])["candidates"][0]["dependency_status"],"additional_upgrades_not_authorized")
        held="@@HOLD\tcurl\n"+output
        self.assertEqual(ab.parse(held,inv,["curl"])["candidates"][0]["dependency_status"],"held_package_blocked")
        self.assertEqual(ab.parse(output.replace("@@COMPLETE","@@SIMLIMIT\n@@COMPLETE"),inv,["curl"])["status"],"partial")

    def test_advisory_digest_and_identity(self):
        import json, hashlib
        row=self.policy()["repositories"][0]
        record={"package":"curl","version":"2.0","architecture":"amd64","archive_sha256":"a"*64,"cve":"CVE-2026-1234","advisory_url":"https://example.org/advisories/1234"}
        data=json.dumps({"schema":"appsec.external-advisories/v1","repository_id":"vendor","suite":"trixie","records":[record]}).encode()
        row["advisory_sha256"]=hashlib.sha256(data).hexdigest()
        claims=ab.advisories(data,row)
        candidate={"status":"signed_binary_found","package":"curl","installed_source":"curl","installed_source_version":"1.0","before":"1.0","candidate":"2.0","architecture":"amd64","sha256":"a"*64}
        finding={"scanner":"trivy","source_package":"curl","installed_source_version":"1.0","installed_binary_version":"1.0","package":"curl","id":"CVE-2026-1234"}
        ab.correlate([candidate],[finding],claims)
        self.assertEqual(candidate["security_status"],"operator_assertion_matched")
        self.assertEqual(candidate["decision"],"REVIEW_REQUIRED")
        candidate["sha256"]="b"*64
        ab.correlate([candidate],[finding],claims)
        self.assertEqual(candidate["security_status"],"unverified")
        with self.assertRaises(ValueError):
            ab.advisories(data+b" ",row)

    def test_apk_review(self):
        result=apk.parse("(1/1) Upgrading busybox (1.36.1-r1 -> 1.36.1-r2)\nOK: 7 MiB in 16 packages\n@@COMPLETE\n")
        self.assertEqual(result["candidate_count"],1)
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(apk.parse("(1/1) Installing new-package (1.0-r0)\n@@COMPLETE\n")["status"],"review_required")
        with self.assertRaises(ValueError):
            apk.parse("OK: 7 MiB in 16 packages")

if __name__=="__main__":
    unittest.main()
