import unittest
from appsecctl import fix_research as r

class FixResearchTests(unittest.TestCase):
    def test_notes_are_scoped_and_unverified(self):
        lines=["CVE-2026-1234 (fixture)\n","\t- fixture 1.2\n",
               "\tNOTE: https://github.com/example/repo/commit/abcdef123456 (not necessarily fix)\n",
               "\tNOTE: https://example.org/advisory\n",
               "CVE-2026-1235 (unrelated)\n","\tNOTE: https://example.org/commit/abcdef123456\n"]
        refs=r.references(lines,{"CVE-2026-1234"})
        self.assertEqual(set(refs),{"CVE-2026-1234"})
        self.assertEqual([x["kind"] for x in refs["CVE-2026-1234"]],["commit_link","other_reference"])
        self.assertFalse(refs["CVE-2026-1234"][0]["verified"])

    def test_group_and_debian_version_order(self):
        def row(vid,version,sev):
            return {"scanner":"trivy","id":vid,"source_package":"fixture","package":"libfixture",
                    "installed_source_version":"1.0","severity":sev,"category":"NEWER_RELEASE_FIX_REPORTED",
                    "newer_releases":{"sid":{"fixed_version":version}}}
        report={"schema":"appsec.fix-discovery/v1","image_id":"sha256:"+"a"*64,"release":"trixie",
                "findings":[row("CVE-2026-1234","1.9","HIGH"),row("CVE-2026-1235","1.10","CRITICAL")]}
        output=r.research(report,{})
        self.assertEqual(output["total_findings"],2)
        self.assertEqual(output["source_packages"][0]["newer_release_highest_reported_fix"],{"sid":"1.10"})
        self.assertEqual(output["source_packages"][0]["newer_release_unique_advisories"],2)
        self.assertFalse(output["publication_authorized"])
