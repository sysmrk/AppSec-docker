import unittest
from appsecctl import upstream_curl as u

class UpstreamCurlTests(unittest.TestCase):
    def test_reintroduction_and_fixed_boundary(self):
        events=[{"introduced":"8.9.0"},{"fixed":"8.14.3"},{"introduced":"8.15.0"},{"fixed":"8.16.2"},{"introduced":"8.17.0"},{"fixed":"8.20.2"},{"introduced":"8.21.0"},{"fixed":"8.23.0"}]
        for v,expected in [("8.14.1",True),("8.14.3",False),("8.20.2",False),("8.21.0",True),("8.23.0",False)]:
            self.assertEqual(u.in_range(events,u.version(v)),expected)
        self.assertIsNone(u.in_range([{"introduced":"8.0.0"},{"fixed":"7.0.0"}],u.version("8.1.0")))
        self.assertIsNone(u.in_range([{"introduced":"8.0.0"},{"limit":"9.0.0"}],u.version("8.1.0")))
        self.assertTrue(u.in_range([{"introduced":"0"},{"last_affected":"8.1.0"}],u.version("8.1.0")))

    def test_occurrence_counts_and_new_exposure(self):
        def advisory(ident,events):
            return {"id":"CURL-"+ident,"aliases":[ident],"database_specific":{"package":"curl"},
                    "affected":[{"ranges":[{"type":"SEMVER","events":events}]}]}
        def row(ident,pkg):
            return {"scanner":"trivy","source_package":"curl","id":ident,"package":pkg,
                    "installed_source_version":"8.14.1-2+deb13u7"}
        report={"schema":"appsec.fix-research/v1","image_id":"sha256:"+"a"*64,"findings":[
                row("CVE-2026-1234","curl"),row("CVE-2026-1234","libcurl4t64"),row("CVE-2026-9999","curl")]}
        result=u.audit(report,[advisory("CVE-2026-1234",[{"introduced":"0"},{"fixed":"8.20.0"}]),
            advisory("CVE-2026-1235",[{"introduced":"8.21.0"},{"fixed":"8.23.0"}])],"8.14.1","8.21.0")
        self.assertEqual(result["finding_breakdown"],{"UPSTREAM_REMEDIATION_LEAD":2,"UPSTREAM_MISSING_OR_AMBIGUOUS":1})
        self.assertEqual(result["unique_advisory_breakdown"]["UPSTREAM_REMEDIATION_LEAD"],1)
        self.assertEqual(result["new_upstream_exposure_leads"][0]["id"],"CVE-2026-1235")
        self.assertFalse(result["publication_authorized"])

    def test_curl_same_release_introduced_fixed(self):
        # Actual event shape in upstream CVE-2026-11856.
        events=[{"introduced":"7.10.6"},{"fixed":"8.14.2"},
                {"introduced":"8.15.0"},{"fixed":"8.16.1"},
                {"introduced":"8.17.0"},{"fixed":"8.20.1"},
                {"introduced":"8.21.0"},{"fixed":"8.21.0"}]
        for v,expected in [("8.14.1",True),("8.14.2",False),
                           ("8.20.0",True),("8.21.0",False),("8.23.0",False)]:
            self.assertIs(u.in_range(events,u.version(v)),expected)
        self.assertIsNone(u.in_range([{"introduced":"8.0.0"},{"introduced":"8.0.0"}],u.version("8.0.0")))
        self.assertIsNone(u.in_range([{"introduced":"8.0.0"},{"fixed":"8.0.0"},{"introduced":"8.0.0"}],u.version("8.0.0")))
        self.assertIsNone(u.in_range([{"introduced":"8.0.0"},{"last_affected":"8.0.0"}],u.version("8.0.0")))

    def test_historical_curl_release(self):
        # Actual CVE-2026-8932 release events, including old two-part
        # version notation and empty final interval.
        events=[{"introduced":"7.7"},{"fixed":"8.14.2"},
                {"introduced":"8.15.0"},{"fixed":"8.16.1"},
                {"introduced":"8.17.0"},{"fixed":"8.20.1"},
                {"introduced":"8.21.0"},{"fixed":"8.21.0"}]
        for v,expected in [("7.6.0",False),("7.7.0",True),("8.14.1",True),
                           ("8.21.0",False),("8.23.0",False)]:
            self.assertIs(u.in_range(events,u.version(v)),expected)
        with self.assertRaises(ValueError):
            u.version("7.7")
        self.assertIsNone(u.in_range([{"introduced":"7.7-rc1"}],u.version("8.23.0")))
