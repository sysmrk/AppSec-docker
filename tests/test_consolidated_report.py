import unittest
from appsecctl.consolidated_report import render


class ConsolidatedReportTests(unittest.TestCase):
    def test_initial_scan_never_claims_zero_after_patch(self):
        payload = {
            "pipeline": {"requested_image": "nginx:1", "status": "success"},
            "scans": [{"id": "scan-1", "phase": "original", "status": "success", "critical_count": 3,
                       "high_count": 4, "raw_report": {"Results": []}}],
            "policies": [], "diffs": [],
        }
        text = render("pipeline", payload)
        self.assertIn("Initial scan", text)
        self.assertIn("No patched scan.", text)
        self.assertIn("Recommendation pending", text)
        self.assertIn("After patch", text)

    def test_two_phases_and_advisory(self):
        from test_remediation_audit import payload as verified_payload
        payload = verified_payload()
        payload["pipeline"] = {"requested_image": "<script>alert(1)</script>", "status": "success"}
        payload["policies"] = [{"scan_id": "patched", "status": "not_recommended",
                                "violations": [{"severity": "CRITICAL", "count": 1, "limit": 0}]}]
        text = render("pipeline", payload)
        self.assertIn("Publication not recommended", text)
        self.assertIn("Full unified finding table", text)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)


class FailedScanTruthfulnessTests(unittest.TestCase):
    def test_failed_patched_scan_never_displays_fake_zero(self):
        payload = {
            "pipeline": {"requested_image": "nginx:1", "status": "failed"},
            "scans": [{"phase": "original", "id": "before", "status": "success", "critical_count": 2},
                      {"phase": "patched", "id": "after", "status": "failed", "critical_count": 0,
                       "error_message": "SOURCE_PULL_FAILED: registry returned 403"}],
            "policies": [], "diffs": [],
        }
        text = render("pipeline", payload)
        self.assertIn("SOURCE_PULL_FAILED", text)
        self.assertIn("no verified results", text)
        self.assertIn("Recommendation pending", text)

class UnifiedFindingTests(unittest.TestCase):
    def test_all_rows_low_hidden_unknown_and_fixed(self):
        from appsecctl.consolidated_report import compare_findings, comparison_table
        def scan(tag, entries):
            return {"raw_report": {"Results": [{"Class": "os-pkgs", "Type": "debian",
                "Target": tag + " (debian 13.7)", "Packages": [{"Name":"p","Version":"1"}], "Vulnerabilities": entries}]}}
        items = [{"VulnerabilityID": "CVE-test-" + str(i), "PkgName": "p", "Severity": "HIGH",
                  "InstalledVersion": "1", "FixedVersion": "2"} for i in range(300)]
        unknown = {"VulnerabilityID": "TEMP-1", "PkgName": "p", "Severity": "UNKNOWN", "VendorSeverity": {"vendor": 3}}
        low = {"VulnerabilityID": "LOW-1", "PkgName": "p", "Severity": "LOW"}
        a = scan("original", items + [unknown, low])
        b = scan("patched", [unknown, dict(items[0], Severity="LOW")])
        rows = compare_findings(a, b, True)
        html = comparison_table(rows, True)
        self.assertEqual(sum(x[2] == "Fixed" for x in rows), 299)
        self.assertIn("CVE-test-299", html)
        self.assertIn('finding-state fixed', html)
        self.assertIn("vendor: HIGH", html)
        self.assertNotIn("<th>Triage</th>", html)
        self.assertEqual(html.count("<th>"), 8)
        self.assertNotIn("LOW-1", html)
        self.assertNotIn('finding-state fixed', comparison_table(compare_findings(a, None, False), False))

    def test_missing_target_not_fixed_and_unlinked_rescan_not_verified(self):
        from test_remediation_audit import payload
        from appsecctl.consolidated_report import compare_findings
        p = payload()
        rows = compare_findings(*p["scans"], True)
        self.assertEqual([r[2] for r in rows if r[0] and r[0]["cve"] == "CVE-4"], ["Coverage unknown"])
        text = render("pipeline", p)
        self.assertIn("Coverage unknown", text)
        p["patches"] = []
        text = render("pipeline", p)
        self.assertNotIn('finding-state fixed', text)


class OptimizationReportTests(unittest.TestCase):
    def test_historical_aggregate_result_visible_without_copa(self):
        payload={"pipeline":{"requested_image":"nginx","status":"success"},
                 "optimization":{"state":"completed","stage":"original","result":{
                    "comparison":"frozen_db","original_findings":452,"overall_findings":300,
                    "base_severity":{"HIGH":10},"candidate_severity":{"HIGH":4},
                    "overall_introduced":0,"coverage_unknown":0,"candidate":"local:optimized"}}}
        html=render("pipeline",payload)
        self.assertIn("452 → 300",html)
        self.assertIn("Final optimized candidate",html)
        self.assertIn("individual candidate findings were not retained",html)
        self.assertIn("publication not authorized",html)
        self.assertNotIn("Recommended for publication</strong>",html)
