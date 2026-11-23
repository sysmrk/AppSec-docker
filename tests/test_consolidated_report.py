import unittest
from appsecctl.consolidated_report import render


class ConsolidatedReportTests(unittest.TestCase):
    def test_initial_scan_never_claims_zero_after_patch(self):
        payload = {
            "pipeline": {"requested_image": "nginx:1", "status": "success"},
            "scans": [{"id": "scan-1", "phase": "original", "critical_count": 3,
                       "high_count": 4, "raw_report": {"Results": []}}],
            "policies": [], "diffs": [],
        }
        text = render("pipeline", payload)
        self.assertIn("Initial scan", text)
        self.assertIn("No patched scan yet", text)
        self.assertIn("Recommendation pending", text)
        self.assertIn("After patch", text)

    def test_two_phases_and_advisory(self):
        payload = {
            "pipeline": {"requested_image": "<script>alert(1)</script>", "status": "success"},
            "scans": [
                {"id": "s1", "phase": "original", "critical_count": 4, "high_count": 0},
                {"id": "s2", "phase": "patched", "critical_count": 1, "high_count": 0},
            ],
            "diffs": [{"fixed_count": 3, "remaining_count": 1, "introduced_count": 0}],
            "policies": [{"scan_id": "s2", "status": "not_recommended",
                          "violations": [{"severity": "CRITICAL", "count": 1, "limit": 0}]}],
        }
        text = render("pipeline", payload)
        self.assertIn("Publication not recommended", text)
        self.assertIn("After-patch vulnerabilities", text)
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
