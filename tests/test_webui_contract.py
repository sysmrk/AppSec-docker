import unittest
from pathlib import Path

from appsecctl import ui_queries


class FakeDB:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))
        return self

    def fetchall(self):
        return []

    def fetchone(self):
        return {"total": 0, "passed": 0, "policy_failed": 0, "failed": 0}


class UIContractTests(unittest.TestCase):
    def test_overview_restricts_non_admin_projects(self):
        conn = FakeDB()
        result = ui_queries.overview_data(conn, {"id": "test-user", "role": "viewer"})
        self.assertEqual(result["pipelines"], [])
        self.assertEqual(result["summary"]["total"], 0)
        for sql, params in conn.calls:
            self.assertIn("team_members", sql)
            self.assertEqual(params, (False, "test-user"))

    def test_ui_has_real_api_paths_without_fake_data(self):
        root = Path(__file__).resolve().parents[1] / "runner/appsecctl/webui"
        html = (root / "index.html").read_text()
        script = (root / "assets/app.js").read_text()
        self.assertIn("/api/ui/overview", script)
        self.assertIn("/api/ui/scans/", script)
        self.assertIn('"/pipelines"', script)
        self.assertIn('value = "scan"', script)
        self.assertNotIn("fakeData", script)
        self.assertNotIn("demoData", script)
        self.assertIn('id="login-form"', html)


if __name__ == "__main__":
    unittest.main()
