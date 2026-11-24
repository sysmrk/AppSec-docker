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
        self.assertIn('"/api/manual-workflows"', script)
        self.assertIn('"approve_patch"', script)
        self.assertIn('id="guided-detail"', html)
        self.assertNotIn("fakeData", script)
        self.assertNotIn("demoData", script)
        self.assertIn('id="login-form"', html)


if __name__ == "__main__":
    unittest.main()


class BulkUIContractTests(unittest.TestCase):
    def test_bulk_actions_only_in_workflow_history(self):
        root = Path(__file__).resolve().parents[1] / "runner/appsecctl/webui"
        html = (root / "index.html").read_text()
        script = (root / "assets/app.js").read_text()
        overview = html.split('id="view-overview"', 1)[1].split('</section>', 1)[0]
        guided = html.split('id="view-guided"', 1)[1].split('</section>', 1)[0]
        for identifier in ("pipeline-select-all", "pipeline-export", "pipeline-delete"):
            self.assertNotIn('id="'+identifier+'"', overview)
            self.assertIn('id="'+identifier+'"', guided)
        self.assertNotIn("Queued and recent jobs", overview)
        self.assertIn("Recent image workflows", overview)
        self.assertIn('id="guided-pagination"', guided)
        self.assertIn("/api/ui/image-workflows?limit=10&page=1", script)
        self.assertIn("/api/ui/image-workflows?limit=20&page=", script)
        self.assertIn("/api/ui/pipelines/export", script)
        self.assertIn("selectedPipelines", script)


class HistoryPaginationTests(unittest.TestCase):
    def test_page_is_bounded_and_clamped(self):
        class HistoryDB(FakeDB):
            def fetchone(self):
                return {"total": 43}
        conn = HistoryDB()
        result = ui_queries.image_workflow_history(conn, {"id": "user", "role": "viewer"}, page=99)
        self.assertEqual((result["page"], result["total_pages"], result["limit"]), (3, 3, 20))
        self.assertEqual(conn.calls[-1][1][-2:], (20, 40))
        self.assertIn("w.created_by", conn.calls[0][0])
        self.assertIn("NOT EXISTS", conn.calls[0][0])
