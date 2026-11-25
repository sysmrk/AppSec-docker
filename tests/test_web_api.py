import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from appsecctl.api import app, current_user


ADMIN = {"id": "00000000-0000-0000-0000-000000000001", "role": "admin", "username": "test-admin"}


class WebAPIContractTests(unittest.TestCase):
    def tearDown(self):
        app.dependency_overrides.clear()

    def test_ui_is_served_without_external_frontend(self):
        with TestClient(app) as client:
            response = client.get("/ui/")
            self.assertEqual(response.status_code, 200)
            self.assertIn("AppSec Control Center", response.text)
            self.assertIn("no-store", response.headers["Cache-Control"])
            self.assertIn("./assets/app.js?v=", response.text)
            self.assertNotIn("__APPSEC_ASSET_KEY__", response.text)
            identity = client.get("/ui/build-info")
            self.assertEqual(identity.status_code, 200)
            self.assertEqual(len(identity.json()["source_sha256"]), 64)
            self.assertEqual(response.headers["X-AppSec-Source"], identity.json()["source_sha256"])
            js = client.get("/ui/assets/app.js")
            self.assertEqual(js.status_code, 200)
            self.assertIn("/api/ui/overview", js.text)

    def test_unauthenticated_read_and_scan_return_401(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/ui/overview").status_code, 401)
            self.assertEqual(client.get("/api/ui/capabilities").status_code, 401)
            response = client.post("/pipelines", json={"image": "nginx:stable"})
            self.assertEqual(response.status_code, 401)

    def test_cookie_write_requires_first_party_header(self):
        with TestClient(app) as client:
            client.cookies.set("appsec_session", "untrusted-cookie")
            response = client.post("/pipelines", json={"image": "nginx:stable"})
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json()["error"]["code"], "CSRF_REJECTED")
            self.assertTrue(response.headers.get("X-Request-ID"))

    def test_download_auth_with_missing_credentials_is_401(self):
        with TestClient(app) as client:
            response = client.get("/api/reports/not-a-report/download")
            self.assertEqual(response.status_code, 401)

    def test_remediation_requires_authentication(self):
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/remediation/00000000-0000-0000-0000-000000000002/plan").status_code, 401)

    def test_remediation_rejects_untyped_payload(self):
        app.dependency_overrides[current_user] = lambda: ADMIN
        with TestClient(app) as client:
            r = client.post("/api/remediation/00000000-0000-0000-0000-000000000002/validate",
                            json={"stage":"original", "plan_digest":"a"*64,
                                  "selections":[{"action_id":"b"*64,"strategy":"os_targeted","command":"not permitted"}]})
            self.assertEqual(r.status_code, 422)

    def test_unassigned_plan_denied_to_other_user(self):
        from unittest.mock import MagicMock
        viewer = dict(ADMIN, role="viewer")
        app.dependency_overrides[current_user] = lambda: viewer
        conn = MagicMock()
        conn.execute.return_value.fetchone.side_effect = [{"project_id":None}, {"project_id":None}, None]
        with patch("appsecctl.api.db.connect") as connect:
            connect.return_value.__enter__.return_value = conn
            with TestClient(app) as client:
                response = client.get("/api/remediation/00000000-0000-0000-0000-000000000002/plan")
                self.assertEqual(response.status_code,403)

    def test_owner_plan_and_stale_selection(self):
        from unittest.mock import MagicMock
        from test_remediation_audit import payload
        viewer = dict(ADMIN, role="viewer")
        app.dependency_overrides[current_user] = lambda: viewer
        conn = MagicMock()
        with patch("appsecctl.api.db.connect") as connect, patch("appsecctl.api.db.pipeline_summary", return_value=payload()):
            connect.return_value.__enter__.return_value = conn
            with TestClient(app) as client:
                conn.execute.return_value.fetchone.side_effect = [{"project_id":None}, {"project_id":None}, {"owned":1}]
                url = "/api/remediation/00000000-0000-0000-0000-000000000002"
                response = client.get(url + "/plan")
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.headers["Cache-Control"],"no-store")
                p = response.json()
                action = p["actions"][0]
                selection = {"stage":"original","plan_digest":p["plan_digest"],"selections":[
                    {"action_id":action["action_id"],"strategy":action["preferred_strategy"]}]}
                conn.execute.return_value.fetchone.side_effect = [{"project_id":None}, {"project_id":None}, {"owned":1}]
                self.assertFalse(client.post(url+"/validate",json=selection).json()["execution_authorized"])
                conn.execute.return_value.fetchone.side_effect = [{"project_id":None}, {"project_id":None}, {"owned":1}]
                selection["plan_digest"] = "0"*64
                self.assertEqual(client.post(url+"/validate",json=selection).status_code,409)

    def test_patching_cannot_be_queued_without_explicit_opt_in(self):
        app.dependency_overrides[current_user] = lambda: ADMIN
        with patch.dict(os.environ, {"APPSEC_PATCH_ENABLED": "false"}):
            with TestClient(app) as client:
                response = client.post("/pipelines", json={"image": "nginx:stable", "mode": "patch", "confirm_patch": True})
                self.assertEqual(response.status_code, 409)
                self.assertIn("disabled", response.json()["detail"])
                response = client.post("/pipelines", json={"image": "nginx:stable", "mode": "patch"})
                self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
