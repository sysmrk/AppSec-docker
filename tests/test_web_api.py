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
            response = client.post("/pipelines", json={"image": "nginx:stable"},
                headers={"X-Requested-With": "AppSec-Control-Center"})
            self.assertEqual(response.status_code, 401)

    def test_download_auth_with_missing_credentials_is_401(self):
        with TestClient(app) as client:
            response = client.get("/api/reports/not-a-report/download")
            self.assertEqual(response.status_code, 401)

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
