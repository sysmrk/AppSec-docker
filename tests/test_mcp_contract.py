"""Static/isolated tests: no live Postgres or AI service needed."""
import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("appsec_mcp", HERE / "integrations/mcp/appsec_mcp.py")


class MCPContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.module)

    def test_uuid_rejected(self):
        with self.assertRaises(ValueError):
            self.module._uuid("1; DROP TABLE users")

    def test_limit_clamped(self):
        self.assertEqual(self.module._limit(999999), 100)
        self.assertEqual(self.module._limit(-4), 1)

    def test_plan_api_requires_explicit_key(self):
        with patch.dict(os.environ, {"APPSEC_MCP_PLAN_API_KEY": "", "APPSEC_MCP_PLAN_API": "http://api:8080"}):
            self.assertIn("error", self.module._plan_api("GET", "00000000-0000-0000-0000-000000000001", "plan"))

    def test_plan_api_refuses_untrusted_origin(self):
        with patch.dict(os.environ, {"APPSEC_MCP_PLAN_API": "https://evil.example", "APPSEC_MCP_PLAN_API_KEY": "dummy"}):
            with self.assertRaisesRegex(RuntimeError, "Unsupported"):
                self.module._plan_api("GET", "00000000-0000-0000-0000-000000000001", "plan")

    def test_plan_request_is_fixed_scope_and_bounded(self):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = b'{"status":"planned"}'
        pid = "00000000-0000-0000-0000-000000000001"
        with patch.dict(os.environ, {"APPSEC_MCP_PLAN_API_KEY": "test-key", "APPSEC_MCP_PLAN_API": "http://api:8080"}), \
             patch.object(self.module.urllib.request, "build_opener", return_value=opener):
            result = self.module.get_remediation_plan(pid, "residual", 10, 1000)
        self.assertEqual(result, {"status":"planned"})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://api:8080/api/remediation/"+pid+"/plan?stage=residual&offset=10&limit=100")
        self.assertEqual(request.get_header("X-api-key"),"test-key")
        self.assertEqual(request.get_method(),"GET")

    def test_readonly_session(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [{"count": 4}]
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor
        with patch.dict(os.environ, {"APPSEC_MCP_DATABASE_URL": "postgresql://readonly@postgres/appsec"}), \
             patch.object(self.module.psycopg, "connect", return_value=connection) as connect:
            self.assertEqual(self.module._fetch("SELECT 4 AS count"), [{"count": 4}])
            self.assertIn("default_transaction_read_only=on", connect.call_args.kwargs["options"])
            cursor.execute.assert_called_once_with("SELECT 4 AS count", ())


if __name__ == "__main__":
    unittest.main()
