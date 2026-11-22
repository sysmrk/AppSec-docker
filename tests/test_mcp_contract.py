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
