import importlib.util
import json
from datetime import datetime,timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from appsecctl import v4_validation as v
SPEC=importlib.util.spec_from_file_location("v4_bench",Path(__file__).resolve().parents[1]/"scripts/v4-benchmark.py")
bench=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)

class V4LabTests(unittest.TestCase):
    def test_db_freshness(self):
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"db").mkdir()
            (root/"db/metadata.json").write_text(json.dumps({"Version":2,"UpdatedAt":"2026-11-24T13:00:00Z","NextUpdate":"2026-11-25T13:00:00Z"}))
            state=bench.database_state(root,datetime(2026,11,26,13,tzinfo=timezone.utc))
            self.assertEqual(state["age_hours"],48)
            self.assertFalse(state["fresh"])
            self.assertTrue(bench.database_state(root,datetime(2026,11,24,14,tzinfo=timezone.utc))["fresh"])

    def test_functional_gate(self):
        a={"status":"passed","http_status":200,"body_sha256":"a"}
        self.assertTrue(v.matches(a,dict(a)))
        self.assertFalse(v.matches(a,dict(a,body_sha256="b")))
        self.assertFalse(v.matches(a,dict(a,status="failed")))
        self.assertFalse(v.matches({},{}))
        with self.assertRaises(ValueError):
            v.smoke("ignored","//external")

    def test_v4_tags_and_retired_unsafe_updater(self):
        root=Path(__file__).resolve().parents[1]
        self.assertNotIn("  trivy-db-updater:",(root/"docker-compose.yaml").read_text())
        self.assertIn("develop/v4",(root/".github/workflows/tag-main-changes.yml").read_text())
