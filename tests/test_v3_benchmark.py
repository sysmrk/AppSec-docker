import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

SPEC = importlib.util.spec_from_file_location("v3_benchmark", Path(__file__).resolve().parents[1] / "scripts/v3-benchmark.py")
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class BenchmarkTests(unittest.TestCase):
    def test_snapshot_hash_detects_content_change(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "db").mkdir()
            (root / "db" / "trivy.db").write_bytes(b"abc")
            (root / "db" / "metadata.json").write_text("{}")
            original = bench.snapshot_manifest(root)
            (root / "db" / "trivy.db").write_bytes(b"xyz")
            self.assertNotEqual(original, bench.snapshot_manifest(root))

    def test_missing_database_rejected(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "prepared Trivy"):
                bench.snapshot_manifest(Path(directory))

    def test_network_and_input_are_restricted(self):
        command = bench.scanner_args("sha256:" + "a"*64, Path("/tmp/work"), "test-scanner")
        self.assertIn("--pull=never", command)
        self.assertEqual(command[command.index("--network")+1], "none")
        self.assertIn("--skip-db-update", command)
        self.assertIn("--skip-java-db-update", command)
        self.assertIn("--offline-scan", command)
        self.assertIn("--input", command)
        self.assertNotIn("/var/run/docker.sock", " ".join(command))
