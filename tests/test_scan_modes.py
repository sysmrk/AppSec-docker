import unittest
from unittest.mock import MagicMock, patch

from appsecctl import cli, db


class ScanModeTests(unittest.TestCase):
    def test_enqueue_scan_is_default(self):
        conn = MagicMock()
        db.enqueue_pipeline(conn, "nginx:stable")
        params = conn.execute.call_args.args[1]
        self.assertEqual(params[-1], "scan")

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            db.enqueue_pipeline(MagicMock(), "nginx:stable", mode="dangerous")

    def test_scan_does_not_patch_or_push(self):
        context = MagicMock()
        context.__enter__.return_value = MagicMock()
        with patch.object(cli.db, "connect", return_value=context), \
             patch.object(cli.db, "get_or_create_image", return_value="image-id"), \
             patch.object(cli.db, "create_pipeline", return_value="pipeline-id"), \
             patch.object(cli, "scan_image", return_value="scan-id"), \
             patch.object(cli, "generate_sbom"), \
             patch.object(cli, "patch_from_scan") as patcher, \
             patch.object(cli, "evaluate_policy", return_value="passed"), \
             patch.object(cli, "write_pipeline_report_if_ready"), \
             patch.object(cli, "print_summary"):
            self.assertEqual(cli.run_pipeline("nginx:stable"), "pipeline-id")
            patcher.assert_not_called()

    def test_patch_mode_explicit(self):
        context = MagicMock()
        context.__enter__.return_value = MagicMock()
        with patch.object(cli.db, "connect", return_value=context), \
             patch.object(cli.db, "get_or_create_image", return_value="image-id"), \
             patch.object(cli.db, "create_pipeline", return_value="pipeline-id"), \
             patch.object(cli, "scan_image", side_effect=["source-scan", "patched-scan"]), \
             patch.object(cli, "generate_sbom"), \
             patch.object(cli, "patch_from_scan", return_value=("patch-id", "patched-image")) as patcher, \
             patch.object(cli, "create_diff"), \
             patch.object(cli, "evaluate_policy", return_value="passed"), \
             patch.object(cli, "write_pipeline_report_if_ready"), \
             patch.object(cli, "print_summary"):
            cli.run_pipeline("nginx:stable", mode="patch")
            patcher.assert_called_once_with("source-scan")


if __name__ == "__main__":
    unittest.main()
