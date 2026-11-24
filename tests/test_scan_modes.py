import unittest
import subprocess
from unittest.mock import MagicMock, patch

from appsecctl import cli, db, policy
from appsecctl.errors import classify


class ScanModeTests(unittest.TestCase):
    def test_report_only_preserves_findings_without_a_policy_pass(self):
        scan = {"critical_count": 2}
        status, rules, violations = policy.evaluate(scan, {"enforce": False})
        self.assertEqual(status, "report_only")
        self.assertFalse(rules["enforce"])
        self.assertEqual(violations, [{"severity": "CRITICAL", "limit": 0, "count": 2}])
        self.assertEqual(policy.evaluate(scan, {"max_critical": 0})[0], "failed")

    def test_java_database_failure_is_classified_from_scanner_output(self):
        command = ["docker", "run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "trivy"]
        java_error = subprocess.CalledProcessError(1, command, stderr="Unable to initialize the Java DB: 403 Forbidden")
        self.assertEqual(classify(java_error)["code"], "TRIVY_JAVA_DB")
        self.assertEqual(classify(subprocess.CalledProcessError(1, command))["code"], "OPERATION_FAILED")

    def test_java_database_repository_is_forwarded(self):
        with patch.dict("os.environ", {"TRIVY_JAVA_DB_REPOSITORY": "registry.example.org/java-db:1"}):
            self.assertIn("TRIVY_JAVA_DB_REPOSITORY=registry.example.org/java-db:1", cli.trivy_database_options())

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
             patch.object(cli.image_sources, "pull_image", return_value="nginx:stable"), \
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
             patch.object(cli.image_sources, "pull_image", return_value="nginx:stable"), \
             patch.object(cli, "scan_image", side_effect=["source-scan", "patched-scan"]), \
             patch.object(cli, "generate_sbom"), \
             patch.object(cli, "patch_from_scan", return_value=("patch-id", "patched-image")) as patcher, \
             patch.object(cli, "create_diff"), \
             patch.object(cli, "evaluate_policy", return_value="passed"), \
             patch.object(cli, "write_pipeline_report_if_ready"), \
             patch.object(cli, "print_summary"):
            cli.run_pipeline("nginx:stable", mode="patch")
            patcher.assert_called_once_with("source-scan")


    def test_direct_patch_prepares_local_image_without_registry_commands(self):
        scan = {"status": "success", "image_ref": "example.org/team/image:1",
                "pipeline_id": "pipeline", "report_path": "/reports/scan.json"}
        with patch.object(cli, "db") as database, patch.object(cli, "run_command") as command, \
             patch.object(cli.patch_sources, "policy_environment") as source_policy:
            source_policy.return_value.__enter__.return_value = None
            database.get_scan.return_value = scan
            _, image_ref = cli.patch_from_scan("scan")
        command.assert_called_once()
        self.assertEqual(command.call_args.args[0][:2], ["copa", "patch"])
        self.assertTrue(image_ref.startswith("example.org/team/image:patched-"))
        self.assertTrue(command.call_args.kwargs["capture_errors"])

    def test_copa_failure_persists_concrete_diagnostic(self):
        scan = {"status": "success", "image_ref": "example.org/team/image:1",
                "pipeline_id": "pipeline", "report_path": "/reports/scan.json"}
        failure = subprocess.CalledProcessError(
            1, ["copa", "patch"], stderr="failed to solve: registry returned 403 Forbidden")
        with patch.object(cli, "db") as database, \
             patch.object(cli, "run_command", side_effect=failure) as command, \
             patch.object(cli.patch_sources, "policy_environment") as source_policy:
            source_policy.return_value.__enter__.return_value = None
            database.get_scan.return_value = scan
            with self.assertRaises(subprocess.CalledProcessError):
                cli.patch_from_scan("scan")
            self.assertTrue(command.call_args.kwargs["capture_errors"])
            self.assertIn("403 Forbidden", database.update_patch_failed.call_args.args[2])

    def test_publication_without_approved_job_is_blocked(self):
        with patch.object(cli, "db") as database, patch.object(cli, "run_command") as command:
            conn = database.connect.return_value.__enter__.return_value
            conn.execute.return_value.fetchone.return_value = None
            with self.assertRaisesRegex(RuntimeError, "No prepared"):
                cli.publish_prepared_patch("pipeline", "unapproved-job")
            query, args = conn.execute.call_args.args
            self.assertIn("w.publish_decision='approve_publish'", query)
            self.assertIn("sr.phase='patched'", query)
            self.assertIn("sr.image_ref=p.local_image_ref", query)
            self.assertEqual(args, ("pipeline", "unapproved-job"))
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
