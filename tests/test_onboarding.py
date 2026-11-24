import importlib.machinery
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def load_cli():
    root = Path(__file__).resolve().parents[1]
    loader = importlib.machinery.SourceFileLoader("appsec_cli", str(root / "appsec"))
    return loader.load_module()


class OnboardingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = load_cli()

    def test_setup_creates_secrets_and_preserves_existing_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            env = root / ".env"
            template = root / ".env.example"
            template.write_text(
                "POSTGRES_PASSWORD=weak\nS3_SECRET_ACCESS_KEY=weak\n"
                "MINIO_ROOT_PASSWORD=weak\nAPPSEC_SESSION_COOKIE_SECURE=true\n",
                encoding="utf-8"
            )
            with patch.object(self.cli, "ROOT", root), \
                 patch.object(self.cli, "ENV_FILE", env), \
                 patch.object(self.cli, "ENV_TEMPLATE", template):
                self.cli.setup(SimpleNamespace())
                content = env.read_text(encoding="utf-8")
                settings = self.cli.read_env()
                self.assertNotIn("weak", content)
                self.assertGreaterEqual(len(settings["POSTGRES_PASSWORD"]), 30)
                self.assertEqual(settings["S3_SECRET_ACCESS_KEY"], settings["MINIO_ROOT_PASSWORD"])
                self.assertEqual(settings["APPSEC_SESSION_COOKIE_SECURE"], "false")
                if os.name != "nt":
                    self.assertEqual(env.stat().st_mode & 0o777, 0o600)
                before = env.read_bytes()
                self.cli.setup(SimpleNamespace())
                self.assertEqual(env.read_bytes(), before)

    def test_start_is_scan_only_unless_explicit(self):
        cli = self.cli
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(cli, "ENV_FILE", Path(folder) / ".env"), \
             patch.object(cli, "check_prerequisites"), \
             patch.object(cli, "compose") as compose_calls, \
             patch.object(cli, "run") as run_command, \
             patch.object(cli.os, "environ", dict(os.environ)):
            cli.ENV_FILE.write_text("POSTGRES_PASSWORD=xyz\n")
            cli.start(SimpleNamespace(analytics=False, patching=False))
            calls = [call.args for call in compose_calls.call_args_list]
            self.assertFalse(any("buildkit" in args for args in calls))
            self.assertFalse(any("patch" in args for args in calls))
            self.assertEqual(cli.os.environ["APPSEC_PATCH_ENABLED"], "false")
            self.assertTrue(any("metabase" in str(args).lower() for args in [call.args for call in run_command.call_args_list]))
            runner_build = ("--profile", "tools", "build", "appsec-runner")
            migrate = ("--profile", "tools", "run", "--rm", "appsec-runner", "migrate")
            self.assertIn(runner_build, calls)
            self.assertIn(migrate, calls)
            self.assertLess(calls.index(runner_build), calls.index(migrate))
            platform_start = next(i for i, args in enumerate(calls) if "--build" in args and "worker" in args)
            self.assertLess(calls.index(migrate), platform_start)

    def test_migration_failure_prevents_platform_start(self):
        cli = self.cli
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(cli, "ENV_FILE", Path(folder) / ".env"), \
             patch.object(cli, "check_prerequisites"), \
             patch.object(cli, "compose") as compose_calls, \
             patch.object(cli, "run") as run_command:
            cli.ENV_FILE.write_text("POSTGRES_PASSWORD=xyz\n")

            def fail_migration(*args):
                if "migrate" in args:
                    raise RuntimeError("migration failed")

            compose_calls.side_effect = fail_migration
            with self.assertRaisesRegex(RuntimeError, "migration failed"):
                cli.start(SimpleNamespace(analytics=False, patching=False))
            self.assertFalse(any("--build" in call.args and "worker" in call.args
                                 for call in compose_calls.call_args_list))
            run_command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
