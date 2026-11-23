import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from appsecctl.sanitization import MASK, redact_gitleaks_report, validate_repo_target, sanitize_security_detail
from appsecctl import security
from appsecctl.errors import safe_message


class SecretSanitizationTests(unittest.TestCase):
    def test_repository_timeout_has_safe_stage_code(self):
        with tempfile.TemporaryDirectory() as workspace, \
             patch.dict(os.environ, {"WORKSPACES_DIR": workspace, "SECURITY_ALLOWED_GIT_HOSTS": "github.com"}), \
             patch.object(security, "run_command", side_effect=subprocess.TimeoutExpired(["SENTINEL"], 120)):
            with self.assertRaises(RuntimeError) as raised:
                security.prepare_repo("https://github.com/org/repo", "job")
        message = safe_message(raised.exception, "repository")
        self.assertTrue(message.startswith("GIT_CLONE_TIMEOUT:"))
        self.assertNotIn("SENTINEL", message)

    def test_gitleaks_secret_fields_removed(self):
        source = [{"Match": "password=TOP_SECRET", "Secret": "TOP_SECRET",
                   "Line": "password=TOP_SECRET", "RuleID": "generic-api-key"}]
        safe = redact_gitleaks_report(source)
        self.assertNotIn("TOP_SECRET", str(safe))
        self.assertEqual(safe[0]["Match"], MASK)
        self.assertEqual(source[0]["Secret"], "TOP_SECRET")

    def test_invalid_report_rejected(self):
        with self.assertRaises(ValueError):
            redact_gitleaks_report({"Match": "secret"})

    def test_old_db_secrets_not_returned(self):
        detail = {"job": {"raw_report": [{"Secret": "SENTINEL"}]},
                  "findings": [{"evidence": "SENTINEL", "metadata": {"secret": "SENTINEL", "commit": "abc"}}]}
        self.assertNotIn("SENTINEL", str(sanitize_security_detail(detail)))
        self.assertEqual(sanitize_security_detail(detail)["findings"][0]["metadata"]["commit"], "abc")

    def test_https_allowlist(self):
        with patch.dict(os.environ, {"SECURITY_ALLOWED_GIT_HOSTS": "github.com,git.example.net"}):
            self.assertEqual(validate_repo_target("https://git.example.net/team/repo.git"),
                             "https://git.example.net/team/repo.git")
            for target in ("file:///etc/shadow", "ssh://github.com/repo", "https://localhost/repo",
                           "https://127.0.0.1/repo", "https://user:secret@github.com/repo",
                           "https://github.com/repo?token=bad", "https://evil.example/repo"):
                with self.subTest(target=target), self.assertRaises(ValueError):
                    validate_repo_target(target)


if __name__ == "__main__":
    unittest.main()
