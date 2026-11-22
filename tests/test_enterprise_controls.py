import unittest
from unittest.mock import MagicMock, patch

from appsecctl.errors import classify, safe_message
from appsecctl import registry, inventory, manual_workflows


class EnterpriseContractTests(unittest.TestCase):
    def test_errors_never_echo_secrets(self):
        secret = "EXAMPLE-PRIVATE-TOKEN-XYZ"
        data = classify("registry unauthorized password=" + secret)
        self.assertEqual(data["code"], "REGISTRY_AUTH")
        self.assertNotIn(secret, str(data))
        self.assertNotIn(secret, safe_message("registry unauthorized " + secret))

    def test_registry_rejects_unsafe_hosts(self):
        for host in (
            "http://registry.internal", "https://admin:pass@registry.internal",
            "https://registry.internal/api", "registry.internal?token=123",
            "registry.internal/../../secret", "registry.internal:invalid",
        ):
            with self.subTest(host=host), self.assertRaises(ValueError):
                registry.normalize_host(host)
        self.assertEqual(registry.normalize_host("HTTPS://Harbor.Example.ORG:443"), "harbor.example.org:443")

    def test_comparison_counts_are_grounded(self):
        import uuid
        left, right = uuid.uuid4(), uuid.uuid4()
        rows = [
            {"scan_id": left, "vulnerability_id": "CVE-1", "pkg_name": "a", "target": "os", "severity": "HIGH", "installed_version": "1", "fixed_version": "2"},
            {"scan_id": left, "vulnerability_id": "CVE-2", "pkg_name": None, "target": "os", "severity": "MEDIUM", "installed_version": "1", "fixed_version": None},
            {"scan_id": right, "vulnerability_id": "CVE-2", "pkg_name": None, "target": "os", "severity": "MEDIUM", "installed_version": "1", "fixed_version": None},
            {"scan_id": right, "vulnerability_id": "CVE-3", "pkg_name": "b", "target": "os", "severity": "LOW", "installed_version": "1", "fixed_version": "3"},
        ]
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = rows
        result = inventory.compare(conn, str(left), str(right))
        self.assertEqual((result["fixed_count"], result["remaining_count"], result["introduced_count"]), (1, 1, 1))
        self.assertEqual(result["fixed"][0]["vulnerability_id"], "CVE-1")

    def test_manual_state_requires_publish_after_patch(self):
        item = {"decision": "approve_patch", "patch_job_status": "success", "pipeline_status": "success"}
        self.assertEqual(manual_workflows._state(item), "awaiting_publication")
        self.assertEqual(manual_workflows._state({**item, "pipeline_status": "policy_failed"}), "publication_blocked")
        self.assertEqual(manual_workflows._state({**item, "publish_decision": "approve_publish",
            "publish_job_status": "running"}), "publishing")
        self.assertEqual(manual_workflows._state({**item, "publish_decision": "approve_publish",
            "publish_job_status": "success"}), "published")
        self.assertEqual(manual_workflows._state({**item, "publish_decision": "skip_publish"}), "completed_without_publish")

    def test_last_admin_cannot_demote_self(self):
        from appsecctl import db
        conn = MagicMock()
        conn.execute.side_effect = [
            MagicMock(fetchall=lambda: [{"id": "admin-id"}]),
            MagicMock(fetchone=lambda: {
                "id": "admin-id", "role": "admin", "disabled": False,
                "username": "admin", "display_name": "Admin"
            }),
        ]
        with self.assertRaisesRegex(ValueError, "own account"):
            db.update_user_admin(conn, "admin-id", "admin-id", role="viewer")

    def test_mfa_encryption_and_replay_protection(self):
        import os
        from cryptography.fernet import Fernet
        import pyotp
        from appsecctl import mfa
        key = Fernet.generate_key().decode("ascii")
        secret = mfa.generate_secret()
        with patch.dict(os.environ, {"APPSEC_MFA_ENCRYPTION_KEY": key}):
            ciphertext = mfa.encrypt_secret(secret)
            self.assertNotEqual(ciphertext, secret)
            self.assertNotIn(secret, ciphertext)
            self.assertEqual(mfa.decrypt_secret(ciphertext), secret)
        now = 1800000000
        step = now // 30
        code = pyotp.TOTP(secret).at(now)
        self.assertEqual(mfa.totp_step(secret, code, -1, now), step)
        self.assertIsNone(mfa.totp_step(secret, code, step, now))
        self.assertIsNone(mfa.totp_step(secret, "not-a-code", -1, now))
        with patch.dict(os.environ, {"APPSEC_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")}):
            with self.assertRaises(RuntimeError):
                mfa.decrypt_secret(ciphertext)

    def test_mfa_recovery_codes_only_have_hashes_in_database(self):
        import hashlib
        import os
        import pyotp
        from cryptography.fernet import Fernet
        from appsecctl import mfa
        secret = mfa.generate_secret()
        with patch.dict(os.environ, {"APPSEC_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode("ascii")}):
            conn = MagicMock()
            conn.execute.return_value.fetchone.return_value = {"mfa_pending_enc": mfa.encrypt_secret(secret)}
            with patch.object(mfa, "totp_step", return_value=100):
                codes = mfa.confirm_enrollment(conn, "00000000-0000-0000-0000-000000000001", "012345")
            self.assertEqual(len(codes), 8)
            self.assertEqual(len(set(codes)), 8)
            self.assertTrue(all(len(c) == 12 for c in codes))
            sql_calls = [call for call in conn.execute.call_args_list if "INSERT INTO mfa_recovery_codes" in call.args[0]]
            self.assertEqual(len(sql_calls), 8)
            self.assertEqual(sql_calls[0].args[1][2], hashlib.sha256(codes[0].encode()).hexdigest())
            self.assertNotEqual(sql_calls[0].args[1][2], codes[0])


if __name__ == "__main__":
    unittest.main()
