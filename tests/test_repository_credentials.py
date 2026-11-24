import os
import tempfile
import unittest
import subprocess
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
from appsecctl import repo_credentials, security

class RepoCredentialTests(unittest.TestCase):
    def test_encrypted_one_job_secret(self):
        conn = MagicMock()
        with patch.dict(os.environ, {"APPSEC_MFA_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            repo_credentials.store(conn, "job", "user", "synthetic-test-token")
            token = conn.execute.call_args_list[0].args[1][1]
            self.assertNotIn("synthetic-test-token", token)
            conn.execute.return_value.fetchone.return_value = {"ciphertext":token, "valid":True}
            self.assertEqual(repo_credentials.consume(conn,"job"), ("user","synthetic-test-token"))
    def test_askpass_credentials_not_in_url_or_argv(self):
        def clone(command, **kwargs):
            self.assertNotIn("synthetic-test-token", str(command))
            env = kwargs["env"]
            self.assertEqual(subprocess.check_output([env["GIT_ASKPASS"],"Password:"],env=env,text=True).strip(),"synthetic-test-token")
            self.assertEqual(subprocess.check_output([env["GIT_ASKPASS"],"Username:"],env=env,text=True).strip(),"user")
            self.assertIn("http.sslVerify=true",command)
            self.assertIn("http.followRedirects=false",command)
            return 0
        with tempfile.TemporaryDirectory() as workspace, patch.dict(os.environ,{"WORKSPACES_DIR":workspace,"SECURITY_ALLOWED_GIT_HOSTS":"github.com"}), patch.object(security,"run_command",side_effect=clone):
            security.prepare_repo("https://github.com/example/private.git","job",("user","synthetic-test-token"))
