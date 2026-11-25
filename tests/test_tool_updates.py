import unittest
from unittest.mock import patch
from appsecctl import tool_updates, policy
class ToolUpdateTests(unittest.TestCase):
    def test_versions(self):
        self.assertTrue(tool_updates.newer("v0.15.0", "0.14.1"))
        self.assertFalse(tool_updates.newer("0.14.1", "0.15.0"))
        self.assertFalse(tool_updates.newer("0.15.0-rc1", "0.14.1"))
    def test_versioned_refs(self):
        with patch.dict("os.environ", {"TRIVY_IMAGE":"mirror.example:5000/aquasec/trivy:latest"}):
            self.assertEqual(tool_updates.image_ref("trivy","0.76.2"),"mirror.example:5000/aquasec/trivy:0.76.2")
    def test_unknown_requires_review(self):
        self.assertEqual(policy.recommend({"unknown_count":1})[0],"not_recommended")
    def test_official_release_url(self):
        self.assertFalse(tool_updates.allowed_url("https://github.com.evil.invalid/a"))
        self.assertFalse(tool_updates.allowed_url("http://github.com/a"))

    def test_transport_diagnostics_and_retry(self):
        import socket
        import urllib.error
        from unittest.mock import MagicMock
        opener = MagicMock()
        opener.open.side_effect = urllib.error.URLError(socket.gaierror(-2,"secret internal host"))
        with patch.object(tool_updates,"release_opener",return_value=opener), patch.object(tool_updates.time,"sleep"):
            with self.assertRaisesRegex(tool_updates.ReleaseNetworkError, "api.github.com.*DNS resolution failed"):
                tool_updates.read_url("https://api.github.com/repos/test", 100)
        self.assertEqual(opener.open.call_count, 3)

    def test_cached_approved_release_avoids_second_network_request(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as d, patch.object(tool_updates,"ROOT",Path(d)), patch.object(tool_updates,"release") as network:
            item = {"tag_name":"v0.15.0","draft":False,"prerelease":False}
            tool_updates.cache_release("copa","0.15.0",item)
            self.assertEqual(tool_updates.approved_release("copa","0.15.0"),("0.15.0",item))
            network.assert_not_called()

    def test_staged_archive_digest_mismatch_is_rejected(self):
        import platform
        from tempfile import TemporaryDirectory
        from pathlib import Path
        architecture = {"x86_64":"amd64","aarch64":"arm64"}[platform.machine()]
        filename = "copa_0.15.0_linux_"+architecture+".tar.gz"
        item = {"assets":[{"name":filename,"digest":"sha256:"+"0"*64,
                 "browser_download_url":"https://github.com/project-copacetic/copacetic/releases/download/v0.15.0/"+filename}]}
        with TemporaryDirectory() as d, patch.object(tool_updates,"ROOT",Path(d)), patch.object(tool_updates,"read_url") as network:
            inbox = Path(d)/"inbox"
            inbox.mkdir()
            (inbox/filename).write_bytes(b"not a trusted archive")
            with self.assertRaisesRegex(RuntimeError,"SHA256 mismatch"):
                tool_updates.install_copa("0.15.0",item)
            network.assert_not_called()

    def test_http_rate_limit_is_not_blindly_retried(self):
        import urllib.error
        error = urllib.error.HTTPError("https://api.github.com",403,"Forbidden",{"X-RateLimit-Remaining":"0"},None)
        self.assertEqual(tool_updates.network_reason(error),("HTTP 403 (GitHub API rate limit; try a later check)",False))

    def test_staged_verified_copa_can_install_without_network(self):
        import io
        import tarfile
        import hashlib
        import platform
        from tempfile import TemporaryDirectory
        from pathlib import Path
        from unittest.mock import MagicMock
        architecture = {"x86_64":"amd64","aarch64":"arm64"}[platform.machine()]
        filename = "copa_0.15.0_linux_"+architecture+".tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w:gz") as tar:
            content = b"test fixture, never executed"
            member = tarfile.TarInfo("copa")
            member.size = len(content)
            tar.addfile(member,io.BytesIO(content))
        data = buf.getvalue()
        item = {"assets":[{"name":filename,"digest":"sha256:"+hashlib.sha256(data).hexdigest(),
                 "browser_download_url":"https://github.com/project-copacetic/copacetic/releases/download/v0.15.0/"+filename}]}
        with TemporaryDirectory() as d, patch.object(tool_updates,"ROOT",Path(d)), patch.object(tool_updates,"read_url") as network, patch.object(tool_updates,"command_version",return_value=("0.15.0","")), patch.object(tool_updates.subprocess,"run",return_value=MagicMock(stdout="--addr --timeout")):
            inbox = Path(d)/"inbox"
            inbox.mkdir()
            (inbox/filename).write_bytes(data)
            tool_updates.install_copa("0.15.0",item)
            self.assertEqual((Path(d)/"0.15.0"/"copa").read_bytes(),content)
            network.assert_not_called()
