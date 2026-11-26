import unittest
from unittest.mock import patch
from appsecctl import job_watch as watch


class WatchTests(unittest.TestCase):
    def test_never_copy_raw_output(self):
        self.assertIsNone(watch.parse_line("token=super-secret"))
        self.assertEqual(watch.parse_line("2026 INFO [debian] Detecting vulnerabilities... pkg_num=146 token=secret"),("trivy_packages",146))
        self.assertEqual(watch.parse_line("#5 DONE 0.2s"),("buildkit_step",5))
        self.assertIsNone(watch.parse_line("#5 DONE token=secret"))

    def test_scoped_fixed_event(self):
        with patch.object(watch.db,"connect") as connect:
            watch.emit("claimed")
            connect.assert_not_called()
            token=watch.CURRENT.set(("image","test-id"))
            try:
                watch.emit("unknown-secret")
                watch.emit("elapsed","secret")
                connect.assert_not_called()
                watch.emit("verified",12)
                conn=connect.return_value.__enter__.return_value
                args=conn.execute.call_args_list[0].args
                self.assertEqual(args[1],("test-id","verified","Verified scan findings: 12"))
            finally:
                watch.CURRENT.reset(token)


    def test_apt_events_do_not_expose_names_or_urls(self):
        self.assertEqual(watch.parse_line("Get:1 https://secret.example/debian trixie InRelease [12 kB]"),("apt_index",None))
        self.assertEqual(watch.parse_line("#4 0.45 Removing private-package (1.0) ..."),("apt_remove",None))
        self.assertEqual(watch.parse_line("1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."),("apt_upgrades",1))

    def test_capture_both_pipes_and_preserve_errors(self):
        import subprocess
        import sys
        with patch.object(watch,"emit") as emit:
            out=watch.capture_output([sys.executable,"-c","import sys; print('ok'); print('Get:1 https://secret.test/debian trixie InRelease',file=sys.stderr)"])
            self.assertEqual(out,"ok\n")
            emit.assert_any_call("apt_index",None)
            with self.assertRaises(subprocess.CalledProcessError) as cm:
                watch.capture_output([sys.executable,"-c","import sys; print('E: certificate failed',file=sys.stderr); sys.exit(100)"])
            self.assertIn("certificate failed",cm.exception.stderr)
            with self.assertRaisesRegex(RuntimeError,"capture limit"):
                watch.capture_output([sys.executable,"-c","print('x'*1000)"],max_bytes=100)
