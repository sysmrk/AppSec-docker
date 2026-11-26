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
