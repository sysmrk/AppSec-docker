import sys
import unittest
from unittest.mock import patch
from appsecctl import job_watch


class LiveProcessTests(unittest.TestCase):
    def test_only_allowlisted_events_are_emitted(self):
        code="print('123456789abc: Download complete');print('secret=not-for-watch')"
        with patch.object(job_watch,"emit") as emit:
            result=job_watch.observed_run([sys.executable,"-c",code],timeout=10)
        self.assertEqual(result.returncode,0)
        self.assertIn("secret=not-for-watch",result.stdout)
        emit.assert_called_once_with("layer_download",None)

    def test_quiet_process_never_captures_output(self):
        result=job_watch.observed_run([sys.executable,"-c","print('secret')"],quiet=True,timeout=10)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,"",""))
