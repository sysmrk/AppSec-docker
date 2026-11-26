import unittest
from datetime import datetime,timezone
from unittest.mock import patch
from appsecctl import cli, scan_evidence, copa_mirrors

class AutomaticCopaTests(unittest.TestCase):
    def test_comprehensive_only_for_verified_automatic_no_fix(self):
        no={"eligible":False,"code":"NO_FIXABLE_OS"}
        self.assertEqual(scan_evidence.copa_strategy(no,automatic=True),"comprehensive")
        self.assertEqual(scan_evidence.copa_strategy(no),"targeted")
        self.assertEqual(scan_evidence.copa_strategy({"eligible":True,"code":"PATCH_CANDIDATES_AVAILABLE"},automatic=True),"targeted")
        with self.assertRaises(RuntimeError):
            scan_evidence.copa_strategy({"eligible":False,"code":"SCAN_EVIDENCE_INVALID"},automatic=True)

    def test_fresh_metadata_ignores_download_time(self):
        now=datetime(2026,11,26,20,54,tzinfo=timezone.utc)
        old={"UpdatedAt":"2026-11-24T13:06:50.432258513Z","NextUpdate":"2026-11-25T13:06:50Z","DownloadedAt":"2026-11-26T20:54:00Z"}
        self.assertFalse(cli.trivy_metadata_fresh(old,now))
        self.assertTrue(cli.trivy_metadata_fresh(dict(old,UpdatedAt="2026-11-26T13:00:00Z",NextUpdate="2026-11-27T13:00:00Z"),now))
        self.assertFalse(cli.trivy_metadata_fresh({},now))

    def test_successful_stale_download_tries_next_source(self):
        with patch.object(cli,"trivy_cache_metadata",return_value={}),patch.object(cli,"trivy_metadata_fresh",side_effect=[False,False,True]),patch.object(cli,"invalidate_trivy_metadata") as invalid,patch.object(cli,"run_trivy_command") as run:
            cli.prepare_trivy_database("scanner","first/db:2,second/db:2")
            self.assertEqual(run.call_count,2)
            self.assertEqual(invalid.call_count,2)

    def test_rewrite_keeps_suite_and_third_party_sources(self):
        original="URIs: http://deb.debian.org/debian\nSuites: trixie\nURIs: http://deb.debian.org/debian-security\nSigned-By: /key\ndeb https://nginx.org/packages/debian trixie nginx\n"
        result=copa_mirrors.rewrite(original,"tuna")
        self.assertIn("https://mirrors.tuna.tsinghua.edu.cn/debian-security",result)
        self.assertIn("Signed-By: /key",result)
        self.assertIn("https://nginx.org/packages/debian",result)
