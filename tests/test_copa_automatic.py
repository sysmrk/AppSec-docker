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
        with patch.object(cli,"trivy_cache_metadata",side_effect=[{},{"UpdatedAt":"old"},{"UpdatedAt":"new"}]),patch.object(cli,"trivy_db_age_hours",side_effect=[None,50,1]),patch.object(cli,"trivy_metadata_fresh",side_effect=[False,True]),patch.object(cli,"trivy_activate_stage") as activate,patch.object(cli,"trivy_stage_cleanup"),patch.object(cli,"trivy_mark_refresh"),patch.object(cli,"run_trivy_command") as run:
            cli.prepare_trivy_database("scanner","first/db:2,second/db:2")
            self.assertEqual(run.call_count,2)
            self.assertEqual(activate.call_count,2)

    def test_overdue_cache_survives_failure_and_cooldown(self):
        from subprocess import CalledProcessError
        old={"UpdatedAt":"old"}
        with patch.object(cli,"trivy_cache_metadata",return_value=old),patch.object(cli,"trivy_db_age_hours",return_value=56),patch.object(cli,"trivy_metadata_fresh",return_value=False),patch.object(cli,"trivy_refresh_recent",side_effect=[False,True]),patch.object(cli,"trivy_activate_stage") as activate,patch.object(cli,"trivy_stage_cleanup"),patch.object(cli,"trivy_mark_refresh"),patch.object(cli,"run_trivy_command",side_effect=CalledProcessError(1,["trivy"],stderr="network unavailable")) as run:
            cli.prepare_trivy_database("scanner","first/db:2")
            cli.prepare_trivy_database("scanner","first/db:2")
            self.assertEqual(run.call_count,1)
            activate.assert_not_called()

    def test_independent_sources_preserve_order(self):
        with patch.dict("os.environ",{"APPSEC_TRIVY_DB_SOURCES":"docker.arvancloud.ir/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2"}):
            self.assertEqual(cli.trivy_db_repositories([]),"docker.arvancloud.ir/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2")

    def test_rewrite_keeps_suite_and_third_party_sources(self):
        original="URIs: http://deb.debian.org/debian\nSuites: trixie\nURIs: http://deb.debian.org/debian-security\nSigned-By: /key\ndeb https://nginx.org/packages/debian trixie nginx\n"
        result=copa_mirrors.rewrite(original,"tuna")
        self.assertIn("https://mirrors.tuna.tsinghua.edu.cn/debian-security",result)
        self.assertIn("Signed-By: /key",result)
        self.assertIn("https://nginx.org/packages/debian",result)

    def test_copa_base_image_label_is_the_only_allowed_change(self):
        source="appsec-local/copa-mirror:"+"a"*32
        original={"Config":{"Labels":{"application":"nginx"}},"RootFS":{"Layers":["base"]}}
        candidate={"Config":{"Labels":{"application":"nginx","BaseImage":source}},"RootFS":{"Layers":["base","patch"]}}
        with patch.object(copa_mirrors.apt,"inspect",side_effect=[original,candidate]),patch.object(copa_mirrors.apt,"inventory",side_effect=[{"p":{"version":"1"}},{"p":{"version":"2"}}]),patch.object(copa_mirrors.apt,"container"):
            copa_mirrors.verify_candidate("original","candidate",source_ref=source)
        candidate["Config"]["Labels"]["application"]="changed"
        with patch.object(copa_mirrors.apt,"inspect",side_effect=[original,candidate]):
            with self.assertRaisesRegex(RuntimeError,"application image labels"):
                copa_mirrors.verify_candidate("original","candidate",source_ref=source)

    def test_actual_automatic_command_omits_report_when_no_fixed_version(self):
        image="sha256:"+"a"*64
        scan={"status":"success","image_ref":"example.org/nginx:1","pipeline_id":"pipeline",
              "report_path":"/reports/original.json","raw_report":{"ArtifactType":"container_image","Metadata":{"ImageID":image},"_appsec":{"verified":True,"image_id":image},"Results":[{"Target":"nginx (debian 13)","Class":"os-pkgs","Packages":[{"Name":"p","Version":"1"}],"Vulnerabilities":[]}]}}
        from appsecctl import optimization
        with patch.object(cli,"db") as database,patch.object(cli,"run_command") as command,patch.object(cli.patch_sources,"policy_environment") as policy,patch.object(cli.scan_evidence,"local_image_id",side_effect=[image,"sha256:"+"b"*64]),patch.object(optimization,"mirrors",return_value=[]),patch.object(cli.tool_updates,"copa_binary",return_value="copa"),patch.object(cli.tool_updates,"command_version",return_value=("0.14.1","test")):
            database.get_scan.return_value=scan
            policy.return_value.__enter__.return_value=None
            cli.patch_from_scan("scan",automatic=True)
        args=command.call_args.args[0]
        self.assertEqual(args[:2],["copa","patch"])
        self.assertNotIn("-r",args)
        self.assertNotIn("--report",args)
        self.assertNotIn("--ignore-errors",args)

    def test_private_staging_policy_allows_only_verified_manifest(self):
        from appsecctl import patch_sources
        ref="appsec-copa-stage:5000/appsec-local/copa-mirror:"+"a"*32
        digest="sha256:"+"b"*64
        source="mirror.example/library/nginx:1"
        rules=patch_sources.source_policy(source,{},local_source=ref,pins={ref:digest})["rules"]
        allowed={r["selector"]["identifier"] for r in rules if r["action"]=="ALLOW"}
        self.assertIn("docker-image://"+ref+"@"+digest,allowed)
        self.assertNotIn("docker-image://"+source,allowed)
        self.assertFalse(any(r["action"]=="ALLOW" and r["selector"]["match_type"]=="REGEX" for r in rules))
        with self.assertRaises(RuntimeError):
            patch_sources.source_policy(source,{},local_source=ref,pins={})
