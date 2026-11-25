import unittest
from unittest.mock import patch
from pathlib import Path

from appsecctl import remediation_lab as lab


class RemediationLabTests(unittest.TestCase):
    def test_pinned_source_and_policy(self):
        ref = "mirror.example/library/nginx@sha256:"+"a"*64
        sources = [{"host":"mirror.example"}]
        self.assertEqual(lab.validate_source(ref,"mirror.example/library/nginx:latest",sources),ref)
        for src, original, configured in [(ref,"mirror.example/library/redis:1",sources),
                                          (ref,"mirror.example/library/nginx:latest",None),
                                          ("mirror.example/library/nginx:latest","mirror.example/library/nginx:latest",sources)]:
            with self.assertRaises(RuntimeError):
                lab.validate_source(src,original,configured)

    def test_manifest_requires_exact_config_and_single_platform(self):
        expected = "sha256:"+"b"*64
        single = {"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":expected}}
        lab.verify_manifest(single,expected)
        for manifest in [dict(single,manifests=[]),dict(single,config={"digest":"sha256:"+"a"*64}),{}]:
            with self.assertRaises(RuntimeError):
                lab.verify_manifest(manifest,expected)

    def test_commands_are_fixed_and_no_push(self):
        ref = "mirror.example/library/nginx@sha256:"+"a"*64
        tag = "v3-lab-"+"b"*32
        for strategy in lab.STRATEGIES:
            cmd = lab.command_for("copa",ref,tag,strategy,Path("/tmp/report.json"),1800,"appsec-buildkit")
            self.assertEqual("--report" in cmd,strategy!="os_comprehensive")
            self.assertEqual("--pkg-types" in cmd,strategy in lab.library_remediation.TYPES)
            if strategy in lab.library_remediation.TYPES:
                self.assertEqual(cmd[cmd.index("--pkg-types")+1],"library")
            self.assertNotIn("--push",cmd)
            self.assertNotIn("--ignore-errors",cmd)
            self.assertEqual(cmd[cmd.index("-i")+1],ref)

    def test_config_comparison(self):
        original = {"Config":{"User":"1000","Cmd":["app"]}}
        self.assertEqual(lab.config_changes(original,{"Config":{"User":"root","Cmd":["app"]}}),["User"])
        self.assertEqual(lab.config_changes(original,original),[])

    def test_disabled_lab_does_not_contact_database(self):
        with patch.dict("os.environ",{"APPSEC_ENABLE_REMEDIATION_LAB":"false"}), patch.object(lab.db,"connect") as connect:
            with self.assertRaisesRegex(RuntimeError,"Lab disabled"):
                lab.run_candidate("00000000-0000-0000-0000-000000000001","image","os_comprehensive",1800)
            connect.assert_not_called()
