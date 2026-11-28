import io
import json
import tempfile
import tarfile
import unittest
from pathlib import Path
from appsecctl import independent_scan as s

class IndependentTests(unittest.TestCase):
    def test_archive_binding(self):
        config=json.dumps({"rootfs":{"diff_ids":["sha256:"+"a"*64]}}).encode()
        expected=s.digest_bytes(config)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"image.tar"
            with tarfile.open(path,"w") as t:
                for name,data in (("manifest.json",b'[{"Config":"config.json","Layers":["layer.tar"]}]'),("config.json",config),("layer.tar",b"layer")):
                    entry=tarfile.TarInfo(name);entry.size=len(data);t.addfile(entry,io.BytesIO(data))
            proof=s.archive_identity(path,expected)
            self.assertEqual(proof["config_digest"],expected)
            self.assertEqual(s.verify_sbom({"artifacts":[{}],"source":{"metadata":{"imageID":expected}}},proof)["identity_method"],"exact_config_or_linked_manifest")
            with self.assertRaises(ValueError):
                s.archive_identity(path,"sha256:"+"f"*64)
            with self.assertRaises(ValueError):
                s.verify_sbom({"artifacts":[{}],"source":{"metadata":{"imageID":"sha256:"+"f"*64}}},proof)

    def test_comparison_does_not_merge_scanners(self):
        item={"id":"CVE-2026-1234","package":"p","type":"deb","namespace":"debian","count":1}
        base={"status":"completed","image_id":"a","matches":1,"syft_image_id":"s","grype_image_id":"g","db_files_sha256":{"db":"hash"},"package_types":{"deb":1},"occurrences":[item]}
        final={**base,"image_id":"b","matches":0,"occurrences":[]}
        result=s.compare(base,final)
        self.assertEqual(result["no_longer_reported_count"],1)
        self.assertEqual(result["introduced_count"],0)
        self.assertEqual(s.compare(base,{**final,"db_files_sha256":{"db":"changed"}})["status"],"not_comparable")

    def test_reject_ignored_matches(self):
        with self.assertRaises(ValueError):
            s.findings({"matches":[],"ignoredMatches":[{}]})

    def test_manifest_id_export_requires_association_and_equal_config(self):
        config=json.dumps({"os":"linux","architecture":"amd64","rootfs":{"diff_ids":["sha256:"+"a"*64]},"config":{"Cmd":["test"]}}).encode()
        expected="sha256:"+"b"*64
        inspected={"Id":expected,"Descriptor":{"digest":expected},"Os":"linux","Architecture":"amd64","RootFS":{"Layers":["sha256:"+"a"*64]},"Config":{"Cmd":["test"]}}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"image.tar"
            with tarfile.open(path,"w") as t:
                for name,data in (("manifest.json",b'[{"Config":"config.json","Layers":["layer.tar"]}]'),("config.json",config),("layer.tar",b"layer")):
                    entry=tarfile.TarInfo(name);entry.size=len(data);t.addfile(entry,io.BytesIO(data))
            result=s.archive_identity(path,expected,inspected)
            self.assertEqual(result["export_binding"],"daemon_export_manifest_identity_config_and_layers")
            with self.assertRaises(ValueError):
                s.archive_identity(path,expected,{**inspected,"Config":{"Cmd":["other"]}})
            with self.assertRaises(ValueError):
                s.archive_identity(path,expected,{**inspected,"Descriptor":{}})
