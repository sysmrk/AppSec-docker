import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from appsecctl import native_apk as apk

class NativeAPKTests(unittest.TestCase):
    def inventory(self):
        return apk.parse_inventory("busybox\t1.36.1-r1\tx86_64\n@@WORLD\t"+"a"*64+"\n@@REPOSITORIES\t"+"b"*64+"\n")

    def test_exact_transaction(self):
        before=self.inventory()
        changes=apk.changes("(1/1) Upgrading busybox (1.36.1-r1 -> 1.36.1-r2)\nOK: 7 MiB in 16 packages\n@@COMPLETE\n",before["packages"])
        after={**before,"packages":{"busybox":{"version":"1.36.1-r2","architecture":"x86_64"}}}
        apk.validate_after(before,after,changes)
        with self.assertRaises(ValueError):
            apk.validate_after(before,{**after,"world_sha256":"c"*64},changes)
        with self.assertRaises(ValueError):
            apk.changes("(1/1) Installing extra (1.0-r0)\n@@COMPLETE\n",before["packages"])

    def test_pinned_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"alpine-keys").mkdir()
            key=root/"alpine-keys"/"test.rsa.pub"
            key.write_bytes(b"test")
            (root/"alpine-keys.json").write_text(json.dumps({"schema":"appsec.alpine-keys/v1","release":"3.22","keys":{"test.rsa.pub":hashlib.sha256(b"test").hexdigest()}}))
            self.assertEqual(apk.policy(root)[1]["test.rsa.pub"],b"test")
            key.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                apk.policy(root)

    def test_stage_exact_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            arch=root/"x86_64";arch.mkdir()
            (arch/"APKINDEX.tar.gz").write_bytes(b"index")
            (arch/"busybox-1.36.1-r2.apk").write_bytes(b"archive")
            updates={"busybox":{"before":"1.36.1-r1","after":"1.36.1-r2"}}
            self.assertEqual(len(apk.verify_stage(root,updates)),2)
            (arch/"extra.apk").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                apk.verify_stage(root,updates)

    def test_v2_fetch_name_and_frozen_index(self):
        self.assertIn('fetch --output /tmp/appsec-apk-output/x86_64 "$name"',apk.STAGE)
        self.assertNotIn('fetch --output /tmp/appsec-apk-output/x86_64 "$pin"',apk.STAGE)
        self.assertIn('test -s "/tmp/appsec-apk-output/x86_64/$name-$ver.apk"',apk.STAGE)
        self.assertIn('local-repositories',apk.STAGE)

    def test_supported_v3_releases(self):
        for release in ("3.23","3.24"):
            self.assertEqual(apk.SUPPORTED[release][0],"3")
            self.assertTrue(apk.supports({"Metadata":{"OS":{"Family":"alpine","Name":release+".0"}}}))
        self.assertFalse(apk.supports({"Metadata":{"OS":{"Family":"alpine","Name":"3.21.0"}}}))

    def test_disabled(self):
        with patch.object(apk,"enabled",return_value=False),patch.object(apk,"build") as build:
            self.assertEqual(apk.attempt("example",{})[1]["status"],"blocked")
            build.assert_not_called()
