import subprocess
import unittest
from unittest.mock import patch

from appsecctl import apt_repository_review as review
from test_remediation_audit import payload


class RepositoryReviewTests(unittest.TestCase):
    def test_explicit_fallback(self):
        err=subprocess.CalledProcessError(100,["docker"],stderr="E: Failed to fetch https://example.org/deb Connection timed out\nE: Some index files failed to download.")
        with patch.object(review.apt,"availability",side_effect=[err,{"status":"repository_checked","mirror":"debian"}]) as p:
            result=review.availability("image",["tuna","debian"])
            self.assertEqual(result["mirror"],"debian")
            self.assertEqual(p.call_count,2)
        with patch.object(review.apt,"availability",side_effect=err):
            self.assertIsNone(review.availability("image",["tuna"])["counts"])

    def test_trust_error_no_fallback(self):
        err=subprocess.CalledProcessError(100,["docker"],stderr="E: Failed to fetch x Certificate verification failed")
        with patch.object(review.apt,"availability",side_effect=err) as p:
            with self.assertRaises(RuntimeError):
                review.availability("image",["tuna","debian"])
            self.assertEqual(p.call_count,1)
        self.assertFalse(review.transport_error("E: Failed to fetch x Connection timed out\nE: The repository is not signed."))

    def test_inventory_version_difference(self):
        raw=payload()["scans"][0]["raw_report"]
        image=raw["_appsec"]["image_id"]
        target=raw["Results"][0]
        target["Type"]="debian"
        target["Packages"]=[{"Name":"libzstd1","Version":"old"}]
        with patch.object(review.apt,"inspect"),patch.object(review.apt,"inventory",return_value={
            "libzstd1:amd64":{"version":"new"},"extra":{"version":"1"}}):
            result=review.reconcile(image,raw)
            self.assertEqual(result["status"],"review_required")
            self.assertEqual(result["native_only"],["extra"])
            self.assertEqual(result["version_differences"][0]["native_version"],"new")
