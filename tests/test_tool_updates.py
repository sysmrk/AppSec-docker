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
