import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsecctl import patch_sources


class PatchSourceTests(unittest.TestCase):
    def test_debian_helper_matches_copa(self):
        report = {"Metadata": {"OS": {"Family": "debian", "Name": "13.1"}}}
        self.assertEqual(patch_sources.helper_groups(report), [[
            "ghcr.io/project-copacetic/copacetic/debian:13-slim",
            "docker.io/library/debian:13-slim"]])
        self.assertIn("docker.io/library/debian:stable-slim",
                      patch_sources.helper_aliases(report, patch_sources.helper_groups(report)[0]))

    def test_debian_minor_uses_same_major_even_when_copa_requests_stable(self):
        report = {"Metadata": {"OS": {"Family": "debian", "Name": "12.9"}}}
        group = patch_sources.helper_groups(report)[0]
        self.assertIn("docker.io/library/debian:12-slim", group)
        self.assertNotIn("docker.io/library/debian:stable-slim", group)
        self.assertIn("docker.io/library/debian:stable-slim", patch_sources.helper_aliases(report, group))

    def test_alpine_needs_no_helper(self):
        self.assertEqual(patch_sources.helper_groups({"Metadata": {"OS": {"Family": "alpine"}}}), [])

    def test_policy_denies_unknown_and_converts_both_helper_refs(self):
        original = "ghcr.io/project-copacetic/copacetic/debian:stable-slim"
        selected = "mirror.example/library/debian:stable-slim"
        rules = patch_sources.source_policy("mirror.example/library/nginx:1", {
            original: selected, "docker.io/library/debian:stable-slim": selected})["rules"]
        self.assertEqual(rules[0]["action"], "DENY")
        self.assertEqual(rules[0]["selector"]["match_type"], "REGEX")
        conversions = [r for r in rules if r["action"] == "CONVERT"]
        self.assertEqual(len(conversions), 2)
        for rule in conversions:
            selector = rule["selector"]
            self.assertEqual(selector["match_type"], "REGEX")
            self.assertTrue(selector["identifier"].startswith("^"))
            self.assertTrue(selector["identifier"].endswith("$"))
            self.assertEqual(rule["updates"]["identifier"], "docker-image://" + selected)
        hub = next(r for r in conversions if "docker" in r["selector"]["identifier"] and "library/debian" in r["selector"]["identifier"])
        pattern = hub["selector"]["identifier"]
        self.assertEqual(re.sub(pattern, hub["updates"]["identifier"],
                                "docker-image://docker.io/library/debian:stable-slim"),
                         "docker-image://" + selected)
        for invalid in ("docker-image://dockerXio/library/debian:stable-slim",
                        "docker-image://docker.io/library/debian:stable-slim-extra",
                        "docker-image://evil.example/library/debian:stable-slim"):
            self.assertIsNone(re.search(pattern, invalid))
        self.assertEqual({r["selector"]["identifier"] for r in rules if r["action"] == "ALLOW"},
                         {"docker-image://mirror.example/library/nginx:1", "docker-image://" + selected})

    def test_policy_file_is_per_job_and_removed(self):
        report = {"Metadata": {"OS": {"Family": "debian", "Name": "13"}}}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.json"
            path.write_text(json.dumps(report))
            rows = [{"name": "mirror", "host": "mirror.example", "priority": 1}]
            with patch.object(patch_sources.db, "connect"), \
                 patch.object(patch_sources.image_sources, "configured_sources", return_value=rows), \
                 patch.object(patch_sources.image_sources, "pull_ordered", return_value="mirror.example/library/debian:13-slim"):
                with patch_sources.policy_environment("mirror.example/library/nginx:1", path) as env:
                    policy_path = Path(env["EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"])
                    self.assertTrue(policy_path.exists())
                    rules = json.loads(policy_path.read_text())["rules"]
                    self.assertIn({"action": "CONVERT", "selector": {"identifier": "^" + re.escape("docker-image://docker.io/library/debian:stable-slim") + "$", "match_type": "REGEX"},
                                   "updates": {"identifier": "docker-image://mirror.example/library/debian:13-slim"}}, rules)
                    self.assertNotIn("docker-image://docker.io/library/debian:stable-slim",
                                     {r["selector"]["identifier"] for r in rules if r["action"] == "ALLOW"})
                self.assertFalse(policy_path.exists())

    def test_no_policy_for_legacy_configuration(self):
        with patch.object(patch_sources.db, "connect"), \
             patch.object(patch_sources.image_sources, "configured_sources", return_value=None):
            with patch_sources.policy_environment("nginx:1", Path("/nonexistent")) as env:
                self.assertIsNone(env)

    def test_unapproved_target_fails_before_helper_pull(self):
        rows = [{"name": "mirror", "host": "mirror.example", "priority": 1}]
        with patch.object(patch_sources.db, "connect"), \
             patch.object(patch_sources.image_sources, "configured_sources", return_value=rows), \
             patch.object(patch_sources.image_sources, "pull_ordered") as pull:
            with self.assertRaisesRegex(RuntimeError, "no longer approved"):
                with patch_sources.policy_environment("other.example/nginx:1", Path("/nonexistent")):
                    pass
            pull.assert_not_called()
