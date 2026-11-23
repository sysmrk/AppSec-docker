import unittest
from unittest.mock import MagicMock, patch
import subprocess

from appsecctl import image_sources, policy


class SourcePriorityTests(unittest.TestCase):
    def test_mirror_order_and_library_prefix(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [
            {"name": "first", "host": "mirror1.example", "priority": 1},
            {"name": "second", "host": "mirror2.example", "priority": 2},
        ]
        got = image_sources.candidates(conn, "nginx:1.27-alpine")
        self.assertEqual([x["ref"] for x in got], [
            "mirror1.example/library/nginx:1.27-alpine",
            "mirror2.example/library/nginx:1.27-alpine",
        ])
        self.assertNotIn("docker.io", str(got))

    def test_no_implicit_dockerhub_when_sources_fail(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [
            {"name": "first", "host": "mirror.example", "priority": 1},
        ]
        with patch.object(image_sources.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "403 Forbidden")) as runner:
            with self.assertRaisesRegex(RuntimeError, "SOURCE_PULL_FAILED.*403"):
                image_sources.pull_image(conn, "nginx:1")
        self.assertEqual(runner.call_count, 1)
        self.assertIn("mirror.example", runner.call_args.args[0][2])

    def test_policy_advice_is_not_a_gate(self):
        self.assertEqual(policy.recommend({"critical_count": 4}, {"max_critical": 0})[0], "not_recommended")
        self.assertEqual(policy.recommend({"critical_count": 0}, {"max_critical": 0})[0], "recommended")


class NoFallbackWhenDisabled(unittest.TestCase):
    def test_all_sources_disabled_must_fail_closed(self):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = []
        conn.execute.return_value.fetchone.return_value = {"configured": True}
        with patch.object(image_sources.subprocess, "run") as runner:
            with self.assertRaisesRegex(RuntimeError, "All trusted image sources are disabled"):
                image_sources.pull_image(conn, "nginx:1")
        runner.assert_not_called()
