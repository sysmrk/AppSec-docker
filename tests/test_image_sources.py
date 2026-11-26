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


    def test_priority_outermost_for_helper_alternatives_and_prefixes(self):
        sources = [{"name": "first", "host": "harbor.example/dockerhub", "priority": 1},
                   {"name": "second", "host": "mirror.example", "priority": 2}]
        refs = ["ghcr.io/project-copacetic/copacetic/debian:stable-slim", "debian:stable-slim"]
        got = image_sources.ordered_candidates(sources, refs)
        self.assertEqual([x["ref"] for x in got], [
            "harbor.example/dockerhub/project-copacetic/copacetic/debian:stable-slim",
            "harbor.example/dockerhub/library/debian:stable-slim",
            "mirror.example/project-copacetic/copacetic/debian:stable-slim",
            "mirror.example/library/debian:stable-slim",
        ])

    def test_explicit_upstream_is_not_generic_proxy(self):
        sources = [{"name": "ghcr", "host": "ghcr.io", "priority": 1}]
        self.assertEqual(image_sources.ordered_candidates(sources, ["nginx:1"]), [])
        self.assertEqual(image_sources.ordered_candidates(sources, ["ghcr.io/org/image:1"])[0]["ref"], "ghcr.io/org/image:1")

    def test_pull_stops_on_first_success(self):
        rows = [{"name": "first", "host": "mirror1.example", "priority": 1},
                {"name": "second", "host": "mirror2.example", "priority": 2},
                {"name": "third", "host": "mirror3.example", "priority": 3}]
        ordered = image_sources.ordered_candidates(rows, ["nginx:1"])
        with patch.object(image_sources.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 1, "", "403 Forbidden"),
            subprocess.CompletedProcess([], 0, "", ""),
        ]) as runner:
            self.assertEqual(image_sources.pull_ordered(ordered), "mirror2.example/library/nginx:1")
        self.assertEqual(runner.call_count, 2)

    def test_reject_credential_and_invalid_prefix(self):
        for value in ["https://user:pass@registry.example", "registry.example/../abc", "registry.example/a?key=secret"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                image_sources.normalize_endpoint(value)

    def test_database_repositories_no_unconfigured_upstream(self):
        rows = [{"name": "first", "host": "m1.example/proxy", "priority": 1},
                {"name": "second", "host": "m2.example", "priority": 2}]
        self.assertEqual(image_sources.artifact_repositories(rows, "ghcr.io/aquasecurity/trivy-db:2"),
                         "m1.example/proxy/aquasecurity/trivy-db:2,m2.example/aquasecurity/trivy-db:2")

    def test_known_docker_hub_proxies_use_aquasec_db_namespace(self):
        sources=[{"name":"arvan","host":"docker.arvancloud.ir","priority":1},
                 {"name":"ghcr","host":"ghcr.io","priority":2}]
        self.assertEqual(image_sources.artifact_repositories(sources,"ghcr.io/aquasecurity/trivy-db:2"),
                         "docker.arvancloud.ir/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2")
        self.assertEqual(image_sources.artifact_repositories(sources,"ghcr.io/aquasecurity/trivy-java-db:1"),
                         "docker.arvancloud.ir/aquasec/trivy-java-db:1,ghcr.io/aquasecurity/trivy-java-db:1")
