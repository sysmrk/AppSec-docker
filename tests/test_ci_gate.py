import unittest
from unittest.mock import patch

from appsecctl import cli


class CiGateTests(unittest.TestCase):
    def _run(self, status, high, limit):
        with patch.object(cli, "run_security_job", return_value="00000000-0000-0000-0000-000000000000"), \
             patch.object(cli.db, "connect") as connect, \
             patch.object(cli.db, "security_job_detail", return_value={"job": {"status": status, "high_count": high}}), \
             patch.object(cli, "write_security_sarif"), \
             patch.dict("os.environ", {"CI_MAX_HIGH": str(limit)}):
            connect.return_value.__enter__.return_value = object()
            return cli.ci_security("secrets", "https://github.com/org/repo", "quick")

    def test_image_gate_uses_verified_findings_not_execution_status(self):
        scan = {"id":"scan", "phase":"original", "status":"success", "critical_count":1,
                "raw_report":{"_appsec":{"verified":True,"image_id":"sha256:test"}}}
        summary = {"pipeline":{"status":"success"},"scans":[scan]}
        with patch.object(cli,"run_pipeline",return_value="pipeline"), patch.object(cli.db,"connect"), \
             patch.object(cli.db,"pipeline_summary",return_value=summary), patch.object(cli,"write_pipeline_report_if_ready"), \
             patch.dict("os.environ",{"POLICY_MAX_CRITICAL":"0","POLICY_MAX_HIGH":"0","POLICY_MAX_UNKNOWN":"0"}):
            self.assertEqual(cli.ci_image("nginx:latest"),1)
            scan["critical_count"] = 0
            self.assertEqual(cli.ci_image("nginx:latest"),0)
            scan["raw_report"] = {}
            self.assertEqual(cli.ci_image("nginx:latest"),1)

    def test_failure_status_fails_closed(self):
        self.assertEqual(self._run("failed", 0, 0), 1)

    def test_threshold_exceeded(self):
        self.assertEqual(self._run("success", 2, 1), 1)

    def test_success_under_threshold(self):
        self.assertEqual(self._run("success", 1, 1), 0)


if __name__ == "__main__":
    unittest.main()
