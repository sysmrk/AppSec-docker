import unittest
from unittest.mock import patch, MagicMock
from appsecctl import dependency_check as dep


def record(strategy="python_in_image", path="opt/venv/lib/python3.11/site-packages"):
    return {"schema":"appsec.remediation-lab/v1","status":"candidate_prepared","strategy":strategy,
            "candidate_image_id":"sha256:"+"a"*64,
            "library_selection":{"strategy":strategy,"selected":[{"package":"requests","path":path}]}}


class DependencyCheckTests(unittest.TestCase):
    def test_python_environment_and_isolation(self):
        image, checks=dep.checks_for(record())
        entry, workdir, args=checks[0]
        self.assertEqual(entry,"/opt/venv/bin/python3")
        cmd=dep.command(image,entry,workdir,args,"test")
        self.assertEqual(cmd[cmd.index("--network")+1],"none")
        self.assertIn("--pull=never",cmd)
        self.assertIn("--read-only",cmd)
        self.assertNotIn("/var/run/docker.sock"," ".join(cmd))
        self.assertEqual(cmd[-3:],["-m","pip","check"])

    def test_npm_scope(self):
        image, checks=dep.checks_for(record("node_in_image","app/node_modules/requests/package.json"))
        self.assertEqual(checks[0][1],"/app")
        self.assertIn("--ignore-scripts",checks[0][2])

    def test_no_compatibility_claim_or_automatic_execution(self):
        r=record()
        with patch.dict("os.environ",{"APPSEC_ENABLE_DEPENDENCY_LAB":"false"}), patch.object(dep.lab,"inspect_local") as inspect:
            with self.assertRaises(RuntimeError):
                dep.check(r)
            inspect.assert_not_called()
        with patch.dict("os.environ",{"APPSEC_ENABLE_DEPENDENCY_LAB":"true"}), patch.object(dep.lab,"inspect_local",return_value={"Id":r["candidate_image_id"]}), patch.object(dep.subprocess,"run",return_value=MagicMock(returncode=1)):
            result=dep.check(r)
            self.assertEqual(result["status"],"review_required")
            self.assertFalse(result["publication_authorized"])
            self.assertFalse(result["functional_test_passed"])
