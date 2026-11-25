import unittest
from unittest.mock import patch
from appsecctl import apt_optimization as apt
from test_remediation_audit import payload


class AptOptimizationTests(unittest.TestCase):
    def test_parse_and_reject_mutations(self):
        rows={"libgd3:amd64":{},"nginx-module-image-filter":{}}
        good="0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\nPurg libgd3\nPurg nginx-module-image-filter\n"
        self.assertEqual(apt.parse_simulation(good,rows),sorted(rows))
        for bad in [good+"Inst libc6\n",good.replace("2 to remove","3 to remove"),good+"Purg apt\n"]:
            with self.assertRaises(ValueError):
                apt.parse_simulation(bad,rows)

    def test_dockerfile_is_offline_and_checks_closure(self):
        value=apt.dockerfile(["nginx-module-image-filter"],["libgd3:amd64","nginx-module-image-filter"])
        self.assertIn("libgd3 nginx-module-image-filter",value)
        self.assertIn("nginx -t",value)
        self.assertNotIn("apt-get update",value)
        with self.assertRaises(ValueError):
            apt.dockerfile(["nginx;whoami"],["nginx"])

    def test_digest_binds_approved_plan(self):
        p={"schema":apt.SCHEMA,"remove":["libgd3"]}
        p["plan_sha256"]=apt.plan_digest(p)
        self.assertEqual(p["plan_sha256"],apt.plan_digest(p))
        p["remove"].append("libc6")
        with self.assertRaisesRegex(ValueError,"digest"):
            apt.build(p,{},p["plan_sha256"])

    def test_protected_package_refused(self):
        report=payload()["scans"][0]["raw_report"]
        image=report["_appsec"]["image_id"]
        report["Metadata"]["OS"]={"Family":"debian","Name":"13.8"}
        rows={p:{"version":"1","essential":p=="libc6","protected":False,"priority":"optional"}
              for p in ("nginx","nginx-module-image-filter","libc6")}
        with patch.object(apt,"inspect"),patch.object(apt,"inventory",return_value=rows),patch.object(apt,"container",side_effect=["nginx\nnginx-module-image-filter\n","0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\nPurg nginx-module-image-filter\nPurg libc6\n"]):
            with self.assertRaisesRegex(ValueError,"Protected"):
                apt.plan_removal(image,["nginx-module-image-filter"],report)
