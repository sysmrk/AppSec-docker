import importlib.util
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock
from appsecctl import apt_optimization as apt, optimization, manual_workflows

SPEC=importlib.util.spec_from_file_location("v4_scanners",Path(__file__).resolve().parents[1]/"scripts/v4-scanner-compare.py")
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class PreservationTests(TestCase):
    def test_no_removal_execution(self):
        plan={"schema":apt.SCHEMA}
        plan["plan_sha256"]=apt.plan_digest(plan)
        with self.assertRaisesRegex(ValueError,"preservation policy"):
            apt.build(plan,{},plan["plan_sha256"])
        with self.assertRaisesRegex(ValueError,"preservation policy"):
            optimization.execute({"operation":"debloat"})
        with self.assertRaisesRegex(ValueError,"preservation policy"):
            optimization.create(None,None,None,"debloat","original",[])
        with self.assertRaisesRegex(ValueError,"preservation policy"):
            manual_workflows.create(None,"nginx",None,"user","auto_optimize",["nginx-module-xslt"])

    def test_grype_fixes_are_advisory(self):
        report={"matches":[{"vulnerability":{"id":"CVE-example","severity":"High","fix":{"state":"fixed","versions":["2"]}},
                             "artifact":{"name":"lib","version":"1","type":"deb"}}]}
        result=mod.findings(report)
        self.assertEqual(result["matches"],1)
        self.assertEqual(result["reported_fix_matches"][0]["fixed_versions"],["2"])
        with self.assertRaises(ValueError):
            mod.findings({})

    def test_exact_grype_delta_preserves_package_occurrences(self):
        def match(pkg):
            return {"vulnerability":{"id":"CVE-example","namespace":"debian:distro:debian:13"},
                    "artifact":{"name":pkg,"type":"deb"}}
        d=mod.match_delta({"matches":[match("a"),match("b")]},{"matches":[match("b"),match("c")]})
        self.assertEqual(d["no_longer_reported_count"],1)
        self.assertEqual(d["introduced_count"],1)
        self.assertEqual(d["no_longer_reported"][0]["package"],"a")
        self.assertEqual(d["introduced"][0]["package"],"c")
