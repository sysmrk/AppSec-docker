import unittest
from copy import deepcopy
from appsecctl import remediation_plan as plan
from test_remediation_audit import payload, finding


class RemediationPlanTests(unittest.TestCase):
    def test_groups_scope_and_hash(self):
        p = payload()
        before = deepcopy(p)
        result = plan.build(p)
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["finding_count"], 4)
        self.assertEqual(result["package_group_count"], 2)
        os = next(a for a in result["actions"] if a["package"] == "libc6")
        self.assertEqual(os["known_fix_count"], 2)
        self.assertEqual(os["preferred_strategy"], "os_targeted")
        app = next(a for a in result["actions"] if a["package"] == "requests")
        # Fixture inventory reports version 2 while the finding reports 1.
        self.assertEqual(app["preferred_strategy"], "manual_review")
        self.assertEqual(p, before)
        self.assertEqual(plan.build(p)["plan_digest"], result["plan_digest"])
        self.assertEqual(plan.page(result,0,1)["next_offset"],1)

    def test_application_and_residual_strategies(self):
        p = payload()
        p["scans"][0]["raw_report"]["Results"][1]["Packages"][0]["Version"] = "1"
        result = plan.build(p)
        app = next(a for a in result["actions"] if a["package"] == "requests")
        self.assertEqual(app["preferred_strategy"], "source_rebuild")
        self.assertIn("python_in_image", [x["strategy"] for x in app["options"]])
        self.assertEqual(plan.build(p,"residual")["status"],"planned")
        p["patches"] = []
        self.assertEqual(plan.build(p,"residual")["status"],"evidence_unavailable")

    def test_selection_is_bound_and_never_executable(self):
        result = plan.build(payload())
        action = next(a for a in result["actions"] if a["package"] == "libc6")
        selected = {"action_id":action["action_id"], "strategy":"os_comprehensive"}
        validated = plan.validate_selection(result,result["plan_digest"],[selected])
        self.assertFalse(validated["execution_authorized"])
        self.assertFalse(validated["package_compatibility_verified"])
        for digest, selection in [
            ("0"*64,[selected]), (result["plan_digest"],[dict(selected,strategy="python_in_image")]),
            (result["plan_digest"],[dict(selected,command="unexpected")]), (result["plan_digest"],[selected,selected])]:
            with self.assertRaises(ValueError):
                plan.validate_selection(result,digest,selection)

    def test_multiple_versions_require_review(self):
        p = payload()
        target = p["scans"][0]["raw_report"]["Results"][0]
        target["Vulnerabilities"].append(finding("CVE-6","libc6",version="3"))
        target["Packages"].append({"Name":"libc6","Version":"3"})
        result = plan.build(p)
        self.assertEqual(next(a for a in result["actions"] if a["package"] == "libc6")["preferred_strategy"],"manual_review")
