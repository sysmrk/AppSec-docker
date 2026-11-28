import unittest
from unittest.mock import patch
from appsecctl import fleet_remediation as fleet, native_apt
from appsecctl.consolidated_report import package_inventory, fleet_section

class FleetTests(unittest.TestCase):
    def test_distro_scope(self):
        self.assertTrue(fleet.supports({"Metadata":{"OS":{"Family":"debian","Name":"13.8"}}}))
        self.assertFalse(fleet.supports({"Metadata":{"OS":{"Family":"alpine","Name":"3.22"}}}))
        self.assertFalse(fleet.supports({"Metadata":{"OS":{"Family":"debian","Name":"11"}}}))

    def test_vendor_failure_is_not_no_fix(self):
        with patch.object(fleet,"snapshot",side_effect=TimeoutError),patch.object(fleet.job_watch,"emit"):
            result=fleet.discover({"Metadata":{"OS":{"Family":"debian","Name":"13"}}})
        self.assertEqual(result["status"],"unavailable")
        self.assertNotIn("summary",result)

    def test_inventory_epoch_release(self):
        scan={"raw_report":{"Results":[{"Class":"os-pkgs","Type":"debian","Target":"test (debian 13)",
            "Packages":[{"Name":"passwd","Version":"4.17.4","Release":"2+deb13u1","Epoch":1}]}]}}
        self.assertEqual(list(package_inventory(scan).values()),[{"1:4.17.4-2+deb13u1"}])

    def test_vendor_and_plan_visible(self):
        scan={"raw_report":{"_appsec":{"fix_discovery":{"status":"completed","summary":{"trivy":{"all_categories":{"NEWER_RELEASE_FIX_REPORTED":7}}}},
            "fleet_plan":{"status":"no_updates","updates":{}}}}}
        result=fleet_section(scan,{})
        self.assertIn("NEWER_RELEASE_FIX_REPORTED",result)
        self.assertIn("no_updates",result)
        self.assertIn("not authorized for publication",result)

    def test_generic_plan_not_limited_to_nginx(self):
        image="sha256:"+"a"*64
        report={"_appsec":{"image_id":image},"Metadata":{"OS":{"Family":"debian","Name":"13"}}}
        inventory={"curl":{"version":"1.0"}}
        simulation="1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst curl [1.0] (2.0 Debian:13/stable [amd64])"
        with patch.object(native_apt.apt,"inspect",return_value={"Config":{"User":""}}),patch.object(native_apt.audit,"verified",return_value=True),patch.object(native_apt.apt,"inventory",return_value=inventory),patch.object(native_apt.repo,"availability",return_value={"status":"repository_checked","simulation":simulation,"mirror":"tuna"}),patch.object(native_apt.apt,"container"):
            result=native_apt.plan(image,report,["tuna"],generic=True)
            self.assertEqual(result["updates"],{"curl":{"before":"1.0","after":"2.0"}})
            with self.assertRaises(ValueError):
                native_apt.plan(image,report,["tuna"])
