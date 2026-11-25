import unittest
from copy import deepcopy
from appsecctl import library_remediation as lib
from test_remediation_audit import payload


class LibraryTests(unittest.TestCase):
    def fixture(self):
        scan = payload()["scans"][0]
        target = scan["raw_report"]["Results"][1]
        target["Type"] = "python-pkg"
        target["Packages"] = [{"Name":"requests","Version":"2.28.0"}]
        target["Vulnerabilities"] = [{"PkgName":"requests","InstalledVersion":"2.28.0",
             "FixedVersion":"2.28.2","VulnerabilityID":"CVE-X","Severity":"HIGH",
             "PkgPath":"opt/venv/lib/python3.11/site-packages"}]
        return scan

    def test_scope_and_no_mutation(self):
        scan = self.fixture()
        before = deepcopy(scan)
        report, result = lib.prepare(scan,"python_in_image","patch",{})
        self.assertEqual(scan,before)
        self.assertEqual(len(report["Results"]),1)
        self.assertEqual(report["Results"][0]["Class"],"lang-pkgs")
        self.assertEqual(result["helper_refs"],["docker.io/library/python:3.11-slim"])
        self.assertFalse(result["dependency_compatibility_verified"])

    def test_no_invented_or_major_fix(self):
        scan = self.fixture()
        v = scan["raw_report"]["Results"][1]["Vulnerabilities"][0]
        v["FixedVersion"] = "3.0.0"
        with self.assertRaisesRegex(RuntimeError,"outside_version_bump_limit"):
            lib.prepare(scan,"python_in_image","minor",{})
        v["FixedVersion"] = "2.29.0"
        with self.assertRaisesRegex(RuntimeError,"outside_version_bump_limit"):
            lib.prepare(scan,"python_in_image","patch",{})
        self.assertEqual(lib.prepare(scan,"python_in_image","minor",{})[1]["selected"][0]["selected_reported_version"],"2.29.0")

    def test_conflicting_reported_fixes_and_unsafe_path(self):
        scan = self.fixture()
        target = scan["raw_report"]["Results"][1]
        target["Vulnerabilities"].append(dict(target["Vulnerabilities"][0],FixedVersion="2.28.3",VulnerabilityID="CVE-Y"))
        with self.assertRaisesRegex(RuntimeError,"no_shared_reported_fix"):
            lib.prepare(scan,"python_in_image","patch",{})
        target["Vulnerabilities"].pop()
        target["Vulnerabilities"][0]["PkgPath"] = "opt/../lib/python3.11/site-packages"
        with self.assertRaisesRegex(RuntimeError,"unsafe_package_path"):
            lib.prepare(scan,"python_in_image","patch",{})

    def test_node_requires_runtime_and_installed_path(self):
        scan = self.fixture()
        target = scan["raw_report"]["Results"][1]
        target["Type"] = "node-pkg"
        target["Vulnerabilities"][0]["PkgPath"] = "app/node_modules/requests/package.json"
        with self.assertRaisesRegex(RuntimeError,"runtime"):
            lib.prepare(scan,"node_in_image","patch",{})
        result = lib.prepare(scan,"node_in_image","patch",{"Env":["NODE_VERSION=22.12.0"]})[1]
        self.assertEqual(result["helper_refs"],["docker.io/library/node:22-alpine"])
