import unittest
from appsecctl import binary_discovery as b

class BinaryDiscoveryTests(unittest.TestCase):
    def fixture(self, added=True):
        inventory={"curl":{"version":"8.14.1-2"},"libcurl4t64:amd64":{"version":"8.14.1-2"}}
        out=""
        for name in inventory:
            out+="@@PACKAGE\t"+name+"\t8.14.1-2\tcurl\t8.14.1-2\t8.21.0-2~bpo13+1\n"
            out+="Package: "+name.split(":")[0]+"\nVersion: 8.21.0-2~bpo13+1\nArchitecture: amd64\nSource: curl\nSHA256: "+"a"*64+"\nSize: 100\nFilename: pool/main/c/curl/test.deb\n@@ENDPACKAGE\n"
        out+="@@SIM\tcurl\n@@EXIT 0\n"
        for name in inventory:
            out+="Inst "+name+" [8.14.1-2] (8.21.0-2~bpo13+1 Debian Backports [amd64])\n"
        if added:
            out+="Inst libngtcp2-16 (1.22.1-1~bpo13+1 Debian Backports [amd64])\n"
        out+=f"2 upgraded, {int(added)} newly installed, 0 to remove and 3 not upgraded.\n@@ENDSIM\n@@COMPLETE\n"
        findings=[{"scanner":"trivy","source_package":"curl","installed_source_version":"8.14.1-2","package":"curl","installed_binary_version":"8.14.1-2","id":"CVE-2026-1234","newer_releases":{"forky":{"fixed_version":"8.20.0-1"}}}]
        return out,inventory,findings

    def test_signed_catalog_and_dependency_addition_block(self):
        result=b.parse(*self.fixture())
        self.assertEqual(result["candidate_count"],2)
        self.assertEqual(result["threshold_lead_count"],1)
        self.assertEqual(result["automatic_selection_count"],0)
        self.assertEqual(result["simulations"]["curl"]["status"],"dependency_additions_not_authorized")

    def test_no_additions_not_security_approval(self):
        result=b.parse(*self.fixture(False))
        self.assertEqual(result["simulations"]["curl"]["status"],"existing_package_upgrades_only")
        self.assertEqual(result["automatic_selection_count"],0)

    def test_incomplete_and_ambiguous_metadata(self):
        out,inventory,findings=self.fixture()
        with self.assertRaises(ValueError):
            b.parse(out.replace("@@COMPLETE",""),inventory,findings)
        result=b.parse(out.replace("SHA256: "+"a"*64,"SHA256: invalid"),inventory,findings)
        self.assertEqual(result["candidates"][0]["status"],"binary_identity_unverified")
        self.assertEqual(result["threshold_lead_count"],0)

    def test_hold_downgrade_and_missing_pin(self):
        inventory={"curl":{"version":"2.0"}}
        line="1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst curl [2.0] (3.0 Debian Backports [amd64])"
        self.assertEqual(b.simulation(line,0,inventory,{"curl":"3.0"},{"curl"})["status"],"held_package_blocked")
        self.assertEqual(b.simulation(line.replace("(3.0","(1.0"),0,inventory,{"curl":"1.0"},set())["status"],"downgrade_or_reinstall_blocked")
        self.assertEqual(b.simulation(line,0,inventory,{"curl":"4.0"},set())["status"],"simulation_unverified")
