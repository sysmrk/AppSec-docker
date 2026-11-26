import unittest
from appsecctl import native_apt, package_versions


class NativeUpgradeTests(unittest.TestCase):
    def test_parse_exact_versions(self):
        rows={"libzstd1:amd64":{"version":"1.5.7+dfsg-1"}}
        sim="1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst libzstd1 [1.5.7+dfsg-1] (1.5.7+dfsg-1+deb13u1 Debian-Security:13/stable-security [amd64])\nConf libzstd1 (1.5.7+dfsg-1+deb13u1 Debian-Security:13/stable-security [amd64])"
        self.assertEqual(native_apt.changes(sim,rows),{"libzstd1:amd64":{"before":"1.5.7+dfsg-1","after":"1.5.7+dfsg-1+deb13u1"}})
        for bad in [sim.replace("0 to remove","1 to remove"),sim.replace("0 newly installed","1 newly installed"),
                    sim.replace("0 not upgraded","1 not upgraded"),sim.replace("1 upgraded","2 upgraded"),
                    sim.replace("[1.5.7+dfsg-1]","[wrong]")]:
            with self.assertRaises(ValueError):
                native_apt.changes(bad,rows)
        self.assertEqual(native_apt.changes("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.",rows),{})

    def test_debian_split_version(self):
        self.assertEqual(package_versions.version({"Version":"1.5.7+dfsg","Release":"1+deb13u1"},"debian"),"1.5.7+dfsg-1+deb13u1")
        self.assertEqual(package_versions.version({"Version":"2.41.5","Release":"0+deb13u1","Epoch":1},"debian"),"1:2.41.5-0+deb13u1")
        self.assertEqual(package_versions.version({"Version":"2.0","Release":"9"},"rpm"),"2.0")
