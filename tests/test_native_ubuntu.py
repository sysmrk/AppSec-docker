import unittest
from unittest.mock import patch
from appsecctl import native_ubuntu as u

class UbuntuTrialTests(unittest.TestCase):
    def test_release_routing(self):
        self.assertTrue(u.supports({"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}}}))
        self.assertFalse(u.supports({"Metadata":{"OS":{"Family":"ubuntu","Name":"22.04"}}}))
        self.assertFalse(u.supports({"Metadata":{"OS":{"Family":"debian","Name":"24.04"}}}))

    def test_signed_isolated_source(self):
        self.assertIn("noble-security main",u.DOWNLOAD)
        self.assertIn("ubuntu-archive-keyring.gpg",u.DOWNLOAD)
        self.assertIn('APT::Get::AllowUnauthenticated "false"',u.DOWNLOAD)
        self.assertIn("apt-get -s --no-remove",u.DOWNLOAD)
        self.assertIn("apt-get download",u.DOWNLOAD)
        self.assertNotIn("trixie",u.DOWNLOAD)

    def test_disabled(self):
        with patch.object(u,"enabled",return_value=False),patch.object(u,"plan") as plan:
            self.assertEqual(u.attempt("image",{})[1]["status"],"blocked")
            plan.assert_not_called()
