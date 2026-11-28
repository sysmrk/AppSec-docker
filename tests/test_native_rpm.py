import json
import unittest
from unittest.mock import patch
from appsecctl import native_rpm as r

class RPMTests(unittest.TestCase):
    def test_routing(self):
        for family,kind in r.FAMILIES.items():
            self.assertEqual(r.distro({"Metadata":{"OS":{"Family":family,"Name":"9.6"}}}),kind)
            self.assertFalse(r.supports({"Metadata":{"OS":{"Family":family,"Name":"8"}}}))
    def test_exact_closure(self):
        old=["bash","0","5.1","1.el9","x86_64"]
        new=["bash","0","5.1","2.el9","x86_64"]
        before=r.parse_inventory("\t".join(old))
        record={"before":old,"after":new,"filename":"bash-5.1-2.el9.x86_64.rpm","repo":"appsec-0"}
        updates=r.parse_plan("@@PLAN "+json.dumps([record]),before)
        r.validate_after(before,r.parse_inventory("\t".join(new)),updates)
        with self.assertRaises(ValueError): r.validate_after(before,{},updates)
        with self.assertRaises(ValueError): r.parse_plan("@@PLAN "+json.dumps([{**record,"repo":"untrusted"}]),before)
        with self.assertRaises(ValueError): r.parse_plan("@@PLAN "+json.dumps([record]),{})
    def test_disabled(self):
        with patch.object(r,"enabled",return_value=False),patch.object(r,"build") as build:
            self.assertEqual(r.attempt("image",{})[1]["status"],"blocked")
            build.assert_not_called()
