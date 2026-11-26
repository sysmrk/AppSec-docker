import unittest
from appsecctl import manual_workflows as mw


class WorkflowControlTests(unittest.TestCase):
    def test_stop_state(self):
        self.assertEqual(mw._state({"stop_requested_at":True,"scan_job_status":"running"}),"stopping")
        self.assertEqual(mw._state({"stop_requested_at":True,"optimization_running":True}),"stopping")
        self.assertEqual(mw._state({"stop_requested_at":True,"scan_job_status":"canceled"}),"stopped")

    def test_unattended_state(self):
        self.assertEqual(mw._state({"unattended":True,"optimization_active":True}),"optimizing")
        self.assertEqual(mw._state({"unattended":True,"auto_error":"failed"}),"failed")
        self.assertEqual(mw._state({"unattended":True,"decision":"finish"}),"completed")
        self.assertEqual(mw._state({"unattended":True,"decision":"approve_patch","patch_job_status":"success","publish_decision":"skip_publish"}),"completed_without_publish")
        self.assertEqual(mw._state({"scan_job_status":"success","pipeline_status":"success","optimization_active":True}),"awaiting_approval")

    def test_invalid_route_refused_before_db(self):
        with self.assertRaises(ValueError):
            mw.create(None,"nginx",None,"user","auto_optimize",[])
        with self.assertRaises(ValueError):
            mw.create(None,"nginx",None,"user","scan_only",["nginx-module-xslt"])
