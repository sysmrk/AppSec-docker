import unittest
from unittest.mock import Mock, patch
from appsecctl import workflow_control as wc
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

    def test_auto_patch_final_output(self):
        for destination,policy,expected in [(None,"recommended","skip_publish"),("registry.example.org/team/image:patched","recommended","approve_publish"),("registry.example.org/team/image:patched","not_recommended","skip_publish")]:
            conn=Mock()
            row={"id":"workflow","created_by":"admin","project_id":None,"execution_mode":"auto_patch","unattended":True,"mode":"continue_patch","decision":"approve_patch","auto_destination":destination}
            actor={"id":"admin","role":"admin","disabled":False}
            conn.execute.return_value.fetchone.side_effect=[row,actor]
            with patch.object(wc.mw,"get_workflow",return_value={"policy_status":policy,"pipeline_id":"pipeline"}),patch.object(wc.scan_evidence,"publication_db_fresh",return_value=True),patch.object(wc.mw,"decide") as decide,patch.object(wc.db,"insert_audit"):
                wc.advance(conn,"job")
                self.assertEqual(decide.call_args.args[3],expected)
                if expected=="approve_publish":
                    self.assertEqual(decide.call_args.kwargs,{"confirm_push":True,"destination":destination})

    def test_invalid_route_refused_before_db(self):
        with self.assertRaises(ValueError):
            mw.create(None,"nginx",None,"user","auto_optimize",[])
        with self.assertRaises(ValueError):
            mw.create(None,"nginx",None,"user","scan_only",["nginx-module-xslt"])

    def test_unattended_no_known_fixes_queues_copa(self):
        conn=Mock()
        row={"id":"workflow","created_by":"admin","project_id":None,"execution_mode":"auto_patch","unattended":True,"mode":"scan","decision":None}
        conn.execute.return_value.fetchone.side_effect=[row,{"id":"admin","role":"admin","disabled":False}]
        with patch.dict("os.environ",{"APPSEC_PATCH_ENABLED":"true"}), patch.object(wc.mw,"get_workflow",return_value={"pipeline_id":"pipeline"}), patch.object(wc.scan_evidence,"original_patch_eligibility",return_value={"eligible":False,"code":"NO_FIXABLE_OS","os_fixable":0}), patch.object(wc.mw,"decide") as decide, patch.object(wc.db,"insert_audit"):
            wc.advance(conn,"job")
            self.assertEqual(decide.call_args.args[3],"approve_patch")
