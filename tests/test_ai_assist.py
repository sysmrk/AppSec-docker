import json
import unittest
from unittest.mock import MagicMock, patch
from appsecctl import ai_assist as ai, remediation_plan as planner
from test_remediation_audit import payload


class LocalAIContractTests(unittest.TestCase):
    def test_minimized_context_and_typed_response(self):
        plan=planner.build(payload())
        context=ai.model_context(plan,0,1)
        self.assertNotIn("image_id",json.dumps(context))
        self.assertNotIn("target",context["actions"][0])
        action=context["actions"][0]
        selection={"action_id":action["action_id"],"strategy":action["preferred_strategy"],"reason_code":"minimize_changes"}
        result=ai.validate_model(plan,context,{"selections":[selection]})
        self.assertEqual(result[0]["reason_code"],"minimize_changes")
        for bad in [dict(selection,command="run anything"),dict(selection,action_id="0"*64),
                    dict(selection,strategy="arbitrary_shell"),dict(selection,reason_code="invented")]:
            with self.assertRaises(ValueError):
                ai.validate_model(plan,context,{"selections":[bad]})
        with self.assertRaises(ValueError):
            ai.validate_model(plan,context,{"selections":[selection,selection]})

    def test_fixed_loopback_and_no_execution(self):
        opener=MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value=json.dumps({"message":{"content":"{\"selections\":[]}"}}).encode()
        with patch.object(ai.urllib.request,"build_opener",return_value=opener):
            result=ai.assist(payload(),"local-model:1")
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["package_compatibility_verified"])
        request=opener.open.call_args.args[0]
        self.assertEqual(request.full_url,"http://127.0.0.1:11434/api/chat")
        self.assertIsNone(request.get_header("Authorization"))
