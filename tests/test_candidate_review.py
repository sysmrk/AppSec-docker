import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from appsecctl import candidate_review as review, remediation_audit as audit
from test_remediation_audit import payload


class CandidateReviewTests(unittest.TestCase):
    def test_recompute_and_block_introductions(self):
        p=payload()
        a,b=p["scans"]
        scanner="sha256:"+"c"*64
        for s in (a,b):
            s["raw_report"]["_appsec"]["scanner_image"]=scanner
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            def write(name,data):
                (root/name).write_text(json.dumps(data))
            write("manifest.json",{"schema":"appsec.benchmark/v1","scanner_image_id":scanner,
                  "database_files_sha256":{"db/trivy.db":"d"*64},
                  "images":[{"id":s["raw_report"]["_appsec"]["image_id"],"ref":s["image_ref"]} for s in (a,b)]})
            write("original.json",a["raw_report"])
            write("candidate-1.json",b["raw_report"])
            c=audit.analyze({"scans":[a,b]},benchmark=True)
            c.update(frozen_db_content_verified=True,scanner_image_id=scanner)
            write("candidate-1-comparison.json",c)
            result=review.review(root)
            self.assertFalse(result["publication_authorized"])
            self.assertIsNone(result["preferred_for_review"])
            self.assertIn("new_findings",result["candidates"][0]["comparison_blockers"])
            c["introduced"]=0
            write("candidate-1-comparison.json",c)
            with self.assertRaisesRegex(ValueError,"differs"):
                review.review(root)
