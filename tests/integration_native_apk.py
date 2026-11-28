"""Real official Alpine APK staging and offline build; scanner gate tested separately."""
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
from appsecctl import native_apk as apk, scan_evidence, backport_trial

def main():
    base="alpine:3.22.0"
    subprocess.run(["docker","pull","--platform","linux/amd64",base],check=True,timeout=180)
    image=scan_evidence.local_image_id(base)
    before=apk.inventory(image)
    candidate=None
    container="appsec-ci-apk-keys-"+uuid4().hex
    try:
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            keys=root/"alpine-keys";keys.mkdir()
            # CI fixture uses trust roots from the explicitly pulled official
            # base; operators must independently verify their own key policy.
            subprocess.run(["docker","create","--name",container,"--pull=never",image],check=True,timeout=60)
            subprocess.run(["docker","cp",container+":/etc/apk/keys/.",str(keys)],check=True,timeout=60)
            policy={"schema":"appsec.alpine-keys/v1","release":"3.22","keys":{
                p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in keys.iterdir()
                if p.is_file() and apk.KEY.fullmatch(p.name)}}
            assert policy["keys"],"No official APK v2 fixture keys"
            (root/"alpine-keys.json").write_text(json.dumps(policy))
            report={"Metadata":{"OS":{"Family":"alpine","Name":"3.22.0"}},"_appsec":{"image_id":image}}
            # This test is specifically the native package transaction. Original
            # scan evidence and dual scanner selection are separate boundaries.
            with patch.object(apk.audit,"verified",return_value=True):
                candidate,plan=apk.build(image,report,root)
            assert candidate and plan["updates"],plan
            assert apk.inventory(image)==before
            apk.validate_after(before,apk.inventory(candidate["candidate_image_id"]),plan["updates"])
            assert plan["signed_index_sha256"]
            assert not candidate["publication_authorized"]
            subprocess.run(["docker","run","--rm","--pull=never","--network=none",candidate["candidate_image_id"],"/bin/sh","-ec","apk --version && busybox true"],check=True,timeout=60)
            print("Real signed APK download and offline upgrade passed:",len(plan["updates"]))
    finally:
        backport_trial.cleanup(candidate)
        subprocess.run(["docker","rm","-f",container],check=False,timeout=30)

if __name__=="__main__":
    main()
