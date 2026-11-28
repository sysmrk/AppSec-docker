"""Real public EL9 DNF4 solver/download and signed offline RPM installation."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
from appsecctl import native_rpm as rpm, scan_evidence, backport_trial

# Old full images make actual upgrades likely; no substitution of archives.
FIXTURES={
    "rhel":("redhat","registry.access.redhat.com/ubi9/ubi:9.4"),
    "rocky":("rocky","rockylinux:9"),
    "almalinux":("alma","almalinux:9.3"),
    "ol":("oracle","oraclelinux:9"),
}
KEY_PREFIX={"rhel":"RPM-GPG-KEY-redhat","rocky":"RPM-GPG-KEY-Rocky","almalinux":"RPM-GPG-KEY-AlmaLinux","ol":"RPM-GPG-KEY-oracle"}

def main():
    kind=sys.argv[1]
    family,ref=FIXTURES[kind]
    subprocess.run(["docker","pull","--platform","linux/amd64",ref],check=True,timeout=180)
    image=scan_evidence.local_image_id(ref)
    before=rpm.inventory(image,kind)
    candidate=None
    container="appsec-ci-rpm-keys-"+uuid4().hex
    try:
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            keys=root/("rpm-"+kind+"-keys");keys.mkdir()
            raw=root/"raw";raw.mkdir()
            subprocess.run(["docker","create","--name",container,"--pull=never",image],check=True,timeout=60)
            subprocess.run(["docker","cp",container+":/etc/pki/rpm-gpg/.",str(raw)],check=True,timeout=60)
            hashes={}
            for p in raw.iterdir():
                if p.is_file() and p.name.lower().startswith(KEY_PREFIX[kind].lower()):
                    data=p.read_bytes()
                    (keys/p.name).write_bytes(data)
                    hashes[p.name]=hashlib.sha256(data).hexdigest()
            assert hashes,"No matching distribution fixture signing keys"
            (root/("rpm-"+kind+"-keys.json")).write_text(json.dumps({"schema":"appsec.rpm-keys/v1","distribution":kind,"major":"9","keys":hashes}))
            report={"Metadata":{"OS":{"Family":family,"Name":"9"}},"_appsec":{"image_id":image}}
            with patch.object(rpm.audit,"verified",return_value=True):
                candidate,plan=rpm.build(image,report,root)
            if not candidate:
                raise AssertionError("Fixture has no upgrades; native build not exercised: "+str(plan))
            rpm.validate_after(before,rpm.inventory(candidate["candidate_image_id"],kind),plan["updates"])
            assert rpm.inventory(image,kind)==before
            assert not candidate["publication_authorized"]
            print("Real signed offline RPM upgrades:",kind,len(plan["updates"]))
    except subprocess.CalledProcessError as exc:
        print((exc.stderr or "")[-4096:])
        raise
    finally:
        backport_trial.cleanup(candidate)
        subprocess.run(["docker","rm","-f",container],check=False,timeout=30)

if __name__=="__main__":
    main()
