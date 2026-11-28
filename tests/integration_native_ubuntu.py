"""Real signed Ubuntu Noble archive staging, offline install and inventory."""
import subprocess
from unittest.mock import patch
from appsecctl import native_ubuntu as ubuntu, apt_optimization as apt, scan_evidence, backport_trial

def main():
    ref="ubuntu:noble-20240429"
    subprocess.run(["docker","pull","--platform","linux/amd64",ref],check=True,timeout=180)
    image=scan_evidence.local_image_id(ref)
    before=apt.inventory(image)
    report={"Metadata":{"OS":{"Family":"ubuntu","Name":"24.04"}},"_appsec":{"image_id":image}}
    candidate=None
    try:
        with patch.object(ubuntu.audit,"verified",return_value=True):
            plan=ubuntu.plan(image,report)
        assert plan["updates"],"Old Noble fixture must have upgrades"
        candidate=ubuntu.build(plan)
        after=apt.inventory(candidate["candidate_image_id"])
        assert apt.inventory(image)==before
        assert all(after[n]["version"]==v["after"] for n,v in plan["updates"].items())
        assert not candidate["publication_authorized"]
        print("Real Ubuntu signed offline upgrades:",len(plan["updates"]))
    except subprocess.CalledProcessError as exc:
        print((exc.stderr or "")[-4096:])
        raise
    finally:
        backport_trial.cleanup(candidate)

if __name__=="__main__":
    main()
