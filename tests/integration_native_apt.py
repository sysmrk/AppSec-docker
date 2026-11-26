"""Run actual native build on nginx with local synthetic .deb upgrades.

Only signed archive retrieval/plan generation are substituted with deterministic
fixtures. No external package downloads, no push. Real dpkg, apt check,
BuildKit, image identity, configuration, inventory, and HTTP smoke checks.
"""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4
import hashlib
import shutil
import subprocess
from appsecctl import native_apt as native, apt_optimization as apt, scan_evidence, v4_validation


def run(*args):
    subprocess.run(args,check=True,timeout=180)


def package(root,name,version,depends=None):
    pkg=root/(name+"-"+version)
    (pkg/"DEBIAN").mkdir(parents=True)
    control=f"Package: {name}\nVersion: {version}\nArchitecture: all\nMaintainer: AppSec CI <ci@example.invalid>\nDescription: offline test fixture\n"
    if depends:
        control+=f"Depends: {depends}\n"
    (pkg/"DEBIAN/control").write_text(control)
    data=pkg/"usr/share"/name
    data.mkdir(parents=True)
    (data/"version").write_text(version)
    archive=root/(name+"_"+version+"_all.deb")
    run("dpkg-deb","--build","--root-owner-group",str(pkg),str(archive))
    return archive


def main():
    tag="appsec-ci/native-base:"+uuid4().hex
    outputs=[]
    try:
        with TemporaryDirectory() as tmp:
            root=Path(tmp)
            initial=root/"initial";initial.mkdir()
            updates=root/"updates";updates.mkdir()
            package(initial,"appsec-fixture-lib","1.0-1")
            package(initial,"appsec-fixture-app","1.0-1","appsec-fixture-lib (= 1.0-1)")
            new=[package(updates,"appsec-fixture-lib","1.0-2"),
                 package(updates,"appsec-fixture-app","1.0-2","appsec-fixture-lib (= 1.0-2)")]
            # Only archive files enter the build context.
            context=root/"context";context.mkdir()
            for deb in initial.glob("*.deb"):
                shutil.copy2(deb,context/deb.name)
            (context/"Dockerfile").write_text(
                "FROM nginx:stable\n"
                "RUN --mount=type=bind,source=.,target=/tmp/fixtures,readonly dpkg --install /tmp/fixtures/*.deb && apt-get check && nginx -t\n")
            run("docker","buildx","build","--builder","default","--network=none","--pull=false","--load","-t",tag,str(context))
            original=scan_evidence.local_image_id(tag)
            rows=apt.inventory(original)
            plan={"schema":native.SCHEMA,"image_id":original,"mirror":"debian","mirror_priority":["debian"],
                  "inventory":rows,"report_sha256":"fixture-only","updates":{
                    "appsec-fixture-lib":{"before":"1.0-1","after":"1.0-2"},
                    "appsec-fixture-app":{"before":"1.0-1","after":"1.0-2"}}}
            plan["plan_sha256"]=apt.plan_digest(plan)
            def download(image,mirror,requested,dest):
                assert image==original and requested==plan["updates"]
                for deb in new:
                    shutil.copy2(deb,dest/deb.name)
                return {deb.name:hashlib.sha256(deb.read_bytes()).hexdigest() for deb in new}
            with patch.object(native,"plan",return_value=plan),patch.object(native,"download",side_effect=download):
                result=native.build(plan,{},plan["plan_sha256"],["debian"])
            outputs.append(result["candidate"])
            after=apt.inventory(result["candidate_image_id"])
            assert after["appsec-fixture-lib"]["version"]=="1.0-2"
            assert after["appsec-fixture-app"]["version"]=="1.0-2"
            assert apt.inventory(original)==rows
            assert v4_validation.matches(v4_validation.smoke(original),v4_validation.smoke(result["candidate_image_id"]))
            # An archive set with a missing approved dependency must fail before
            # installation and never return a candidate.
            def incomplete(image,mirror,requested,dest):
                shutil.copy2(new[0],dest/new[0].name)
                return {}
            with patch.object(native,"plan",return_value=plan),patch.object(native,"download",side_effect=incomplete):
                try:
                    native.build(plan,{},plan["plan_sha256"],["debian"])
                except subprocess.CalledProcessError:
                    pass
                else:
                    raise AssertionError("Incomplete approved archive set was accepted")
            print("Native upgrade regression: verified two real installed upgrades and HTTP parity; incomplete set rejected")
    finally:
        subprocess.run(["docker","image","rm",tag,*outputs],check=False,timeout=30)


if __name__=="__main__":
    main()
