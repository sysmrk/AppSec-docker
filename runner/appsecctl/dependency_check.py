"""Isolated, opt-in dependency consistency checks on a local lab candidate.

The package runtime is untrusted code. Execute only in a disposable dedicated
lab, with no network, bind mounts, Docker socket, credentials or registry pull.
A zero exit code is not a functional test or proof that all dependencies are
compatible.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

from . import library_remediation as lib, remediation_lab as lab

MAX_CHECKS = 16


def checks_for(record):
    selection = record.get("library_selection")
    strategy = record.get("strategy")
    if (record.get("schema") != "appsec.remediation-lab/v1" or record.get("status") != "candidate_prepared"
            or strategy not in lib.TYPES or not isinstance(selection, dict)
            or selection.get("strategy") != strategy):
        raise ValueError("A prepared library lab candidate record is required")
    image = record.get("candidate_image_id")
    if not isinstance(image,str) or not lab.DIGEST.fullmatch(image):
        raise ValueError("Candidate image ID is invalid")
    selected = selection.get("selected")
    if not isinstance(selected,list) or not selected:
        raise ValueError("Missing selected package paths")
    checks = set()
    for item in selected:
        path, name = item["path"], item["package"]
        if not lib.clean_path(path):
            raise ValueError("Unsafe or missing candidate package path")
        path = "/" + path.lstrip("/")
        if strategy == "python_in_image":
            match = lib.PY_PATH.search(path)
            if not match:
                raise ValueError("Unsupported Python installation path")
            prefix = path[:match.start()].rstrip("/")
            interpreter = (prefix or "/usr") + "/bin/python3"
            # For ordinary virtual environments use their own interpreter;
            # do not pick the host's Python or run a shell.
            checks.add((interpreter, "/", ("-I", "-m", "pip", "check")))
        else:
            if not lib.NPM_NAME.fullmatch(name) or not path.endswith("/node_modules/"+name+"/package.json"):
                raise ValueError("Unsupported npm package path")
            workdir = path.split("/node_modules/",1)[0] or "/"
            checks.add(("/usr/local/bin/npm", workdir,
                        ("ls","--all","--offline","--ignore-scripts","--omit=dev","--json")))
    if not checks or len(checks)>MAX_CHECKS:
        raise ValueError("Unsupported number of installation environments")
    return image, sorted(checks)


def command(image, entrypoint, workdir, args, name):
    return ["docker","run","--rm","--pull=never","--name",name,
            "--network","none","--read-only","--cap-drop","ALL",
            "--security-opt","no-new-privileges=true","--user","65534:65534",
            "--pids-limit","64","--memory","512m","--cpus","1",
            "--tmpfs","/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--env","HOME=/tmp","--env","npm_config_cache=/tmp/npm-cache",
            "--workdir",workdir,"--entrypoint",entrypoint,image,*args]


def check(record, timeout=120):
    if os.getenv("APPSEC_ENABLE_DEPENDENCY_LAB") != "true":
        raise RuntimeError("Dependency lab disabled; use a disposable isolated host")
    if not 5 <= timeout <= 900:
        raise ValueError("Timeout must be 5–900 seconds")
    image, checks = checks_for(record)
    # Resolve by immutable config ID, never a mutable output tag.
    if lab.inspect_local(image)["Id"] != image:
        raise RuntimeError("Candidate image identity mismatch")
    results = []
    for entrypoint, workdir, args in checks:
        name = "appsec-dependency-check-" + uuid4().hex
        exit_code = None
        try:
            run = subprocess.run(command(image,entrypoint,workdir,args,name),
                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                 timeout=timeout,check=False)
            exit_code = run.returncode
            status = "passed" if exit_code == 0 else "runtime_or_dependency_check_failed"
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            try:
                subprocess.run(["docker","rm","-f",name],stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,timeout=30,check=False)
            except (OSError,subprocess.SubprocessError):
                print("Inspect candidate check container: "+name,file=sys.stderr)
            if sys.exc_info()[0] is KeyboardInterrupt:
                raise
            status = "timeout"
        except OSError:
            status = "executor_unavailable"
        results.append({"runtime":entrypoint,"workdir":workdir,"status":status,"exit_code":exit_code})
    return {"schema":"appsec.dependency-check/v1","candidate_image_id":image,
            "checks":results,"status":"passed" if all(r["status"]=="passed" for r in results) else "review_required",
            "scope":"offline runtime package-manager consistency only; runtime executes untrusted image code",
            "functional_test_passed":False,"publication_authorized":False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate",type=Path,required=True)
    parser.add_argument("--confirm-isolated-lab",action="store_true",required=True)
    parser.add_argument("--timeout",type=int,default=120)
    args=parser.parse_args(argv)
    try:
        with args.candidate.open(encoding="utf-8") as stream:
            result=check(json.load(stream),args.timeout)
    except (RuntimeError,ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        print("Dependency check refused or unavailable; verify candidate record and lab configuration.",file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2))
    return 0 if result["status"]=="passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
