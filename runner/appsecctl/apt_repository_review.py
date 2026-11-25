"""Explicit mirror priority and native inventory comparison for the P0 lab."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import apt_optimization as apt, remediation_audit as audit


def transport_error(stderr):
    lower=(stderr or "").lower()
    fatal=("signature","not signed","no_pubkey","expkeysig","badsig","certificate",
           "tls","expired","not valid","hash sum mismatch","release file",
           "clearsigned","403 forbidden","404 not found","401 unauthorized")
    if any(x in lower for x in fatal):
        return False
    errors=[line for line in lower.splitlines() if line.startswith("e:")]
    failed=[line for line in errors if "failed to fetch" in line]
    allowed=("connection timed out","connection refused","temporary failure resolving",
             "could not resolve","network is unreachable","could not connect")
    return bool(failed) and all(any(x in line for x in allowed) for line in failed) and all(
        "failed to fetch" in line or "some index files failed to download" in line for line in errors)


def availability(image, mirrors):
    if not mirrors or len(mirrors)!=len(set(mirrors)) or any(m not in apt.MIRRORS for m in mirrors):
        raise ValueError("Use a unique explicitly approved mirror priority list")
    attempts=[]
    for mirror in mirrors:
        try:
            result=apt.availability(image,mirror)
        except subprocess.CalledProcessError as exc:
            if not transport_error(exc.stderr):
                raise RuntimeError("APT probe failed; unknown or trust error; fallback refused") from None
            attempts.append({"mirror":mirror,"status":"transport_unavailable"})
            continue
        attempts.append({"mirror":mirror,"status":"repository_checked"})
        return {**result,"mirror_priority":list(mirrors),"attempts":attempts}
    return {"schema":"appsec.apt-availability/v1","status":"repositories_unavailable",
            "image_id":image,"mirror_priority":list(mirrors),"attempts":attempts,
            "counts":None,"publication_authorized":False}


def reconcile(image,report):
    apt.inspect(image)
    if not audit.verified({"status":"success","raw_report":report}) or report["_appsec"]["image_id"]!=image:
        raise ValueError("Verified raw scan of the exact image required")
    native=apt.inventory(image)
    targets=[t for t in report["Results"] if t["Class"]=="os-pkgs"]
    if len(targets)!=1 or targets[0]["Type"]!="debian":
        raise ValueError("Single Debian package target required")
    scanned={}
    for p in targets[0].get("Packages") or []:
        name,version=p.get("Name"),p.get("Version")
        if not isinstance(name,str) or not apt.PKG.fullmatch(name) or not isinstance(version,str) or not version:
            raise ValueError("Malformed scanner inventory")
        scanned.setdefault(name,set()).add(version)
    if not scanned:
        raise ValueError("Empty scanner inventory")
    matched=set()
    missing=[]
    ambiguous=[]
    differences=[]
    for name,versions in sorted(scanned.items()):
        try:
            actual=apt.resolve(name,native)
        except ValueError:
            if any(p.split(":")[0]==name.split(":")[0] for p in native):
                ambiguous.append(name)
            else:
                missing.append(name)
            continue
        matched.add(actual)
        if versions!={native[actual]["version"]}:
            differences.append({"package":actual,"native_version":native[actual]["version"],
                                "scanner_versions":sorted(versions)})
    finding_diffs=set()
    for v in targets[0].get("Vulnerabilities") or []:
        try:
            actual=apt.resolve(v["PkgName"],native)
            version=native[actual]["version"]
        except ValueError:
            version="unmatched"
        if v["InstalledVersion"]!=version:
            finding_diffs.add((v["PkgName"],v["InstalledVersion"],version))
    native_only=sorted(set(native)-matched)
    return {"schema":"appsec.apt-inventory-reconciliation/v1","image_id":image,
            "native_package_count":len(native),"scanner_package_names":len(scanned),
            "scanner_package_records":len(targets[0]["Packages"]),
            "native_only":native_only,"scanner_only":missing,"ambiguous_names":ambiguous,
            "version_differences":differences,"finding_version_differences":[
                {"package":n,"scanner_version":s,"native_version":a} for n,s,a in sorted(finding_diffs)],
            "libzstd1_native":{p:v["version"] for p,v in native.items() if p.split(":")[0]=="libzstd1"},
            "libzstd1_scanner":{p:sorted(v) for p,v in scanned.items() if p.split(":")[0]=="libzstd1"},
            "status":"review_required" if native_only or missing or ambiguous or differences or finding_diffs else "matched",
            "publication_authorized":False}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    a=sub.add_parser("availability")
    a.add_argument("--mirror",choices=sorted(apt.MIRRORS),action="append",required=True)
    b=sub.add_parser("inventory")
    b.add_argument("--report",type=Path,required=True)
    for parser in (a,b):
        parser.add_argument("--image",required=True)
        parser.add_argument("--confirm-isolated-lab",action="store_true",required=True)
    args=p.parse_args(argv)
    try:
        result=availability(args.image,args.mirror) if args.command=="availability" else reconcile(
            args.image,json.loads(args.report.read_text(encoding="utf-8")))
    except (RuntimeError,ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print("APT_REVIEW_FAILED: "+str(exc)[:500],file=sys.stderr)
        return 1
    print(json.dumps(result,indent=2))
    return 1 if result["status"]=="repositories_unavailable" else 0


if __name__=="__main__":
    raise SystemExit(main())
