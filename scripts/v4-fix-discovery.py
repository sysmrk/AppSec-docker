#!/usr/bin/env python3
"""Analyze existing raw Trivy evidence against an official Debian Tracker snapshot.
No Docker, image download, scanner DB copy, package modification or network call.
"""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runner"))
from appsecctl import fix_discovery

def load(path,limit):
    with path.open("rb") as stream:
        data=stream.read(limit+1)
    if len(data)>limit:
        raise ValueError("Input exceeds size limit: "+path.name)
    return json.loads(data),hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--trivy-report",type=Path,required=True)
    p.add_argument("--tracker",type=Path,required=True,help="JSON from https://security-tracker.debian.org/tracker/data/json")
    p.add_argument("--grype-report",type=Path,help="Optional Grype JSON with matching source image identity")
    p.add_argument("--output",type=Path,required=True,help="New private report JSON; never overwritten")
    a=p.parse_args()
    os.umask(0o077)
    trivy,th=load(a.trivy_report,64*1024*1024)
    tracker,dh=load(a.tracker,128*1024*1024)
    grype,gh=load(a.grype_report,64*1024*1024) if a.grype_report else (None,None)
    result=fix_discovery.audit(trivy,tracker,grype)
    result["provenance"]={"trivy_sha256":th,"grype_sha256":gh,"tracker_sha256":dh,
                          "tracker_expected_source":"https://security-tracker.debian.org/tracker/data/json",
                          "snapshot_origin":"operator-supplied; not authenticated by this offline script",
                          "analyzed_at":datetime.now(timezone.utc).isoformat()}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,ensure_ascii=True)
    print(json.dumps(result["summary"],indent=2))
    print(a.output)

if __name__=="__main__":
    main()
