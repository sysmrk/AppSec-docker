#!/usr/bin/env python3
"""Compare original curl finding IDs with official upstream OSV-style release ranges."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runner"))
from appsecctl import upstream_curl, benchmark

def read(path,limit):
    with path.open("rb") as stream:
        data=stream.read(limit+1)
    if len(data)>limit:
        raise ValueError("Input exceeds size limit")
    return json.loads(data),hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--research",type=Path,required=True)
    p.add_argument("--feed",type=Path,required=True,help="Official https://curl.se/docs/vuln.json snapshot")
    p.add_argument("--original-upstream",required=True)
    p.add_argument("--candidate-upstream",required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    os.umask(0o077)
    research,rh=read(a.research,64*1024*1024)
    feed,fh=read(a.feed,16*1024*1024)
    result=upstream_curl.audit(research,feed,a.original_upstream,a.candidate_upstream)
    result["provenance"]={"research_sha256":rh,"feed_sha256":fh,
        "expected_feed_url":"https://curl.se/docs/vuln.json","origin":"operator-supplied snapshot"}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    benchmark.write_json(a.output,result)
    print(json.dumps({k:v for k,v in result.items() if k not in ("findings","provenance")},indent=2))
    print(a.output)

if __name__=="__main__":
    main()
