#!/usr/bin/env python3
"""Prioritize source packages and extract upstream reference leads from Debian CVE/list."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runner"))
from appsecctl import fix_research, benchmark

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--discovery",type=Path,required=True)
    p.add_argument("--cve-list",type=Path,required=True,help="Official Debian security-tracker data/CVE/list snapshot")
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    os.umask(0o077)
    if a.discovery.stat().st_size>64*1024*1024 or a.cve_list.stat().st_size>128*1024*1024:
        p.error("Evidence exceeds size limit")
    raw=a.discovery.read_bytes()
    discovery=json.loads(raw)
    with a.cve_list.open("rb") as stream:
        digest=benchmark.hash_stream(stream)
    with a.cve_list.open(encoding="utf-8") as stream:
        refs=fix_research.references(stream,{r["id"] for r in discovery["findings"]})
    with a.cve_list.open("rb") as stream:
        if benchmark.hash_stream(stream)!=digest:
            raise RuntimeError("CVE list changed during analysis")
    result=fix_research.research(discovery,refs)
    result["provenance"]={"discovery_sha256":hashlib.sha256(raw).hexdigest(),"cve_list_sha256":digest,
                          "origin":"operator-provided snapshot; not authenticated by offline script"}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    benchmark.write_json(a.output,result)
    print(json.dumps({"total_findings":result["total_findings"],
                     "reference_coverage_by_category":result["reference_coverage_by_category"],
                     "prioritized_source_packages":[r for r in result["source_packages"] if r["newer_release_findings"]][:12]},indent=2))
    print(a.output)

if __name__=="__main__":
    main()
