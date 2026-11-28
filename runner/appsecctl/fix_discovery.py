"""Read-only Debian fix discovery. Never rewrite scanner evidence or authorize a patch.

Classify each original finding independently, using exact binary/source identity,
Debian source versions, a separately supplied vendor snapshot and dpkg ordering.
Missing or contradictory evidence remains unknown. Other releases are leads only.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from functools import lru_cache
import re
import subprocess
from . import scan_evidence, package_versions

RELEASES={"12":"bookworm","13":"trixie"}
NAME=re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?")
VERSION=re.compile(r"[0-9][A-Za-z0-9.+:~\-]{0,191}")
ADVISORY=re.compile(r"(?:CVE-\d{4}-\d{4,}|TEMP-[A-Za-z0-9-]+)")
NEWER={"bookworm":("trixie","forky","sid"),"trixie":("forky","sid")}


@lru_cache(maxsize=8192)
def ge(a,b):
    if not all(isinstance(x,str) and VERSION.fullmatch(x) for x in (a,b)):
        raise ValueError("Invalid Debian version")
    r=subprocess.run(["dpkg","--compare-versions",a,"ge",b],capture_output=True,timeout=10)
    if r.returncode not in (0,1):
        raise ValueError("dpkg rejected version")
    return r.returncode==0


def package_index(target):
    out=defaultdict(set)
    for p in target.get("Packages") or []:
        name,src=p.get("Name"),p.get("SrcName")
        if not isinstance(name,str) or not NAME.fullmatch(name):
            continue
        # Do not infer source package from a similarly named binary.
        sv=p.get("SrcVersion")
        if not isinstance(src,str) or not NAME.fullmatch(src) or not sv or not p.get("Version"):
            continue
        source=package_versions.version({"Version":sv,"Release":p.get("SrcRelease"),"Epoch":p.get("SrcEpoch")},"debian")
        binary=package_versions.version(p,"debian")
        if VERSION.fullmatch(source) and VERSION.fullmatch(binary):
            out[name.split(":")[0]].add((binary,src,source,p.get("Arch") or ""))
    return out


def match_source(index,name,version):
    if not isinstance(name,str) or not NAME.fullmatch(name):
        return None
    bare,_,arch=name.partition(":")
    matches={(s,sv) for bv,s,sv,a in index.get(bare,set())
             if bv==version and (not arch or arch==a)}
    return next(iter(matches)) if len(matches)==1 else None


def release_evidence(record):
    if not isinstance(record,dict):
        return {}
    return {k:record[k] for k in ("status","fixed_version","repositories","urgency","nodsa","nodsa_reason","next_point_update") if k in record}


def classify(record,release,source_version):
    if not isinstance(record,dict) or not isinstance(record.get("releases"),dict):
        return "VENDOR_RECORD_MISSING",{},{}
    releases=record["releases"]
    current=release_evidence(releases.get(release))
    other={}
    for suite in NEWER[release]:
        row=release_evidence(releases.get(suite))
        fix=row.get("fixed_version")
        if row.get("status")=="resolved" and isinstance(fix,str) and fix!="0" and VERSION.fullmatch(fix):
            other[suite]=row
    status=current.get("status")
    fixed=current.get("fixed_version")
    if status=="resolved" and fixed=="0":
        return "VENDOR_NOT_AFFECTED_REVIEW",current,other
    if status=="resolved" and isinstance(fixed,str) and VERSION.fullmatch(fixed):
        if ge(source_version,fixed):
            return "INSTALLED_AT_OR_ABOVE_VENDOR_FIX_REVIEW",current,other
        # Tracker source package version is not a verified installable binary.
        return "SAME_RELEASE_VENDOR_FIX_REPORTED",current,other
    if status=="open" and other:
        return "NEWER_RELEASE_FIX_REPORTED",current,other
    if status=="open":
        return "VENDOR_OPEN_NO_SAME_RELEASE_FIX_REPORTED",current,other
    if status=="undetermined":
        return "VENDOR_UNDETERMINED",current,other
    return "VENDOR_STATUS_UNKNOWN",current,other


def audit(report,tracker,grype=None):
    iid=(report.get("Metadata") or {}).get("ImageID")
    if not isinstance(iid,str) or not re.fullmatch(r"sha256:[a-f0-9]{64}",iid):
        raise ValueError("Missing immutable Trivy image ID")
    scan_evidence.validate_report(report,iid)
    os=(report.get("Metadata") or {}).get("OS") or {}
    release=RELEASES.get(str(os.get("Name","")).split(".")[0])
    if os.get("Family")!="debian" or not release:
        raise ValueError("Debian 12/13 only")
    targets=[t for t in report["Results"] if t.get("Class")=="os-pkgs" and t.get("Type")=="debian"]
    if len(targets)!=1:
        raise ValueError("Expected one Debian OS target")
    if not isinstance(tracker,dict) or not tracker or not any(isinstance(v,dict) and any(
            isinstance(c,dict) and isinstance(c.get("releases"),dict) for c in v.values()) for v in tracker.values()):
        raise ValueError("Invalid Debian Tracker snapshot")
    target=targets[0]
    index=package_index(target)
    rows=[]
    def add(scanner,name,version,vid,severity,fixed,scanner_status):
        row={"scanner":scanner,"package":name,"installed_binary_version":version,"id":vid,
             "severity":severity,"scanner_fixed_version":fixed,"scanner_status":scanner_status}
        mapping=match_source(index,name,version)
        if not mapping:
            row["category"]="SOURCE_IDENTITY_UNVERIFIED"
        elif not isinstance(vid,str) or not ADVISORY.fullmatch(vid):
            row["category"]="ADVISORY_ID_UNSUPPORTED"
        else:
            source,sv=mapping
            row.update(source_package=source,installed_source_version=sv,
                       vendor_url="https://security-tracker.debian.org/tracker/"+vid)
            records=tracker.get(source,{})
            entry=records.get(vid) if isinstance(records,dict) else None
            cat,current,other=classify(entry,release,sv)
            row.update(category=cat,vendor_release=current,newer_releases=other)
        rows.append(row)
    for v in target.get("Vulnerabilities") or []:
        add("trivy",v["PkgName"],v["InstalledVersion"],v["VulnerabilityID"],v.get("Severity"),
            v.get("FixedVersion") or "",v.get("Status"))
    if grype is not None:
        if not isinstance(grype.get("matches"),list):
            raise ValueError("Invalid Grype report")
        # Grype SBOM source metadata includes Docker image ID; reject missing
        # identity rather than comparing unrelated scan inputs.
        metadata=(grype.get("source") or {}).get("target") or {}
        gid=metadata.get("imageID") if isinstance(metadata,dict) else None
        if gid!=iid:
            raise ValueError("Grype source image identity not verified; use Trivy-only or bound SBOM manifest")
        for m in grype["matches"]:
            v,a=m["vulnerability"],m["artifact"]
            if a.get("type")!="deb" or v.get("namespace")!="debian:distro:debian:"+str(os["Name"]).split(".")[0]:
                continue
            fix=v.get("fix") or {}
            add("grype",a["name"],a["version"],v["id"],v.get("severity"),
                fix.get("versions") or [],fix.get("state"))
    summary={}
    for scanner in sorted({r["scanner"] for r in rows}):
        selected=[r for r in rows if r["scanner"]==scanner]
        missing=[r for r in selected if not r["scanner_fixed_version"]]
        counts=Counter(r["category"] for r in missing)
        summary[scanner]={"os_finding_occurrences":len(selected),"blank_fixed_version":len(missing),
                          "blank_fixed_version_percent":round(100*len(missing)/len(selected),2),
                          "blank_breakdown":[{"category":k,"count":v,"percent":round(100*v/len(missing),2)}
                                             for k,v in sorted(counts.items())],
                          "all_categories":dict(Counter(r["category"] for r in selected))}
    return {"schema":"appsec.fix-discovery/v1","image_id":iid,"release":release,
            "summary":summary,"findings":rows,"publication_authorized":False,
            "limitations":["Vendor snapshot is a later independent observation, not proof of what was known at scan time.",
             "Source-package fix is not a verified available or compatible binary; no packages installed.",
             "Other release versions are research leads only; never mix suites automatically.",
             "Missing records, TEMP identifiers and uncertain source identity are not no-fix conclusions.",
             "Counts are finding occurrences per scanner, not additive; no automatic suppression or VEX."]}
