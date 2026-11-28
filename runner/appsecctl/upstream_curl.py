"""Offline curl upstream range comparison. Research only, not Debian fix evidence."""
from collections import Counter, defaultdict
import re

SEMVER=re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
CVE=re.compile(r"CVE-\d{4}-\d{4,}")

def version(value):
    if not isinstance(value,str) or not SEMVER.fullmatch(value):
        raise ValueError("Expected numeric upstream release, not Debian package version")
    return tuple(map(int,value.split(".")))

def historical_version(value):
    # Official curl releases used X.Y before the patch component became
    # conventional (e.g. 7.7). Normalize only in the curl adapter.
    if isinstance(value,str) and re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)",value):
        value+=".0"
    return version(value)

def in_range(events,target):
    """OSV alternating introduced/fixed intervals, including reintroduction.
    Unknown event types, malformed order, or prereleases fail closed."""
    if not isinstance(events,list) or not events:
        return None
    active=False
    hit=False
    previous=None
    try:
        for event in events:
            if not isinstance(event,dict) or len(event)!=1:
                return None
            kind,value=next(iter(event.items()))
            if kind not in ("introduced","fixed","last_affected"):
                return None
            point=(0,0,0) if kind=="introduced" and value=="0" else historical_version(value)
            # curl publishes empty [introduced, fixed) intervals when
            # both events occur in the same release, e.g. CVE-2026-11856.
            # Only that specific equal-boundary pair is accepted. Other
            # equal events and descending versions remain invalid.
            if previous is not None and (point<previous or
                    (point==previous and not (active and kind=="fixed" and start==point))):
                return None
            previous=point
            if kind=="introduced":
                if active:
                    return None
                active=True
                start=point
            else:
                if not active:
                    return None
                hit |= start<=target and (target<=point if kind=="last_affected" else target<point)
                active=False
        return hit or (active and start<=target)
    except (ValueError,TypeError):
        return None

def affected(record,target):
    if record.get("withdrawn"):
        return None
    blocks=record.get("affected")
    if not isinstance(blocks,list) or not blocks:
        return None
    results=[]
    for block in blocks:
        if not isinstance(block,dict):
            return None
        ranges=block.get("ranges") or []
        sem=[r for r in ranges if isinstance(r,dict) and r.get("type")=="SEMVER"]
        if not sem:
            results.append(None)
            continue
        results.extend(in_range(r.get("events"),target) for r in sem)
        # Explicit positive versions are additional evidence; absence from
        # a list does not establish unaffected.
        if ".".join(map(str,target)) in (block.get("versions") or []):
            results.append(True)
    if True in results:
        return True
    return None if not results or None in results else False

def audit(report,feed,original,candidate):
    old,new=version(original),version(candidate)
    if new<=old:
        raise ValueError("Candidate upstream release must be newer")
    if report.get("schema")!="appsec.fix-research/v1" or not isinstance(report.get("findings"),list):
        raise ValueError("Expected fix-research v1 report")
    if not isinstance(feed,list) or not feed:
        raise ValueError("Expected official curl vulnerability JSON array")
    records=defaultdict(list)
    for item in feed:
        if not isinstance(item,dict):
            raise ValueError("Malformed curl advisory")
        if (item.get("database_specific") or {}).get("package")!="curl":
            continue
        for ident in set(item.get("aliases") or []):
            if isinstance(ident,str) and CVE.fullmatch(ident):
                records[ident].append(item)
    if not records:
        raise ValueError("No curl advisories in feed")
    rows=[r for r in report["findings"] if r.get("scanner")=="trivy" and r.get("source_package")=="curl"]
    if not rows:
        raise ValueError("No original curl findings")
    # Caller explicitly supplies upstream versions. Verify original source
    # version has the matching prefix; never infer an upstream version for
    # arbitrary Debian packaging (e.g. +really versions).
    for r in rows:
        if not re.fullmatch(re.escape(original)+r"-[A-Za-z0-9.+~]+",r["installed_source_version"]):
            raise ValueError("Original source version does not match supplied upstream release")
    def compare(ident):
        matches=records.get(ident,[])
        if len(matches)!=1:
            return {"category":"UPSTREAM_MISSING_OR_AMBIGUOUS","original_affected":None,"candidate_affected":None}
        item=matches[0]
        a,b=affected(item,old),affected(item,new)
        if a is None or b is None:
            category="UPSTREAM_RANGE_UNKNOWN"
        elif a and not b:
            category="UPSTREAM_REMEDIATION_LEAD"
        elif b and not a:
            category="UPSTREAM_NEW_EXPOSURE_LEAD"
        elif a and b:
            category="UPSTREAM_BOTH_AFFECTED"
        else:
            category="UPSTREAM_NEITHER_AFFECTED_REVIEW"
        return {"category":category,"original_affected":a,"candidate_affected":b,
                "advisory_id":item.get("id"),"modified":item.get("modified"),
                "upstream_severity":(item.get("database_specific") or {}).get("severity"),
                "url":"https://curl.se/docs/"+ident+".html"}
    result=[{**r,"upstream":compare(r["id"])} for r in rows]
    original_ids={r["id"] for r in rows}
    new_leads=[]
    unknown_leads=[]
    candidate_affected=[]
    for ident in sorted(records):
        detail=compare(ident)
        if detail["category"]=="UPSTREAM_NEW_EXPOSURE_LEAD":
            new_leads.append({"id":ident,"in_original_findings":ident in original_ids,**detail})
        if detail["original_affected"] is None or detail["candidate_affected"] is None:
            unknown_leads.append({"id":ident,"in_original_findings":ident in original_ids,**detail})
        if detail["candidate_affected"] is True:
            candidate_affected.append({"id":ident,"in_original_findings":ident in original_ids,**detail})
    return {"schema":"appsec.curl-upstream-review/v1","image_id":report["image_id"],
            "original_upstream":original,"candidate_upstream":candidate,
            "finding_count":len(rows),"unique_advisory_count":len(original_ids),
            "finding_breakdown":dict(Counter(r["upstream"]["category"] for r in result)),
            "unique_advisory_breakdown":dict(Counter(compare(i)["category"] for i in original_ids)),
            "new_upstream_exposure_leads":new_leads,"findings":result,
            "original_unresolved_advisory_ids":sorted(i for i in original_ids if
                compare(i)["category"] in ("UPSTREAM_RANGE_UNKNOWN","UPSTREAM_MISSING_OR_AMBIGUOUS")),
            "full_feed_review":{"unique_advisories":len(records),
                "unresolved_comparison_count":len(unknown_leads),
                "unresolved_original_findings_advisories":[r["id"] for r in unknown_leads if r["in_original_findings"]],
                "unresolved_advisory_ids":[r["id"] for r in unknown_leads],
                "candidate_affected_count":len(candidate_affected),
                "candidate_affected_advisory_ids":[r["id"] for r in candidate_affected]},

            "publication_authorized":False,
            "limitations":["Upstream release ranges are not Debian package or build-configuration evidence.",
              "Backported patches may change applicability in either direction; do not suppress findings.",
              "New exposure leads need binary configuration, Debian changelog and source verification.",
              "No package installed, candidate image built, or compatibility proven."]}
