"""Read-only research of Debian CVE/list references and source-package cohorts.

Tracker NOTE links are unverified leads, not proof a commit fixes a CVE or
applies to the installed source. Never fetch or execute referenced content.
"""
from collections import Counter, defaultdict
from functools import cmp_to_key
import re
from urllib.parse import urlsplit
from .fix_discovery import ADVISORY, NAME, VERSION, ge

HEADER=re.compile(r"^((?:CVE-\d{4}-(?:\d{4,}|XXXX)|TEMP-[A-Za-z0-9-]+))\s*(?:.*)$")
URL=re.compile(r"https://[^\s<>\"']+")
COMMIT=re.compile(r"/(?:-/)?commits?/[0-9a-fA-F]{7,64}(?:[/#?]|$)")
SEVERITY=("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN")

def references(lines, wanted):
    """Stream the official text file; keep only requested advisories."""
    current=None
    out=defaultdict(list)
    for line in lines:
        if line and not line[0].isspace():
            match=HEADER.match(line)
            current=match.group(1) if match and match.group(1) in wanted else None
        elif current and line.lstrip().startswith("NOTE:"):
            note=line.strip()[5:].strip()
            # Notes may apply to several source packages or describe a
            # non-fixing commit. Preserve context; never treat as verified.
            for raw in URL.findall(note):
                url=raw.rstrip(".,;)]}")
                try:
                    parsed=urlsplit(url)
                    if not parsed.hostname or parsed.username or parsed.password:
                        continue
                except ValueError:
                    continue
                kind="commit_link" if COMMIT.search(parsed.path) or (
                    parsed.path.endswith("/commit/") and re.search(r"(?:^|&)id=[0-9a-f]{7,64}(?:&|$)",parsed.query)) else "other_reference"
                entry={"url":url,"kind":kind,"note":note,"verified":False}
                if entry not in out[current]:
                    out[current].append(entry)
    return dict(out)

def version_cmp(a,b):
    return 0 if ge(a,b) and ge(b,a) else (1 if ge(a,b) else -1)

def research(report, notes):
    if report.get("schema")!="appsec.fix-discovery/v1" or not isinstance(report.get("findings"),list):
        raise ValueError("Expected fix-discovery v1 report")
    rows=[r for r in report["findings"] if r.get("scanner")=="trivy"]
    if not rows:
        raise ValueError("No Trivy findings")
    groups=defaultdict(list)
    for row in rows:
        source=row.get("source_package")
        if source and NAME.fullmatch(source):
            groups[source].append(row)
    result=[]
    enriched=[]
    for source,items in groups.items():
        newer=[r for r in items if r["category"]=="NEWER_RELEASE_FIX_REPORTED"]
        versions=defaultdict(set)
        for r in newer:
            for suite,entry in r.get("newer_releases",{}).items():
                fix=entry.get("fixed_version")
                if isinstance(fix,str) and fix!="0" and VERSION.fullmatch(fix):
                    versions[suite].add(fix)
        severity=Counter(r.get("severity") or "UNKNOWN" for r in newer)
        source_rows=[]
        for r in items:
            links=notes.get(r["id"],[])
            source_rows.append({**r,"tracker_note_references":links,
                                "has_unverified_commit_reference":any(x["kind"]=="commit_link" for x in links)})
        enriched.extend(source_rows)
        result.append({"source_package":source,"total_findings":len(items),
                       "newer_release_findings":len(newer),
                       "newer_release_unique_advisories":len({r["id"] for r in newer}),
                       "severity":dict(severity),
                       "installed_source_versions":sorted({r["installed_source_version"] for r in items}),
                       "binary_packages":sorted({r["package"] for r in items}),
                       "categories":dict(Counter(r["category"] for r in items)),
                       "newer_release_highest_reported_fix":{s:max(v,key=cmp_to_key(version_cmp)) for s,v in versions.items()},
                       "findings_with_commit_references":sum(r["has_unverified_commit_reference"] for r in source_rows)})
    result.sort(key=lambda r:(-r["severity"].get("CRITICAL",0),-r["severity"].get("HIGH",0),
                              -r["newer_release_findings"],r["source_package"]))
    # Include unmatched identity rows in denominator, without inventing a source.
    enriched.extend({**r,"tracker_note_references":notes.get(r["id"],[]),
                     "has_unverified_commit_reference":any(x["kind"]=="commit_link" for x in notes.get(r["id"],[]))}
                    for r in rows if not r.get("source_package") or not NAME.fullmatch(r["source_package"]))
    by_category={}
    for category in sorted({r["category"] for r in enriched}):
        subset=[r for r in enriched if r["category"]==category]
        with_commit=[r for r in subset if r["has_unverified_commit_reference"]]
        by_category[category]={"findings":len(subset),"findings_with_commit_reference":len(with_commit),
                              "unique_advisories_with_commit_reference":len({r["id"] for r in with_commit})}
    return {"schema":"appsec.fix-research/v1","image_id":report["image_id"],
            "release":report["release"],"total_findings":len(rows),"source_packages":result,
            "reference_coverage_by_category":by_category,"findings":enriched,
            "publication_authorized":False,
            "limitations":["Tracker NOTE links are research leads, not verified security fixes; some refer to other releases or packages.",
             "Highest reported fix is a source-version threshold, not a binary candidate or proof all fixes are present.",
             "No signed repository index, dependency, ABI, source patch applicability or workload validation performed.",
             "No installation, image build, scanner suppression or automated upstream URL retrieval."]}
