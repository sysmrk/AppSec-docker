"""Conservative experimental library input preparation.

The original scanner report is never modified. Exact candidate versions come
from scanner-reported fixes; selecting a version does not establish that it
fixes all CVEs, resolves dependencies or is obtainable from a repository.
"""
from __future__ import annotations

from collections import defaultdict, Counter
from copy import deepcopy
import re

from . import remediation_audit as audit, scan_evidence

TYPES = {"python_in_image": "python-pkg", "node_in_image": "node-pkg"}
TRIPLET = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
PY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}")
PATH = re.compile(r"/?[a-zA-Z0-9_@.+-]+(?:/[a-zA-Z0-9_@.+-]+)*")
PY_PATH = re.compile(r"(?:^|/)lib/python(3\.[0-9]{1,2})/site-packages(?:/[^/]+)?$")
NODE_PATH = re.compile(r"(?:^|/)node_modules/")


def version(value):
    if not isinstance(value, str) or not TRIPLET.fullmatch(value):
        return None
    return tuple(int(x) for x in value.split("."))


def clean_path(value):
    return (isinstance(value, str) and len(value) <= 500 and PATH.fullmatch(value)
            and not any(x in (".", "..") for x in value.split("/")))


def candidate(entries, level):
    installed = {v["InstalledVersion"] for v in entries}
    if len(installed) != 1:
        return None, "multiple_installed_versions"
    current = version(next(iter(installed)))
    if current is None:
        return None, "unsupported_version_syntax"
    sets = []
    for v in entries:
        if not scan_evidence.has_fix(v):
            return None, "one_or_more_findings_without_reported_fix"
        options = {x.strip() for x in v["FixedVersion"].split(",")}
        # Do not interpret ranges, prereleases, distro revisions or PEP440
        # local versions as simple release triplets.
        if any(version(x) is None for x in options):
            return None, "unsupported_version_syntax"
        allowed = {x for x in options if version(x) > current
                   and version(x)[0] == current[0]
                   and (level == "minor" or version(x)[1] == current[1])}
        if not allowed:
            return None, "outside_version_bump_limit"
        sets.append(allowed)
    # Exact shared scanner-reported fix, not an inferred maximum of
    # lower bounds across incompatible release lines.
    common = set.intersection(*sets)
    if not common:
        return None, "no_shared_reported_fix"
    return min(common, key=version), None


def prepare(scan, strategy, level, image_config):
    if strategy not in TYPES or level not in ("patch", "minor"):
        raise ValueError("Unsupported library strategy or version bump limit")
    if not audit.verified(scan) or scan.get("phase") != "original":
        raise RuntimeError("Verified original scan required")
    raw = scan["raw_report"]
    _, inventory, _ = audit.index(raw)
    output = deepcopy(raw)
    output.pop("_appsec", None)
    output["Results"] = []
    records, helpers, skipped = [], set(), Counter()
    global_instances = defaultdict(set)
    for target in raw["Results"]:
        if target["Class"] == "lang-pkgs" and target["Type"] == TYPES[strategy]:
            for v in target.get("Vulnerabilities") or []:
                global_instances[v["PkgName"]].add((target["Target"], str(v.get("PkgPath") or ""), v["InstalledVersion"]))
    for target in raw["Results"]:
        if target["Class"] != "lang-pkgs" or target["Type"] != TYPES[strategy]:
            continue
        grouped = defaultdict(list)
        for v in target.get("Vulnerabilities") or []:
            grouped[(v["PkgName"], str(v.get("PkgPath") or ""))].append(v)
        # Refuse a package split across multiple installation locations in
        # this first lab; the planner does not yet model individual instances.
        paths = defaultdict(set)
        for name, path in grouped:
            paths[name].add(path)
        selected = []
        for (name, path), entries in sorted(grouped.items()):
            reason, helper = None, None
            versions = {v["InstalledVersion"] for v in entries}
            if (len(paths[name]) != 1 or len(global_instances[name]) != 1
                    or not versions <= inventory.get(audit.target_key(target)+(name,), set())):
                reason = "ambiguous_package_inventory"
            elif not clean_path(path):
                reason = "missing_or_unsafe_package_path"
            elif strategy == "python_in_image":
                match = PY_PATH.search(path)
                if not PY_NAME.fullmatch(name) or name.lower().replace("_","-") in ("certifi","pip","setuptools","wheel"):
                    reason = "special_or_unsupported_package"
                elif not match:
                    reason = "unsupported_python_install_layout"
                else:
                    helper = "docker.io/library/python:" + match[1] + "-slim"
            else:
                # Only ordinary top-level installed npm packages. No nested,
                # global npm internals, lockfile-only or unknown install paths.
                expected = "/node_modules/" + name + "/package.json"
                env = (image_config or {}).get("Env") or []
                nv = [x.split("=",1)[1] for x in env if isinstance(x,str) and x.startswith("NODE_VERSION=")]
                if (not NPM_NAME.fullmatch(name) or name == "npm" or
                    path.count("node_modules/") != 1 or not ("/"+path.lstrip("/")).endswith(expected)
                    or len(nv) != 1 or version(nv[0]) is None):
                    reason = "unsupported_node_install_layout_or_runtime"
                else:
                    helper = "docker.io/library/node:" + str(version(nv[0])[0]) + "-alpine"
            fix = None
            if reason is None:
                fix, reason = candidate(entries,level)
            if reason:
                skipped[reason] += len(entries)
                continue
            helpers.add(helper)
            for v in entries:
                item = deepcopy(v)
                item["FixedVersion"] = fix
                selected.append(item)
            records.append({"package":name, "path":path, "installed":next(iter(versions)),
                            "selected_reported_version":fix, "finding_count":len(entries)})
        if selected:
            item = deepcopy(target)
            item["Vulnerabilities"] = selected
            output["Results"].append(item)
    if not records:
        raise RuntimeError("No eligible library candidates under conservative rules: " +
                           ", ".join(k+"="+str(v) for k,v in sorted(skipped.items())))
    return output, {"strategy":strategy, "version_bump_limit":level, "selected":records,
                    "excluded_findings_by_reason":dict(skipped), "helper_refs":sorted(helpers),
                    "dependency_compatibility_verified":False, "package_availability_verified":False}
