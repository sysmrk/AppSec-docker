"""Per-job Copa source policy for approved runtime registries.

Copa v0.14.1 accepts EXPERIMENTAL_BUILDKIT_SOURCE_POLICY. Resolve the known
OS helper before invoking Copa; never silently use an unapproved helper.
This controls LLB sources, not network egress, BuildKit daemon mirrors or
package-manager traffic. Unknown helper references are denied.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

from . import db, image_sources

COPA = "ghcr.io/project-copacetic/copacetic/"


def helper_groups(report: dict) -> list[list[str]]:
    os_info = (report.get("Metadata") or {}).get("OS") or {}
    family = str(os_info.get("Family") or "").lower()
    version = str(os_info.get("Name") or "")
    if family == "alpine":
        return []
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version):
        raise RuntimeError("PATCH_SOURCE_POLICY: Cannot determine a supported OS version from the Trivy report")
    major = version.split(".")[0]
    if family == "debian":
        # Copa v0.14.1 compares the full version lexically and can request
        # stable-slim even for Debian 12.x. Never pull a moving stable tag
        # for a known Debian release; resolve the same major tooling image.
        tag = major + "-slim"
        return [[COPA + "debian:" + tag, "docker.io/library/debian:" + tag]]
    if family == "ubuntu":
        return [[COPA + "ubuntu:" + version, "docker.io/library/ubuntu:" + version]]
    if family in ("redhat", "rhel", "centos", "rocky", "rockylinux", "alma", "almalinux", "amazon", "oracle", "oraclelinux", "azurelinux", "cbl-mariner", "mariner"):
        if family == "azurelinux":
            suffix = "azurelinux/base/core:" + ("3.0" if "3.0" in version else version)
        elif family in ("cbl-mariner", "mariner"):
            suffix = "cbl-mariner/base/core:" + ".".join((version.split(".") + ["0"])[:2])
        else:
            suffix = "cbl-mariner/base/core:2.0"
        return [[COPA + suffix, "mcr.microsoft.com/" + suffix]]
    raise RuntimeError("PATCH_SOURCE_POLICY: No approved automatic helper mapping for OS family " + family[:40])


def helper_aliases(report: dict, group: list[str]) -> list[str]:
    """Cover Copa's original and fallback Debian identifiers for this OS."""
    os_info = (report.get("Metadata") or {}).get("OS") or {}
    if str(os_info.get("Family") or "").lower() == "debian":
        return list(dict.fromkeys(group + [COPA + "debian:stable-slim", "docker.io/library/debian:stable-slim"]))
    return group


def source_policy(source: str, mappings: dict[str, str], *, local_source=None) -> dict:
    canonical_source = image_sources.canonical_ref(source)
    # Copa v0.14.1 expects the first rule to have an updates object.
    # Retain the default-deny rule first; BuildKit re-evaluates a converted
    # source against the entire policy and the final repository/tag-scoped allowlist.
    rules = [{"action": "DENY", "selector": {"identifier": "^docker-image://.*$", "match_type": "REGEX"},
              "updates": {"identifier": ""}}]
    permitted = {canonical_source}
    if local_source:
        if not re.fullmatch(r"appsec-local/copa-mirror:[0-9a-f]{32}",local_source):
            raise RuntimeError("PATCH_SOURCE_POLICY: Invalid local preparation reference")
        permitted.add(image_sources.canonical_ref(local_source))
    for original, selected in mappings.items():
        original = image_sources.canonical_ref(original)
        selected = image_sources.canonical_ref(selected)
        permitted.add(selected)
        # A helper alias cannot override the explicitly approved target.
        if original != selected and original != canonical_source:
            # BuildKit v0.29.0 selectorCache.Format returns the original
            # selector for EXACT, making CONVERT a no-op. Anchored, escaped
            # REGEX matches exactly one source and expands the destination.
            pattern = "^" + re.escape("docker-image://" + original) + "$"
            rules.append({"action": "CONVERT", "selector": {"identifier": pattern, "match_type": "REGEX"},
                          "updates": {"identifier": "docker-image://" + selected}})
    for reference in sorted(permitted):
        identifier = "docker-image://" + reference
        rules.append({"action": "ALLOW", "selector": {"identifier": identifier, "match_type": "EXACT"}})
        # The Dockerfile frontend resolves a tag into tag@sha256:digest
        # before loading the LLB. Permit that form only for the very same
        # approved registry, repository and tag. An already pinned input
        # stays exact; never append a second digest or allow another tag.
        # This is a source allowlist, not a cryptographic digest pin.
        if "@" not in reference:
            resolved = "^" + re.escape(identifier) + "@sha256:[0-9a-f]{64}$"
            rules.append({"action": "ALLOW", "selector": {"identifier": resolved, "match_type": "REGEX"}})
    return {"version": 1, "rules": rules}


@contextmanager
def policy_environment(source: str, report_path: Path, *, extra_groups=(), local_source=None, local_mirror=None):
    with db.connect() as conn:
        sources = image_sources.configured_sources(conn)
    if sources is None:
        if local_source:
            raise RuntimeError("PATCH_SOURCE_POLICY: Configure approved image sources before local mirror preparation")
        yield None
        return
    if not sources:
        raise RuntimeError("SOURCE_PULL_FAILED: All trusted image sources are disabled")
    canonical = image_sources.canonical_ref(source)
    if not any(canonical.startswith(image_sources.normalize_endpoint(row["host"]) + "/") for row in sources):
        raise RuntimeError("PATCH_SOURCE_POLICY: Previously scanned source is no longer approved; create a new scan")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    mappings = {}
    groups = [(group, helper_aliases(report, group)) for group in helper_groups(report)]
    # Explicit language helpers are exact references derived by the lab,
    # not arbitrary inputs from AI or a web request. No wildcard fallback.
    for group in extra_groups:
        if len(group) != 1 or not re.fullmatch(r"docker\.io/library/(?:python:3\.[0-9]{1,2}-slim|node:[0-9]{1,3}-alpine)", group[0]):
            raise RuntimeError("PATCH_SOURCE_POLICY: Invalid experimental language helper")
        groups.append((group, group))
    staged_helpers=[]
    try:
        for group, aliases in groups:
            chosen = image_sources.pull_ordered(image_sources.ordered_candidates(sources, group))
            if local_mirror and local_source and str((report.get("Metadata") or {}).get("OS",{}).get("Family"))=="debian":
                from . import copa_mirrors, scan_evidence
                helper=copa_mirrors.prepare_sources(scan_evidence.local_image_id(chosen),local_mirror)
                staged_helpers.append(helper["image_ref"])
                chosen=helper["image_ref"]
            for reference in aliases:
                mappings[reference] = chosen
                print("COPA_HELPER_MAPPING " + reference + " -> " + chosen, flush=True)
        policy = source_policy(source, mappings,local_source=local_source)
        with tempfile.TemporaryDirectory(prefix="appsec-copa-policy-") as folder:
            path = Path(folder) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            print("COPA_SOURCE_POLICY active; helper mappings=" + str(len(mappings)), flush=True)
            yield {**os.environ, "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY": str(path)}
    finally:
        for ref in staged_helpers:
            from . import copa_mirrors
            copa_mirrors.cleanup(ref)
