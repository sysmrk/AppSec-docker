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
        # Match Copa v0.14.1's version selection for Debian.
        tag = "stable-slim" if version > "12" else major + "-slim"
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


def source_policy(source: str, mappings: dict[str, str]) -> dict:
    canonical_source = image_sources.canonical_ref(source)
    # Copa v0.14.1 inspects the first rule's updates.identifier even for DENY.
    # Provide an empty update object for compatibility; it has no DENY effect.
    rules = [{"action": "DENY", "selector": {"identifier": "^docker-image://.*$", "match_type": 2},
              "updates": {"identifier": ""}}]
    permitted = {canonical_source}
    for original, selected in mappings.items():
        original = image_sources.canonical_ref(original)
        selected = image_sources.canonical_ref(selected)
        permitted.add(selected)
        if original != selected:
            rules.append({"action": "CONVERT", "selector": {"identifier": "docker-image://" + original, "match_type": 1},
                          "updates": {"identifier": "docker-image://" + selected}})
    for reference in sorted(permitted):
        rules.append({"action": "ALLOW", "selector": {"identifier": "docker-image://" + reference, "match_type": 1}})
    return {"version": 1, "rules": rules}


@contextmanager
def policy_environment(source: str, report_path: Path):
    with db.connect() as conn:
        sources = image_sources.configured_sources(conn)
    if sources is None:
        yield None
        return
    if not sources:
        raise RuntimeError("SOURCE_PULL_FAILED: All trusted image sources are disabled")
    canonical = image_sources.canonical_ref(source)
    if not any(canonical.startswith(image_sources.normalize_endpoint(row["host"]) + "/") for row in sources):
        raise RuntimeError("PATCH_SOURCE_POLICY: Previously scanned source is no longer approved; create a new scan")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    mappings = {}
    for group in helper_groups(report):
        chosen = image_sources.pull_ordered(image_sources.ordered_candidates(sources, group))
        for reference in group:
            mappings[reference] = chosen
    policy = source_policy(source, mappings)
    with tempfile.TemporaryDirectory(prefix="appsec-copa-policy-") as folder:
        path = Path(folder) / "policy.json"
        path.write_text(json.dumps(policy), encoding="utf-8")
        print("COPA_SOURCE_POLICY active; helper mappings=" + str(len(mappings)), flush=True)
        yield {**os.environ, "EXPERIMENTAL_BUILDKIT_SOURCE_POLICY": str(path)}
