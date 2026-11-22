"""Stable, user-facing diagnostic codes without leaking infrastructure secrets.

Never echo raw subprocess stderr (may contain registry credentials, tokens, URLs).
Operators can correlate a short code and job ID with trusted container logs.
"""
from __future__ import annotations

import re
from typing import Any

_CATALOG = [
    ("REGISTRY_AUTH", r"(unauthorized|authentication required|denied: requested access|401 Unauthorized|no basic auth credentials)", "Registry authentication failed", "Check registry credentials, permissions and image namespace.", False),
    ("REGISTRY_NOT_FOUND", r"(manifest unknown|manifest not found|name unknown|pull access denied|404 Not Found|repository does not exist)", "Container image not found", "Check the repository, tag/digest and registry hostname.", False),
    ("DOCKER_UNAVAILABLE", r"(cannot connect to the docker daemon|docker daemon.*not running|/var/run/docker.sock|connection refused.*docker)", "Docker execution service unavailable", "Ask an administrator to check Docker and the isolated scanning worker.", True),
    ("TRIVY_DB", r"(vulnerability db|trivy db|db update|could not download.*db|database.*download)", "Vulnerability database unavailable", "Check the Trivy cache, trusted registry mirrors and egress connectivity.", True),
    ("REGISTRY_NETWORK", r"(no such host|temporary failure in name resolution|network is unreachable|i/o timeout|tls handshake timeout|certificate signed by unknown authority)", "Registry or network connection failed", "Check DNS, proxy, outbound firewall and trusted TLS certificates.", True),
    ("NO_DISK", r"(no space left on device|disk quota exceeded|out of space)", "Scanner disk space exhausted", "Ask an administrator to check Docker disk usage and artifact retention.", True),
    ("BUILDKIT", r"(buildkit|failed to solve|copa patch)", "Image patch executor failed", "Check the isolated BuildKit container, Copa logs and package compatibility.", False),
    ("PERMISSION", r"(permission denied|insufficient role|project access denied)", "Permission denied", "Ask a Project owner or administrator to review your access.", False),
    ("TIMEOUT", r"(timed out|timeout expired|deadline exceeded)", "Operation timed out", "Inspect network and worker capacity; retry a scan only if no publication occurred.", True),
    ("POLICY_FAILED", r"(policy.failed|policy_failed|policy violation)", "Security policy blocked the workflow", "Review the policy findings and ask for an authorized exception if required.", False),
]

def classify(value: Any, stage: str = "execution") -> dict[str, Any]:
    raw = str(value or "")
    for code, pattern, title, hint, retryable in _CATALOG:
        if re.search(pattern, raw, flags=re.IGNORECASE):
            return {"code": code, "title": title, "hint": hint, "retryable": retryable, "stage": stage}
    return {
        "code": "OPERATION_FAILED", "title": "Operation could not be completed",
        "hint": "Open System Health or ask an administrator to check the worker logs with this job ID.",
        "retryable": False, "stage": stage,
    }

def safe_message(value: Any, stage: str = "execution") -> str:
    item = classify(value, stage)
    return item["code"] + ": " + item["title"]

def ui_error(value: Any, stage: str = "execution") -> dict[str, Any] | None:
    return classify(value, stage) if value else None
