"""Stable, user-facing diagnostic codes without leaking infrastructure secrets.

Never echo raw subprocess stderr (may contain registry credentials, tokens, URLs).
Operators can correlate a short code and job ID with trusted container logs.
"""
from __future__ import annotations

import re
import subprocess
from typing import Any

_CATALOG = [
    ("NO_FIXABLE_OS", r"^NO_FIXABLE_OS:|No fixable OS vulnerabilities for Copa", "No known OS fixes available", "Finish without patching. Review remaining OS risks and application dependency updates separately.", False),
    ("SCAN_EVIDENCE_INVALID", r"^SCAN_EVIDENCE_INVALID:", "Scan or image evidence could not be verified", "Review image identity, scanner results and supported OS. Create a fresh scan if required; do not publish unverified output.", False),
    ("PATCH_SOURCE_POLICY", r"^PATCH_SOURCE_POLICY:|source denied by policy", "Image source is not approved for this patch", "Review the enabled registry endpoints and supported Copa helper mapping. Start a new scan if the original source changed.", False),
    ("SOURCE_PULL_FAILED", r"^SOURCE_PULL_FAILED:", "Image unavailable from approved sources", "Check each source's HTTP code, image path, permissions and TLS; no Docker Hub fallback was attempted.", True),
    ("REGISTRY_PUSH_DENIED", r"^REGISTRY_PUSH_DENIED:", "Registry push permission revoked", "Have an admin review the destination registry authorization.", False),
    ("TRIVY_JAVA_DB", r"java db update failed|unable to initialize the java db|failed to (?:download|update) (?:the )?java db", "Trivy Java database unavailable", "Check TRIVY_JAVA_DB_REPOSITORY, registry access and the Trivy cache.", True),
    ("REPO_TARGET", r"^REPO_TARGET:", "Repository target is invalid", "Use an approved HTTPS Git host and repository path.", False),
    ("GIT_CLONE_TIMEOUT", r"^GIT_CLONE_TIMEOUT:", "Repository clone timed out", "Check DNS, proxy and HTTPS access from the Worker.", True),
    ("GIT_CLONE_FAILED", r"^GIT_CLONE_FAILED:", "Repository clone failed", "Check HTTPS access, repository permissions and the Worker Git configuration.", True),
    ("GITLEAKS_DOCKER", r"^GITLEAKS_DOCKER:", "Docker could not start Gitleaks", "Check Docker access and whether the configured Gitleaks image is available to the daemon.", True),
    ("GITLEAKS_FAILED", r"^GITLEAKS_FAILED:", "Gitleaks execution failed", "Check the scanner version, entrypoint and workspace permissions.", False),
    ("GITLEAKS_REPORT", r"^GITLEAKS_REPORT:", "Gitleaks report is missing or invalid", "Check report volume permissions and the scanner JSON format.", False),
    ("MFA_REQUIRED", r"mfa_required|authenticator code.*required", "Authenticator verification required", "Enter your 6-digit authenticator code or one of your one-time recovery codes.", False),
    ("REGISTRY_FORBIDDEN", r"403 Forbidden|status code: 403|status: 403", "Registry access forbidden", "Check approved source availability, registry permissions and egress policy.", True),
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
    # A failed command's arguments can include the Docker socket mount even
    # when the daemon worked. Classify the subprocess diagnostic itself.
    raw = str((value.stderr or "") if isinstance(value, subprocess.CalledProcessError) else (value or ""))
    for code, pattern, title, hint, retryable in _CATALOG:
        if raw.startswith(code + ":") or re.search(pattern, raw, flags=re.IGNORECASE):
            return {"code": code, "title": title, "hint": hint, "retryable": retryable, "stage": stage}
    return {
        "code": "OPERATION_FAILED", "title": "Operation could not be completed",
        "hint": "Open System Health or ask an administrator to check the worker logs with this job ID.",
        "retryable": False, "stage": stage,
    }

def safe_message(value: Any, stage: str = "execution") -> str:
    item = classify(value, stage)
    raw = value.stderr if isinstance(value, subprocess.CalledProcessError) else value
    if str(raw or "").startswith(item["code"] + ":"):
        detail = str(raw).split(":", 1)[1].strip()[:1600]
    elif isinstance(value, subprocess.CalledProcessError):
        detail = "exit=" + str(value.returncode) + "; " + safe_detail(raw)
    else:
        detail = ""
    return item["code"] + ": " + item["title"] + (" | " + detail if detail else "")

def ui_error(value: Any, stage: str = "execution") -> dict[str, Any] | None:
    if not value:
        return None
    info = classify(value, stage)
    if str(value).startswith(info["code"] + ":"):
        info["detail"] = str(value).split("|", 1)[-1].strip()[:1600] if "|" in str(value) else str(value).split(":", 1)[1].strip()[:350]
    return info


def safe_detail(value: Any) -> str:
    """Expose concrete scanner reason without tokens, credentials or full command args."""
    raw = str(value or "")
    raw = re.sub(r"(?i)(https?://)[^/\s@]+:[^/\s@]+@", r"\1[credentials]@", raw)
    raw = re.sub(r"(?i)\b(bearer|authorization|password|token|secret|api[-_]?key)\s*[:=]\s*[^;\s]+",
                 r"\1=[REDACTED]", raw)
    raw = re.sub(r"(?i)([?&](?:token|key|signature|password|secret)=)[^&\s]+", r"\1[REDACTED]", raw)
    lines = [re.sub(r"[\x00-\x1f]", " ", x).strip() for x in raw.splitlines() if x.strip()]
    return (lines[-1] if lines else "No scanner diagnostic was returned")[:350]
