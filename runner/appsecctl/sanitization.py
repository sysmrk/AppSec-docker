"""Guardrails for secret scanning and report serialization.

Do not store Gitleaks raw Match, Secret or Line fields. Historical exports and
backups created before this fix must be purged separately.
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit

MASK = "[REDACTED]"
SENSITIVE_FIELDS = frozenset({"Match", "Secret", "Line", "Offender", "Raw"})


def validate_repo_target(target: str) -> str:
    """Permit only HTTPS Git repositories on explicitly approved hosts."""
    try:
        parsed = urlsplit(target)
        hostname = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as exc:
        raise ValueError("invalid repository URL") from exc
    if parsed.scheme != "https" or not hostname or parsed.username or parsed.password:
        raise ValueError("repository target must be an HTTPS URL without embedded credentials")
    if parsed.query or parsed.fragment or not parsed.path or parsed.path == "/":
        raise ValueError("repository URL must have a path and no query or fragment")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal repository targets are not permitted")
    allowed = {h.strip().lower().rstrip(".") for h in
               os.environ.get("SECURITY_ALLOWED_GIT_HOSTS", "github.com,gitlab.com").split(",") if h.strip()}
    if hostname not in allowed:
        raise ValueError("repository host is not in SECURITY_ALLOWED_GIT_HOSTS")
    return target


def redact_gitleaks_report(report: object) -> list[dict]:
    """Strip secret-bearing fields even when Gitleaks' own redaction is disabled."""
    if not isinstance(report, list):
        raise ValueError("Gitleaks JSON report must be a list")
    safe = []
    for entry in report:
        if not isinstance(entry, dict):
            raise ValueError("invalid Gitleaks report entry")
        safe.append({key: (MASK if key in SENSITIVE_FIELDS and value else value)
                     for key, value in entry.items()})
    return safe


def sanitize_security_detail(detail: dict) -> dict:
    """Do not emit historical unredacted DB content through API/reports."""
    job = dict(detail.get("job") or {})
    job.pop("raw_report", None)
    findings = []
    for item in detail.get("findings", []):
        finding = dict(item)
        if finding.get("evidence"):
            finding["evidence"] = MASK
        metadata = dict(finding.get("metadata") or {})
        metadata.pop("secret", None)
        finding["metadata"] = metadata
        findings.append(finding)
    return {**detail, "job": job, "findings": findings}
