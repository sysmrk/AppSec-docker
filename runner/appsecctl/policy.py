from __future__ import annotations

import os
from typing import Any


SEVERITY_FIELDS = {
    "critical": "critical_count",
    "high": "high_count",
    "medium": "medium_count",
    "low": "low_count",
}


def _limit(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return int(value)


def rules_from_env() -> dict[str, int]:
    return {
        "max_critical": _limit("POLICY_MAX_CRITICAL", 0),
        "max_high": _limit("POLICY_MAX_HIGH", 0),
        "max_medium": _limit("POLICY_MAX_MEDIUM", 999999),
        "max_low": _limit("POLICY_MAX_LOW", 999999),
    }


def normalize_rules(rules: dict[str, Any]) -> dict[str, int]:
    return {
        "max_critical": int(rules.get("max_critical", 0)),
        "max_high": int(rules.get("max_high", 0)),
        "max_medium": int(rules.get("max_medium", 999999)),
        "max_low": int(rules.get("max_low", 999999)),
    }


def evaluate(scan: dict[str, Any], rules: dict[str, int] | None = None) -> tuple[str, dict[str, int], list[dict[str, Any]]]:
    active_rules = normalize_rules(rules) if rules else rules_from_env()
    violations = []

    for severity, field in SEVERITY_FIELDS.items():
        count = int(scan.get(field) or 0)
        limit = int(active_rules[f"max_{severity}"])
        if count > limit:
            violations.append(
                {
                    "severity": severity.upper(),
                    "count": count,
                    "limit": limit,
                }
            )

    return ("passed" if not violations else "failed", active_rules, violations)
