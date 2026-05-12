from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REQUIRED_RULE_FIELDS = {"rule_id", "severity", "compliance_tag", "explanation", "remediation"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def load_rules(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        payload = yaml.safe_load(file)
    rules = payload.get("rules", [])
    validate_rules(rules)
    return rules


def validate_rules(rules: list[dict[str, Any]]) -> None:
    seen = set()
    for rule in rules:
        missing = REQUIRED_RULE_FIELDS - set(rule)
        if missing:
            raise ValueError(f"{rule.get('rule_id', 'unknown')} missing fields: {', '.join(sorted(missing))}")
        if rule["severity"] not in VALID_SEVERITIES:
            raise ValueError(f"{rule['rule_id']} has invalid severity: {rule['severity']}")
        if not rule["remediation"].strip():
            raise ValueError(f"{rule['rule_id']} missing remediation")
        if rule["rule_id"] in seen:
            raise ValueError(f"Duplicate rule_id: {rule['rule_id']}")
        seen.add(rule["rule_id"])
