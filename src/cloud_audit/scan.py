from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd

from cloud_audit.config import ensure_parent, load_settings, project_path
from cloud_audit.generate_snapshots import generate_snapshots
from cloud_audit.markdown import dataframe_to_markdown
from cloud_audit.rules import load_rules

FINDING_COLUMNS = [
    "account_id",
    "environment",
    "resource_type",
    "resource_id",
    "rule_id",
    "severity",
    "risk_explanation",
    "remediation",
    "compliance_tag",
]
SEVERITY_POINTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}
RISKY_PUBLIC_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}
SCAN_DATE = datetime(2026, 5, 12, tzinfo=UTC)


def scan_snapshots(source: str = "snapshots") -> dict[str, Path]:
    if source != "snapshots":
        raise NotImplementedError("Only offline snapshots are supported in the public demo.")
    settings = load_settings()
    snapshot_dir = project_path(settings["paths"]["snapshots"])
    if not list(snapshot_dir.glob("*.json")):
        generate_snapshots()
    rules = {rule["rule_id"]: rule for rule in load_rules(project_path(settings["paths"]["rules"]))}
    findings = []
    for snapshot in _load_snapshots(snapshot_dir):
        findings.extend(_scan_account(snapshot, rules))
    findings_frame = pd.DataFrame(findings, columns=FINDING_COLUMNS)
    summary = build_risk_summary(findings_frame)
    scorecard = build_scorecard(findings_frame)
    outputs = _write_outputs(findings_frame, summary, scorecard, settings)
    write_reports(findings_frame, summary, scorecard)
    return outputs


def build_risk_summary(findings: pd.DataFrame) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["severity", "finding_count", "risk_points"])
    summary = findings.groupby("severity", as_index=False).size().rename(columns={"size": "finding_count"})
    summary["risk_points"] = summary["severity"].map(SEVERITY_POINTS) * summary["finding_count"]
    summary["severity_rank"] = summary["severity"].map({"critical": 0, "high": 1, "medium": 2, "low": 3})
    return summary.sort_values("severity_rank").drop(columns="severity_rank")


def build_scorecard(findings: pd.DataFrame) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["account_id", "environment", "finding_count", "risk_points", "security_score"])
    scored = findings.assign(points=findings["severity"].map(SEVERITY_POINTS))
    scorecard = (
        scored.groupby(["account_id", "environment"], as_index=False)
        .agg(finding_count=("rule_id", "count"), risk_points=("points", "sum"))
        .sort_values("risk_points", ascending=False)
    )
    scorecard["security_score"] = (100 - scorecard["risk_points"] * 0.6).round(1).clip(lower=0)
    return scorecard[["account_id", "environment", "finding_count", "risk_points", "security_score"]]


def write_reports(findings: pd.DataFrame, summary: pd.DataFrame, scorecard: pd.DataFrame) -> None:
    docs_dir = project_path("docs")
    docs_dir.mkdir(parents=True, exist_ok=True)
    critical = findings[findings["severity"].isin(["critical", "high"])].head(20)
    security_report = [
        "# Security Report",
        "",
        "Synthetic AWS-style snapshots only. No real cloud credentials are required.",
        "",
        "## Account Scorecard",
        "",
        dataframe_to_markdown(scorecard),
        "",
        "## Severity Summary",
        "",
        dataframe_to_markdown(summary),
        "",
        "## Top Critical and High Findings",
        "",
        dataframe_to_markdown(critical),
        "",
    ]
    remediation_plan = [
        "# Remediation Plan",
        "",
        dataframe_to_markdown(
            findings[["severity", "resource_type", "resource_id", "rule_id", "remediation"]]
            .sort_values("severity", key=lambda col: col.map({"critical": 0, "high": 1, "medium": 2, "low": 3}))
            .head(30)
        ),
        "",
    ]
    (docs_dir / "security_report.md").write_text("\n".join(security_report), encoding="utf-8")
    (docs_dir / "remediation_plan.md").write_text("\n".join(remediation_plan), encoding="utf-8")


def _load_snapshots(snapshot_dir: Path) -> list[dict[str, Any]]:
    snapshots = []
    for path in sorted(snapshot_dir.glob("*.json")):
        snapshots.append(json.loads(path.read_text(encoding="utf-8")))
    return snapshots


def _scan_account(snapshot: dict[str, Any], rules: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    findings = []
    account_id = snapshot["account_id"]
    environment = snapshot["environment"]

    if not snapshot.get("cloudtrail_enabled", False):
        findings.append(_finding(snapshot, "account", account_id, rules["CLOUDTRAIL_DISABLED"]))
    if not snapshot.get("guardduty_enabled", False):
        findings.append(_finding(snapshot, "account", account_id, rules["GUARDDUTY_DISABLED"]))

    for user in snapshot.get("iam_users", []):
        if not user.get("mfa_enabled", False):
            findings.append(_finding(snapshot, "iam_user", user["user_name"], rules["IAM_MFA_DISABLED"]))
        for key in user.get("access_keys", []):
            key_age = (SCAN_DATE - datetime.fromisoformat(key["created_at"]).replace(tzinfo=UTC)).days
            if key.get("status") == "active" and key_age > 90:
                findings.append(_finding(snapshot, "iam_access_key", key["key_id"], rules["IAM_OLD_ACCESS_KEY"]))
        for policy in user.get("attached_policies", []):
            actions = {str(action) for action in policy.get("actions", [])}
            resources = {str(resource) for resource in policy.get("resources", [])}
            if policy.get("policy_name") == "AdministratorAccess" or "*" in actions:
                findings.append(
                    _finding(
                        snapshot,
                        "iam_policy",
                        f"{user['user_name']}:{policy['policy_name']}",
                        rules["IAM_DIRECT_ADMIN_POLICY"],
                    )
                )
            if "*" in actions or any(action.endswith(":*") for action in actions) or "*" in resources:
                findings.append(
                    _finding(
                        snapshot,
                        "iam_policy",
                        f"{user['user_name']}:{policy['policy_name']}",
                        rules["IAM_WILDCARD_PERMISSION"],
                    )
                )

    for role in snapshot.get("iam_roles", []):
        if "*" in role.get("trust_principals", []):
            findings.append(_finding(snapshot, "iam_role", role["role_name"], rules["IAM_OPEN_TRUST_POLICY"]))

    for bucket in snapshot.get("s3_buckets", []):
        if bucket.get("public", False):
            findings.append(_finding(snapshot, "s3_bucket", bucket["bucket_name"], rules["S3_PUBLIC_BUCKET"]))
        if not bucket.get("encrypted", False):
            findings.append(_finding(snapshot, "s3_bucket", bucket["bucket_name"], rules["S3_ENCRYPTION_DISABLED"]))
        if not bucket.get("versioning", False):
            findings.append(_finding(snapshot, "s3_bucket", bucket["bucket_name"], rules["S3_VERSIONING_DISABLED"]))

    for group in snapshot.get("security_groups", []):
        for rule in group.get("rules", []):
            if rule.get("cidr") == "0.0.0.0/0" and int(rule.get("port", 0)) in RISKY_PUBLIC_PORTS:
                findings.append(
                    _finding(
                        snapshot,
                        "security_group",
                        f"{group['group_id']}:{rule['port']}",
                        rules["SG_RISKY_PUBLIC_INGRESS"],
                    )
                )

    for database in snapshot.get("rds_instances", []):
        if database.get("publicly_accessible", False):
            findings.append(_finding(snapshot, "rds_instance", database["db_id"], rules["RDS_PUBLIC"]))
        if not database.get("encrypted", False):
            findings.append(_finding(snapshot, "rds_instance", database["db_id"], rules["VOLUME_UNENCRYPTED"]))

    for volume in snapshot.get("ebs_volumes", []):
        if not volume.get("encrypted", False):
            findings.append(_finding(snapshot, "ebs_volume", volume["volume_id"], rules["VOLUME_UNENCRYPTED"]))

    for finding in findings:
        finding["account_id"] = account_id
        finding["environment"] = environment
    return findings


def _finding(snapshot: dict[str, Any], resource_type: str, resource_id: str, rule: dict[str, Any]) -> dict[str, str]:
    return {
        "account_id": snapshot["account_id"],
        "environment": snapshot["environment"],
        "resource_type": resource_type,
        "resource_id": resource_id,
        "rule_id": rule["rule_id"],
        "severity": rule["severity"],
        "risk_explanation": rule["explanation"],
        "remediation": rule["remediation"],
        "compliance_tag": rule["compliance_tag"],
    }


def _write_outputs(
    findings: pd.DataFrame,
    summary: pd.DataFrame,
    scorecard: pd.DataFrame,
    settings: dict[str, Any],
) -> dict[str, Path]:
    paths = {name: project_path(path) for name, path in settings["exports"].items()}
    for path in paths.values():
        ensure_parent(path)
    findings.to_csv(paths["findings"], index=False)
    summary.to_csv(paths["risk_summary"], index=False)
    scorecard.to_csv(paths["account_scorecard"], index=False)
    database_path = project_path(settings["paths"]["findings_db"])
    ensure_parent(database_path)
    with closing(sqlite3.connect(database_path)) as connection:
        findings.to_sql("findings", connection, if_exists="replace", index=False)
        summary.to_sql("risk_summary", connection, if_exists="replace", index=False)
        scorecard.to_sql("account_scorecard", connection, if_exists="replace", index=False)
        connection.commit()
    paths["database"] = database_path
    return paths
