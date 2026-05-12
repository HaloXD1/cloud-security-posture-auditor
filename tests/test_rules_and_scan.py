import pandas as pd
import pytest

from cloud_audit.bootstrap import ensure_demo_outputs
from cloud_audit.config import load_settings, project_path
from cloud_audit.generate_snapshots import generate_snapshots
from cloud_audit.health import assert_outputs, required_exports
from cloud_audit.rules import load_rules
from cloud_audit.scan import build_risk_summary, build_scorecard, scan_snapshots


def test_generate_snapshots_and_validate_rules():
    outputs = generate_snapshots()
    assert len(outputs) == 2
    settings = load_settings()
    rules = load_rules(project_path(settings["paths"]["rules"]))
    assert len(rules) >= 13


def test_scan_flags_major_security_rules():
    generate_snapshots()
    scan_snapshots(source="snapshots")
    findings = pd.read_csv(required_exports()["findings"])
    expected_rules = {
        "IAM_MFA_DISABLED",
        "IAM_OLD_ACCESS_KEY",
        "IAM_DIRECT_ADMIN_POLICY",
        "IAM_WILDCARD_PERMISSION",
        "IAM_OPEN_TRUST_POLICY",
        "S3_PUBLIC_BUCKET",
        "S3_ENCRYPTION_DISABLED",
        "S3_VERSIONING_DISABLED",
        "SG_RISKY_PUBLIC_INGRESS",
        "RDS_PUBLIC",
        "CLOUDTRAIL_DISABLED",
        "GUARDDUTY_DISABLED",
        "VOLUME_UNENCRYPTED",
    }
    assert expected_rules.issubset(set(findings["rule_id"]))
    assert findings["remediation"].str.len().min() > 10


def test_summary_and_scorecard_match_findings():
    generate_snapshots()
    scan_snapshots(source="snapshots")
    findings = pd.read_csv(required_exports()["findings"])
    summary = build_risk_summary(findings)
    scorecard = build_scorecard(findings)
    assert int(summary["finding_count"].sum()) == len(findings)
    assert scorecard["security_score"].between(0, 100).all()


def test_bootstrap_recreates_missing_exports():
    generate_snapshots()
    scan_snapshots(source="snapshots")
    for path in required_exports().values():
        path.unlink(missing_ok=True)
    assert ensure_demo_outputs() is True
    assert_outputs()


def test_unknown_live_aws_mode_is_blocked():
    with pytest.raises(NotImplementedError):
        scan_snapshots(source="aws")
