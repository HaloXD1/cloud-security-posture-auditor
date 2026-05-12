from __future__ import annotations

import json
from pathlib import Path

from cloud_audit.config import load_settings, project_path


def generate_snapshots() -> dict[str, Path]:
    settings = load_settings()
    snapshot_dir = project_path(settings["paths"]["snapshots"])
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    outputs = {}
    for snapshot in _snapshots():
        path = snapshot_dir / f"{snapshot['account_id']}_{snapshot['environment']}.json"
        path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        outputs[f"{snapshot['account_id']}_{snapshot['environment']}"] = path
    return outputs


def _snapshots() -> list[dict]:
    return [
        {
            "account_id": "111111111111",
            "environment": "dev",
            "cloudtrail_enabled": False,
            "guardduty_enabled": False,
            "iam_users": [
                {
                    "user_name": "alice.dev",
                    "mfa_enabled": False,
                    "access_keys": [{"key_id": "FAKE-DEV-OLD-001", "created_at": "2025-09-01", "status": "active"}],
                    "attached_policies": [
                        {"policy_name": "PowerUserDebug", "actions": ["ec2:*", "s3:GetObject"], "resources": ["*"]}
                    ],
                },
                {
                    "user_name": "ci-bot",
                    "mfa_enabled": True,
                    "access_keys": [{"key_id": "FAKE-DEV-NEW-002", "created_at": "2026-04-15", "status": "active"}],
                    "attached_policies": [
                        {
                            "policy_name": "ReadOnlyArtifacts",
                            "actions": ["s3:GetObject"],
                            "resources": ["arn:aws:s3:::dev-artifacts/*"],
                        }
                    ],
                },
            ],
            "iam_roles": [
                {"role_name": "dev-cross-account-debug", "trust_principals": ["*"]},
                {"role_name": "lambda-runtime", "trust_principals": ["lambda.amazonaws.com"]},
            ],
            "s3_buckets": [
                {"bucket_name": "dev-public-reports", "public": True, "encrypted": False, "versioning": False},
                {"bucket_name": "dev-private-artifacts", "public": False, "encrypted": True, "versioning": False},
            ],
            "security_groups": [
                {
                    "group_id": "sg-dev-ssh",
                    "rules": [
                        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0", "description": "temporary ssh"},
                        {"protocol": "tcp", "port": 443, "cidr": "10.0.0.0/16", "description": "internal https"},
                    ],
                }
            ],
            "rds_instances": [{"db_id": "dev-reporting-db", "publicly_accessible": True, "encrypted": False}],
            "ebs_volumes": [{"volume_id": "vol-dev-001", "encrypted": False}],
        },
        {
            "account_id": "222222222222",
            "environment": "prod",
            "cloudtrail_enabled": True,
            "guardduty_enabled": True,
            "iam_users": [
                {
                    "user_name": "bob.ops",
                    "mfa_enabled": True,
                    "access_keys": [{"key_id": "FAKE-PROD-OLD-001", "created_at": "2025-10-01", "status": "active"}],
                    "attached_policies": [{"policy_name": "AdministratorAccess", "actions": ["*"], "resources": ["*"]}],
                },
                {
                    "user_name": "analyst",
                    "mfa_enabled": False,
                    "access_keys": [],
                    "attached_policies": [
                        {"policy_name": "AthenaReadOnly", "actions": ["athena:GetQueryResults"], "resources": ["*"]}
                    ],
                },
            ],
            "iam_roles": [{"role_name": "prod-deploy-role", "trust_principals": ["arn:aws:iam::333333333333:root"]}],
            "s3_buckets": [
                {"bucket_name": "prod-customer-exports", "public": False, "encrypted": True, "versioning": True},
                {"bucket_name": "prod-logs", "public": False, "encrypted": True, "versioning": False},
            ],
            "security_groups": [
                {
                    "group_id": "sg-prod-web",
                    "rules": [{"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0", "description": "public app"}],
                },
                {
                    "group_id": "sg-prod-db",
                    "rules": [{"protocol": "tcp", "port": 5432, "cidr": "0.0.0.0/0", "description": "bad db rule"}],
                },
            ],
            "rds_instances": [{"db_id": "prod-main-db", "publicly_accessible": False, "encrypted": True}],
            "ebs_volumes": [
                {"volume_id": "vol-prod-001", "encrypted": True},
                {"volume_id": "vol-prod-legacy", "encrypted": False},
            ],
        },
    ]
