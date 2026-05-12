# Security Report

Synthetic AWS-style snapshots only. No real cloud credentials are required.

## Account Scorecard

| account_id   | environment | finding_count | risk_points | security_score |
| ------------ | ----------- | ------------- | ----------- | -------------- |
| 111111111111 | dev         | 14            | 98          | 41.2           |
| 222222222222 | prod        | 8             | 56          | 66.4           |

## Severity Summary

| severity | finding_count | risk_points |
| -------- | ------------- | ----------- |
| critical | 6             | 60          |
| high     | 10            | 70          |
| medium   | 6             | 24          |

## Top Critical and High Findings

| account_id   | environment | resource_type  | resource_id                 | rule_id                 | severity | risk_explanation                                            | remediation                                                                   | compliance_tag |
| ------------ | ----------- | -------------- | --------------------------- | ----------------------- | -------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------- |
| 111111111111 | dev         | account        | 111111111111                | CLOUDTRAIL_DISABLED     | high     | Account-level audit logging is disabled.                    | Enable CloudTrail-style logging for all regions.                              | logging        |
| 111111111111 | dev         | iam_user       | alice.dev                   | IAM_MFA_DISABLED        | high     | IAM user has console access risk without MFA.               | Enable MFA for the user or remove interactive access.                         | IAM            |
| 111111111111 | dev         | iam_policy     | alice.dev:PowerUserDebug    | IAM_WILDCARD_PERMISSION | high     | IAM policy grants wildcard actions or resources.            | Replace wildcard permissions with explicit allowed actions and resources.     | IAM            |
| 111111111111 | dev         | iam_role       | dev-cross-account-debug     | IAM_OPEN_TRUST_POLICY   | critical | Role trust policy allows overly broad principals.           | Restrict trusted principals to specific account, role, or service identities. | IAM            |
| 111111111111 | dev         | s3_bucket      | dev-public-reports          | S3_PUBLIC_BUCKET        | critical | S3 bucket is publicly exposed.                              | Block public access and review bucket policies.                               | storage        |
| 111111111111 | dev         | s3_bucket      | dev-public-reports          | S3_ENCRYPTION_DISABLED  | high     | S3 bucket does not enforce encryption at rest.              | Enable default server-side encryption.                                        | encryption     |
| 111111111111 | dev         | security_group | sg-dev-ssh:22               | SG_RISKY_PUBLIC_INGRESS | critical | Security group exposes a risky port to the public internet. | Restrict ingress to trusted CIDR ranges or private connectivity.              | network        |
| 111111111111 | dev         | rds_instance   | dev-reporting-db            | RDS_PUBLIC              | critical | Database is publicly accessible.                            | Disable public accessibility and place the database in private subnets.       | network        |
| 111111111111 | dev         | rds_instance   | dev-reporting-db            | VOLUME_UNENCRYPTED      | high     | Storage volume is not encrypted.                            | Encrypt the volume or migrate data to encrypted storage.                      | encryption     |
| 111111111111 | dev         | ebs_volume     | vol-dev-001                 | VOLUME_UNENCRYPTED      | high     | Storage volume is not encrypted.                            | Encrypt the volume or migrate data to encrypted storage.                      | encryption     |
| 222222222222 | prod        | iam_policy     | bob.ops:AdministratorAccess | IAM_DIRECT_ADMIN_POLICY | critical | Administrative permissions are attached directly to a user. | Use least-privilege role-based access instead of direct admin user policies.  | IAM            |
| 222222222222 | prod        | iam_policy     | bob.ops:AdministratorAccess | IAM_WILDCARD_PERMISSION | high     | IAM policy grants wildcard actions or resources.            | Replace wildcard permissions with explicit allowed actions and resources.     | IAM            |
| 222222222222 | prod        | iam_user       | analyst                     | IAM_MFA_DISABLED        | high     | IAM user has console access risk without MFA.               | Enable MFA for the user or remove interactive access.                         | IAM            |
| 222222222222 | prod        | iam_policy     | analyst:AthenaReadOnly      | IAM_WILDCARD_PERMISSION | high     | IAM policy grants wildcard actions or resources.            | Replace wildcard permissions with explicit allowed actions and resources.     | IAM            |
| 222222222222 | prod        | security_group | sg-prod-db:5432             | SG_RISKY_PUBLIC_INGRESS | critical | Security group exposes a risky port to the public internet. | Restrict ingress to trusted CIDR ranges or private connectivity.              | network        |
| 222222222222 | prod        | ebs_volume     | vol-prod-legacy             | VOLUME_UNENCRYPTED      | high     | Storage volume is not encrypted.                            | Encrypt the volume or migrate data to encrypted storage.                      | encryption     |
