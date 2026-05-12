# Remediation Plan

| severity | resource_type  | resource_id                 | rule_id                 | remediation                                                                   |
| -------- | -------------- | --------------------------- | ----------------------- | ----------------------------------------------------------------------------- |
| critical | security_group | sg-dev-ssh:22               | SG_RISKY_PUBLIC_INGRESS | Restrict ingress to trusted CIDR ranges or private connectivity.              |
| critical | iam_policy     | bob.ops:AdministratorAccess | IAM_DIRECT_ADMIN_POLICY | Use least-privilege role-based access instead of direct admin user policies.  |
| critical | iam_role       | dev-cross-account-debug     | IAM_OPEN_TRUST_POLICY   | Restrict trusted principals to specific account, role, or service identities. |
| critical | s3_bucket      | dev-public-reports          | S3_PUBLIC_BUCKET        | Block public access and review bucket policies.                               |
| critical | rds_instance   | dev-reporting-db            | RDS_PUBLIC              | Disable public accessibility and place the database in private subnets.       |
| critical | security_group | sg-prod-db:5432             | SG_RISKY_PUBLIC_INGRESS | Restrict ingress to trusted CIDR ranges or private connectivity.              |
| high     | iam_policy     | analyst:AthenaReadOnly      | IAM_WILDCARD_PERMISSION | Replace wildcard permissions with explicit allowed actions and resources.     |
| high     | iam_user       | analyst                     | IAM_MFA_DISABLED        | Enable MFA for the user or remove interactive access.                         |
| high     | iam_policy     | bob.ops:AdministratorAccess | IAM_WILDCARD_PERMISSION | Replace wildcard permissions with explicit allowed actions and resources.     |
| high     | ebs_volume     | vol-dev-001                 | VOLUME_UNENCRYPTED      | Encrypt the volume or migrate data to encrypted storage.                      |
| high     | rds_instance   | dev-reporting-db            | VOLUME_UNENCRYPTED      | Encrypt the volume or migrate data to encrypted storage.                      |
| high     | account        | 111111111111                | CLOUDTRAIL_DISABLED     | Enable CloudTrail-style logging for all regions.                              |
| high     | s3_bucket      | dev-public-reports          | S3_ENCRYPTION_DISABLED  | Enable default server-side encryption.                                        |
| high     | iam_policy     | alice.dev:PowerUserDebug    | IAM_WILDCARD_PERMISSION | Replace wildcard permissions with explicit allowed actions and resources.     |
| high     | iam_user       | alice.dev                   | IAM_MFA_DISABLED        | Enable MFA for the user or remove interactive access.                         |
| high     | ebs_volume     | vol-prod-legacy             | VOLUME_UNENCRYPTED      | Encrypt the volume or migrate data to encrypted storage.                      |
| medium   | s3_bucket      | dev-public-reports          | S3_VERSIONING_DISABLED  | Enable versioning for recovery and change tracking.                           |
| medium   | iam_access_key | FAKE-PROD-OLD-001           | IAM_OLD_ACCESS_KEY      | Rotate the key and remove unused credentials.                                 |
| medium   | iam_access_key | FAKE-DEV-OLD-001            | IAM_OLD_ACCESS_KEY      | Rotate the key and remove unused credentials.                                 |
| medium   | account        | 111111111111                | GUARDDUTY_DISABLED      | Enable GuardDuty-style detection or equivalent monitoring.                    |
| medium   | s3_bucket      | prod-logs                   | S3_VERSIONING_DISABLED  | Enable versioning for recovery and change tracking.                           |
| medium   | s3_bucket      | dev-private-artifacts       | S3_VERSIONING_DISABLED  | Enable versioning for recovery and change tracking.                           |
