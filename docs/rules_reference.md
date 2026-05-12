# Rules Reference

| Rule ID | Area | Severity | What it catches |
| --- | --- | --- | --- |
| IAM_MFA_DISABLED | IAM | high | IAM users without MFA |
| IAM_OLD_ACCESS_KEY | IAM | medium | Active access keys older than 90 days |
| IAM_DIRECT_ADMIN_POLICY | IAM | critical | Admin policies attached directly to users |
| IAM_WILDCARD_PERMISSION | IAM | high | Wildcard actions or resources |
| IAM_OPEN_TRUST_POLICY | IAM | critical | Trust policies with broad principals |
| S3_PUBLIC_BUCKET | storage | critical | Public S3 buckets |
| S3_ENCRYPTION_DISABLED | encryption | high | Buckets without default encryption |
| S3_VERSIONING_DISABLED | storage | medium | Buckets without versioning |
| SG_RISKY_PUBLIC_INGRESS | network | critical | Risky ports exposed to `0.0.0.0/0` |
| RDS_PUBLIC | network | critical | Public database instances |
| CLOUDTRAIL_DISABLED | logging | high | Missing account audit logging |
| GUARDDUTY_DISABLED | logging | medium | Missing detection flag |
| VOLUME_UNENCRYPTED | encryption | high | Unencrypted databases or volumes |

Each finding includes resource type, resource ID, account, environment, rule ID, severity, explanation, remediation, and compliance tag.
