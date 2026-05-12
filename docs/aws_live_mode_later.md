# AWS Live Mode Later

Live AWS mode is intentionally not enabled in the public version.

If added later:

- Require explicit `cloud-audit scan --source aws --profile default`.
- Use read-only AWS permissions.
- Never store credentials in the repo.
- Export sanitized findings only.
- Add tests that mock `boto3`.
- Document required IAM policy before use.

This keeps the CV project safe while leaving a clear upgrade path.
