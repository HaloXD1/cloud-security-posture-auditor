# Interview Guide

## Pitch

I built a cloud security posture auditor that scans AWS-style account configuration snapshots using YAML policy rules. It produces severity-based findings, account scorecards, remediation reports, and a Streamlit dashboard. It is safe to publish because it uses synthetic offline snapshots by default.

## Strong Talking Points

- Offline snapshots avoid exposing credentials in a public portfolio.
- YAML rules separate security policy from scanner code.
- Severity scoring helps prioritize remediation instead of listing raw issues.
- Findings include remediation text so the output is actionable.
- CI runs linting, formatting, tests, smoke checks, dashboard bootstrap, and secret scanning.

## Explain Simply

The project is like a security checklist that reads cloud settings, finds risky configurations, scores the account, and tells the team what to fix first.
