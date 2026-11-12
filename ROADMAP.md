# SENTRY Roadmap

SENTRY v1.0.0 is the first public release. It focuses on a complete,
locally runnable detect → alert → investigate loop. Everything below is
planned work, not a current capability.

## v1.1 — Broader ingestion and reporting

- Windows Event Log ingestion (Security, System, PowerShell channels).
- Linux authentication (`auth.log`, `journald`) and syslog ingestion.
- Improved event search and filtering in the dashboard.
- CSV and JSON report exports for alerts and investigations.
- Additional detection rules (for example impossible travel, service
  creation, suspicious process execution).
- Import/export of rule configuration.

## v1.2 — Integrations and policy

- Threat-intelligence provider integrations beyond the local feed and
  optional AbuseIPDB lookup.
- Email and webhook notification templates with retry handling.
- Configurable detection policies and per-rule severity overrides.
- Improved alert investigation workflow (assignment, tags, saved views).
- Retention controls for events and audit history.

## v1.3 — Analytics

- ML-based anomaly detection improvements and baseline management UI.
- Behavioural analytics per host and per account.
- Advanced cross-rule correlation and incident grouping.
- Additional visualisations (timelines, geo/ASN summaries, port heatmaps).

## Future

- User authentication and role-based access control.
- Multi-user and team deployment.
- Distributed log ingestion and agent management.
- Scalable storage backends (PostgreSQL, object storage).
- Enterprise deployment, high availability and audit export.

## Out of scope for v1.0

- Cloud-hosted multi-tenant operation.
- Packet payload capture or full stream reassembly.
- Automatic blocking or remediation actions.
