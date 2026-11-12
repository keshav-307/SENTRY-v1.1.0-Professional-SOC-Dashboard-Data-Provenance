# Changelog

All notable changes to SENTRY are documented here.

## [1.1.0] — 2026-11-12

### Added

- Explicit synthetic/live data provenance. Events now carry `event_origin`
  (`SYNTHETIC`, `LIVE`) and the origin of the triggering events is propagated
  to alerts. Historical rows remain `UNKNOWN` and are never guessed.
- Additive, idempotent schema migration for `events.event_origin`,
  `alerts.event_origin` and an origin index; existing data is untouched.
- Professional eight-page SOC dashboard: Security Overview, Live Network
  Monitoring, Alerts & Incidents, Network Activity, Event Explorer, Synthetic
  Lab, Detection Rules and About SENTRY.
- Real-data overview charts: 24-hour event volume by origin, alert severity,
  event-source split, top source IPs, top destination ports and detection-rule
  distribution, with explicit empty states.
- Origin filters (`All Sources`, `Live`, `Synthetic`, `Unknown`) and text
  badges across alerts, network activity, related events and the event
  explorer.
- Dedicated **Synthetic Lab** with scenario and intensity selection, explicit
  generation, post-run event/alert summary, and a persistent simulated-data
  warning.
- Server-side Event Explorer filtering and pagination so large event stores
  are never loaded in full.
- Bounded dashboard queries: timeline, top-N and paginated event access
  instead of full-table scans on every refresh.
- Dark Streamlit theme (`.streamlit/config.toml`) aligned with the SENTRY
  palette.
- Automated UI verification with Streamlit `AppTest` covering navigation,
  synthetic generation, alert filtering and lifecycle, live start/stop and
  explorer filtering.

### Changed

- Synthetic scenarios are labelled `SYNTHETIC` at generation time; network
  sensor events are labelled `LIVE`. Detection logic, thresholds, dedup,
  severity, confidence, evidence and MITRE mappings are unchanged.
- The alert investigation workspace groups Overview, Detection evidence,
  Investigation context, and Notes & lifecycle into working tabs.
- README documents provenance, the new dashboard, current test baseline and
  refreshed screenshots.

### Migration

- Existing `sentry.db` files are upgraded in place. `event_origin` is added to
  `events` and `alerts`; existing rows keep `NULL` and display as `UNKNOWN`.
  No events, alerts, notes, statuses or investigations are modified.

### Fixed

- Live monitoring start/stop no longer uses a fragment-scoped rerun that could
  fail outside a fragment rerun context.
- Event tables serialise destination ports consistently, avoiding Arrow type
  warnings when ports are mixed with empty values.

## [1.0.0] — 2026-11-12

### Added

- Structured detection evidence for every rule, persisted as JSON with a
  non-destructive schema migration. Legacy alerts remain readable.
- Detection evidence panel in the dashboard ("WHY SENTRY DETECTED THIS")
  separated from ±120-second investigation context.
- User-editable rule configuration in `config/detection_rules.json`
  (enable/disable, thresholds, windows).
- Suspicious DNS activity rule (`DNS-SUSPICIOUS-001`) with DNS query capture.
- Threat intelligence / IP reputation enrichment with local feed, optional
  AbuseIPDB provider, caching, and private/reserved address handling.
- Optional statistical anomaly layer (`ML-ANOMALY-001`) with an explainable
  baseline and per-feature deviation reasons. Disabled by default.
- Optional JSON webhook notifications with severity filter and cooldown.
- Audit log for alert status and investigation changes.
- Query indexes and support tables for enrichment, audit, ML baseline and
  notification state.
- Reliable live capture: stop responds within one short sniff window even on
  idle links, batch processing replaces per-packet commits, capture errors are
  surfaced in the dashboard.
- Alert search in the dashboard.
- Threat intelligence panel in alert investigation.

### Changed

- The pipeline, detector, enrichment and ML baseline now share one database
  instance and the configured path.
- Network sensor buffers events and flushes on size or time thresholds.

### Fixed

- Detector no longer opens a second default database when a custom path is used.
- Alert confidence rendering no longer crashes on NULL confidence values.
- Path traversal now detects mixed, percent-encoded, uppercase and
  double-encoded separators with bounded two-pass decoding, while benign paths
  containing `..` remain clean.
- SQL injection signatures now require SQL context, removing false positives
  on ordinary search terms and double hyphens in filenames; encoded SQL
  payloads are decoded before matching.
- Repeated detections no longer create duplicate alerts: SSH brute force,
  SQL injection, path traversal and authentication compromise use persistent
  per-rule deduplication with cooldowns; network reconnaissance keeps its
  120-second per-source suppression.

### Documentation

- README screenshots, verification scope, roadmap, and contributor guidance
  completed for the first public release.
- Added `ROADMAP.md` and refreshed architecture and detection documentation.
