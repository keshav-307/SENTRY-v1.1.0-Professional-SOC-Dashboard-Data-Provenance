# Changelog

All notable changes to SENTRY are documented here.

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
