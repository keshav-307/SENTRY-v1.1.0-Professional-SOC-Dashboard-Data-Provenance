import os
from datetime import datetime

from core.anomaly import AnomalyDetector
from core.database import SentryDatabase
from core.detector import DetectionEngine
from core.notifications import NotificationManager
from core.parser import LogParser
from core.threat_intel import ThreatIntel


ANOMALY_RULE_ID = "ML-ANOMALY-001"

ANOMALY_RECOMMENDED_ACTIONS = [
    "Compare the flagged host's activity with the rule-based alerts for the same period.",
    "Confirm the flagged activity is expected for this host before escalating.",
    "Review the contributing features; the score is a deviation signal, not proof of compromise.",
]


class SentryPipeline:
    """
    Main SENTRY security event processing pipeline.

    Flow:

        Raw Logs
            ↓
        Log Parser
            ↓
        Normalized Security Events
            ↓
        Detection Engine
            ↓
        Optional enrichment (threat intelligence, anomaly layer)
            ↓
        Security Alerts
            ↓
        SQLite Database
            ↓
        Optional notifications

    Detection state, evidence, enrichment and the ML baseline all use
    the single database configured for this pipeline.
    """

    def __init__(
        self,
        database_path="sentry.db",
        rules_config=None,
        threat_intel=None,
        anomaly_enabled=None,
        notifier=None,
    ):

        self.parser = LogParser()

        self.database = SentryDatabase(
            database_path
        )

        self.detector = DetectionEngine(
            database=self.database,
            rules_config=rules_config,
        )

        self.threat_intel = (
            threat_intel
            if threat_intel is not None
            else ThreatIntel(database=self.database)
        )

        self.notifier = (
            notifier
            if notifier is not None
            else NotificationManager()
        )

        if anomaly_enabled is None:
            anomaly_enabled = os.environ.get(
                "SENTRY_ANOMALY_ENABLED",
                "",
            ).strip().lower() in {
                "1",
                "true",
                "yes",
                "on",
            }

        self.anomaly_enabled = bool(anomaly_enabled)
        self.anomaly_detector = AnomalyDetector()

    # ---------------------------------------------------------
    # PROCESSING
    # ---------------------------------------------------------

    def process_logs(self, auth_path, access_path):
        """
        Parse raw authentication and web logs,
        run detection, and persist the results.

        Returns:
            events, alerts
        """

        events = self.parser.parse_files(
            auth_path,
            access_path,
        )

        alerts = self._process_events(events)

        return events, alerts

    def process_events(self, events):
        """
        Run the detection engine against already
        normalized SecurityEvent objects.

        Generated events are also persisted.
        """

        return self._process_events(events)

    def _process_events(self, events):
        alerts = self.detector.detect(
            events
        )

        if self.anomaly_enabled:
            alerts.extend(
                self._detect_anomalies(events)
            )

        alerts = self._label_alert_origins(
            alerts,
            events,
        )

        alerts = self._enrich_alerts(alerts)

        if events:
            self.database.save_events(
                events
            )

        if alerts:
            self.database.save_alerts(
                alerts
            )

        self.notifier.notify(
            alerts,
            self.database,
        )

        return alerts

    # ---------------------------------------------------------
    # DATA ORIGIN PROPAGATION
    # ---------------------------------------------------------

    @staticmethod
    def _label_alert_origins(alerts, events):
        """
        Carry the origin of the triggering events onto their alerts.

        This is metadata only: detection, severity, confidence and
        deduplication behaviour are untouched. Mixed origins are marked
        UNKNOWN rather than guessing.
        """

        if not alerts:
            return alerts

        origins_by_ip = {}
        batch_origins = set()

        for event in events or []:
            origin = (
                event.event_origin or "UNKNOWN"
            )

            batch_origins.add(origin)

            if event.source_ip:
                origins_by_ip.setdefault(
                    event.source_ip,
                    set(),
                ).add(origin)

        for alert in alerts:
            origins = (
                origins_by_ip.get(alert.source_ip)
                if alert.source_ip
                else None
            ) or batch_origins

            alert.event_origin = (
                next(iter(origins))
                if len(origins) == 1
                else "UNKNOWN"
            )

        return alerts

    # ---------------------------------------------------------
    # THREAT INTELLIGENCE ENRICHMENT
    # ---------------------------------------------------------

    def _enrich_alerts(self, alerts):
        for alert in alerts:
            if not alert.source_ip:
                continue

            try:
                alert.threat_intel = (
                    self.threat_intel.enrich_ip(
                        alert.source_ip
                    )
                )
            except Exception:
                # Enrichment must never break detection.
                alert.threat_intel = {
                    "ip": alert.source_ip,
                    "status": "unknown",
                    "source": None,
                    "score": None,
                    "details": "Enrichment failed.",
                    "last_checked": datetime.now().isoformat(),
                }

        return alerts

    # ---------------------------------------------------------
    # OPTIONAL ANOMALY LAYER
    # ---------------------------------------------------------

    def _detect_anomalies(self, events):
        """
        Run the statistical anomaly layer.

        The baseline is updated after scoring so current activity is
        compared against prior behaviour, not against itself.
        """

        baseline = self.database.get_ml_baseline()

        findings = self.anomaly_detector.detect(
            events,
            baseline,
        )

        alerts = [
            self._anomaly_alert(finding, events)
            for finding in findings
        ]

        try:
            updated = self.anomaly_detector.update_baseline(
                baseline,
                events,
            )

            if updated:
                self.database.set_ml_baseline(updated)
        except Exception:
            # Baseline persistence must never break detection.
            pass

        return alerts

    def _anomaly_alert(self, finding, events):
        source_ip = finding["source_ip"]

        matching_events = [
            event
            for event in events
            if event.source_ip == source_ip
        ][:50]

        reason_text = "; ".join(
            (
                f"{reason['feature']} observed "
                f"{reason['observed']} against a baseline mean of "
                f"{reason['baseline_mean']:.2f}"
            )
            for reason in finding["reasons"]
        )

        evidence = {
            "rule_id": ANOMALY_RULE_ID,
            "rule_name": "Statistical Anomaly",
            "rule_description": (
                "Compares per-source activity features against a stored "
                "baseline of normal behaviour."
            ),
            "severity": "MEDIUM",
            "mitre": {},
            "source_ip": source_ip,
            "summary": (
                f"{source_ip} deviated from the stored activity baseline "
                f"(score {finding['score']})."
            ),
            "explanation": (
                f"The anomaly layer observed behaviour that differs from "
                f"the learned baseline: {reason_text}. This indicates "
                f"unusual activity for this host, not necessarily malicious "
                f"activity."
            ),
            "confidence": {
                "score": None,
                "basis": (
                    "Anomaly scores measure deviation from a baseline. "
                    "They are not probabilities of malicious activity."
                ),
            },
            "window": {
                "start": (
                    min(
                        event.timestamp
                        for event in matching_events
                    ).isoformat()
                    if matching_events
                    else None
                ),
                "end": (
                    max(
                        event.timestamp
                        for event in matching_events
                    ).isoformat()
                    if matching_events
                    else None
                ),
                "seconds": None,
            },
            "conditions": [
                {
                    "condition": (
                        "Feature deviation from the stored baseline"
                    ),
                    "expected": (
                        f"z-score below {finding['threshold']}"
                    ),
                    "observed": (
                        f"z-score {finding['score']}"
                    ),
                    "result": "MET",
                }
            ],
            "triggering_event_count": finding["features"][
                "event_count"
            ],
            "triggering_events": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "source": event.source,
                    "event_type": event.event_type,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "protocol": event.protocol,
                    "username": event.username,
                    "method": event.method,
                    "path": event.path,
                    "status": event.status,
                    "outcome": event.outcome,
                    "raw": event.raw,
                }
                for event in matching_events
            ],
            "recommended_actions": ANOMALY_RECOMMENDED_ACTIONS,
            "model": finding["model"],
            "anomaly_score": finding["score"],
            "baseline": finding["baseline"],
            "features": finding["features"],
            "reasons": finding["reasons"],
        }

        return _build_anomaly_alert(source_ip, finding, evidence)


def _build_anomaly_alert(source_ip, finding, evidence):
    from core.models import Alert

    return Alert(
        alert_type="Statistical Anomaly",
        severity="MEDIUM",
        source_ip=source_ip,
        detail=(
            f"Activity from {source_ip} deviated from the stored "
            f"baseline (score {finding['score']})."
        ),
        timestamp=datetime.fromisoformat(
            finding["detected_at"]
        ),
        rule_id=ANOMALY_RULE_ID,
        confidence=0.5,
        evidence=evidence,
    )
