import json
from datetime import datetime, timedelta

from scapy.all import DNS, DNSQR, IP, TCP, UDP

from core.anomaly import AnomalyDetector
from core.database import SentryDatabase
from core.detector import DetectionEngine, load_rules_config
from core.models import Alert, SecurityEvent
from core.notifications import NotificationManager
from core.pipeline import SentryPipeline
from core.threat_intel import ThreatIntel
from sensors.network_sensor import NetworkSensor


BASE = datetime(2026, 1, 1, 12, 0, 0)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def failure_events(source_ip, count, spacing=10):
    return [
        SecurityEvent(
            timestamp=BASE + timedelta(seconds=spacing * i),
            source="authentication",
            event_type="login_failure",
            source_ip=source_ip,
            username="admin",
        )
        for i in range(count)
    ]


def dns_event(source_ip, name, timestamp, status=0):
    return SecurityEvent(
        timestamp=timestamp,
        source="network",
        event_type="dns_query",
        source_ip=source_ip,
        destination_ip="10.0.0.53",
        destination_port=53,
        protocol="UDP",
        path=name,
        status=status,
    )


def tcp_packet(source_ip="192.0.2.1", destination_port=80):
    return (
        IP(src=source_ip, dst="192.0.2.2")
        / TCP(dport=destination_port)
    )


class RecordingPipeline:
    def __init__(self):
        self.batches = []

    def process_events(self, events):
        self.batches.append([event.event_type for event in events])
        return []


# -------------------------------------------------------------------
# Rule configuration
# -------------------------------------------------------------------

def test_default_rule_config_preserves_documented_thresholds():
    config = load_rules_config()

    assert config["SSH-BRUTE-001"]["threshold"] == 5
    assert config["SSH-BRUTE-001"]["window_seconds"] == 120
    assert config["AUTH-COMPROMISE-001"]["threshold"] == 5
    assert config["NET-RECON-001"]["threshold"] == 10
    assert config["DNS-SUSPICIOUS-001"]["threshold"] == 20
    assert config["WEB-SQLI-001"]["enabled"] is True


def test_missing_config_file_falls_back_to_defaults():
    config = load_rules_config("does-not-exist.json")

    assert config["NET-RECON-001"]["threshold"] == 10


def test_threshold_override_is_applied(tmp_path):
    database = SentryDatabase(str(tmp_path / "config.db"))

    engine = DetectionEngine(
        database=database,
        rules_config={
            "SSH-BRUTE-001": {"threshold": 3},
        },
    )

    alerts = engine.detect(
        failure_events("203.0.113.10", 3)
    )

    assert len(alerts) == 1
    assert alerts[0].evidence["threshold"] == 3
    assert alerts[0].evidence["observed_failures"] == 3


def test_rule_can_be_disabled(tmp_path):
    database = SentryDatabase(str(tmp_path / "disabled.db"))

    engine = DetectionEngine(
        database=database,
        rules_config={
            "SSH-BRUTE-001": {"enabled": False},
        },
    )

    assert engine.detect(
        failure_events("203.0.113.11", 10)
    ) == []


# -------------------------------------------------------------------
# DNS detection
# -------------------------------------------------------------------

def test_suspicious_dns_activity_alert(tmp_path):
    database = SentryDatabase(str(tmp_path / "dns.db"))
    engine = DetectionEngine(database=database)

    events = [
        dns_event(
            "192.0.2.50",
            f"host{i}.example.com",
            BASE + timedelta(seconds=i),
            status=3 if i % 5 == 0 else 0,
        )
        for i in range(20)
    ]

    alerts = [
        alert
        for alert in engine.detect(events)
        if alert.rule_id == "DNS-SUSPICIOUS-001"
    ]

    assert len(alerts) == 1

    evidence = alerts[0].evidence

    assert evidence["mitre"]["technique_id"] == "T1071.004"
    assert evidence["unique_domain_count"] == 20
    assert evidence["threshold"] == 20
    assert evidence["nxdomain_count"] == 4
    assert len(evidence["unique_domains"]) == 20


def test_dns_activity_below_threshold_does_not_alert(tmp_path):
    database = SentryDatabase(str(tmp_path / "dns_low.db"))
    engine = DetectionEngine(database=database)

    events = [
        dns_event(
            "192.0.2.51",
            f"host{i}.example.com",
            BASE + timedelta(seconds=i),
        )
        for i in range(10)
    ]

    assert engine.detect(events) == []


def test_dns_activity_is_deduplicated(tmp_path):
    database = SentryDatabase(str(tmp_path / "dns_dedup.db"))
    engine = DetectionEngine(database=database)

    events = [
        dns_event(
            "192.0.2.52",
            f"host{i}.example.com",
            BASE + timedelta(seconds=i),
        )
        for i in range(25)
    ]

    assert len(engine.detect(events)) == 1
    assert engine.detect(events) == []


# -------------------------------------------------------------------
# Network sensor
# -------------------------------------------------------------------

def test_sensor_converts_dns_query_packet():
    packet = (
        IP(src="192.0.2.10", dst="8.8.8.8")
        / UDP(sport=5555, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    event = NetworkSensor().packet_to_event(packet)

    assert event is not None
    assert event.event_type == "dns_query"
    assert event.path == "example.com"
    assert event.destination_port == 53
    assert event.protocol == "UDP"


def test_sensor_converts_tcp_connection_packet():
    event = NetworkSensor().packet_to_event(tcp_packet())

    assert event.event_type == "connection"
    assert event.destination_port == 80
    assert event.protocol == "TCP"


def test_sensor_ignores_non_ip_packets():
    from scapy.all import Ether

    assert NetworkSensor().packet_to_event(Ether()) is None


def test_sensor_batches_events_before_pipeline():
    pipeline = RecordingPipeline()

    sensor = NetworkSensor(
        pipeline=pipeline,
        batch_size=2,
        flush_interval=999,
    )

    packet = tcp_packet()

    sensor.packet_handler(packet)
    sensor.packet_handler(packet)

    assert len(pipeline.batches) == 1
    assert len(pipeline.batches[0]) == 2

    sensor.packet_handler(packet)
    sensor._flush_pending()

    assert len(pipeline.batches) == 2
    assert sensor.packet_count == 3
    assert sensor.event_count == 3


def test_sensor_stop_is_immediate_and_status_reports_errors():
    sensor = NetworkSensor()

    sensor.stop()

    assert sensor._stop_event.is_set()

    sensor.last_error = "PermissionError: capture not permitted"

    status = sensor.status()

    assert status["last_error"] == "PermissionError: capture not permitted"
    assert status["pending_events"] == 0


# -------------------------------------------------------------------
# Threat intelligence
# -------------------------------------------------------------------

def test_private_and_invalid_addresses_are_not_looked_up(tmp_path):
    intel = ThreatIntel(
        database=SentryDatabase(str(tmp_path / "intel_private.db")),
        feed_path=tmp_path / "missing.json",
    )

    assert intel.enrich_ip("192.168.1.5")["status"] == "private"
    assert intel.enrich_ip("127.0.0.1")["status"] == "private"
    assert intel.enrich_ip("::1")["status"] == "private"
    assert intel.enrich_ip("not-an-ip")["status"] == "invalid"
    assert intel.enrich_ip(None)["status"] == "unknown"


def test_local_threat_feed_marks_confirmed_indicator(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(
        json.dumps(
            {
                "malicious_ips": ["45.33.32.156"],
                "suspicious_ips": ["45.33.32.157"],
            }
        ),
        encoding="utf-8",
    )

    database = SentryDatabase(str(tmp_path / "intel_feed.db"))
    intel = ThreatIntel(database=database, feed_path=feed)

    malicious = intel.enrich_ip("45.33.32.156")

    assert malicious["status"] == "malicious"
    assert malicious["source"] == "local_feed"

    suspicious = intel.enrich_ip("45.33.32.157")

    assert suspicious["status"] == "suspicious"

    cached = intel.enrich_ip("45.33.32.156")

    assert cached["status"] == "malicious"
    assert cached["last_checked"] == malicious["last_checked"]


def test_unknown_indicator_is_reported_as_unknown(tmp_path):
    intel = ThreatIntel(
        database=SentryDatabase(str(tmp_path / "intel_unknown.db")),
        feed_path=tmp_path / "missing.json",
    )

    entry = intel.enrich_ip("8.8.8.8")

    assert entry["status"] == "unknown"
    assert entry["source"] is None
    assert "not evidence" in entry["details"]


# -------------------------------------------------------------------
# Anomaly layer
# -------------------------------------------------------------------

def test_anomaly_detector_flags_deviation_from_baseline():
    detector = AnomalyDetector()

    normal = [
        SecurityEvent(
            timestamp=BASE,
            source="network",
            event_type="connection",
            source_ip=f"192.0.2.{i}",
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="TCP",
        )
        for i in range(1, 7)
    ]

    baseline = detector.update_baseline(None, normal)

    assert baseline["count"] == 6

    anomalous = [
        SecurityEvent(
            timestamp=BASE + timedelta(seconds=i),
            source="network",
            event_type="connection",
            source_ip="45.33.32.156",
            destination_ip=f"10.0.0.{i % 5}",
            destination_port=1000 + i,
            protocol="TCP",
        )
        for i in range(20)
    ]

    findings = detector.detect(anomalous, baseline)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["source_ip"] == "45.33.32.156"
    assert finding["score"] > 0
    assert finding["model"]["name"] == "sentry-statistical-baseline"
    assert any(
        reason["feature"] == "event_count"
        for reason in finding["reasons"]
    )


def test_anomaly_detector_requires_a_baseline():
    detector = AnomalyDetector()

    assert detector.detect(
        failure_events("45.33.32.156", 5),
        None,
    ) == []

    tiny_baseline = {
        "count": 1,
        "mean": {"event_count": 1.0},
        "std": {"event_count": 0.0},
    }

    assert detector.detect(
        failure_events("45.33.32.156", 5),
        tiny_baseline,
    ) == []


# -------------------------------------------------------------------
# Notifications
# -------------------------------------------------------------------

def test_notifications_respect_severity_and_cooldown(tmp_path):
    sent = []

    database = SentryDatabase(str(tmp_path / "notify.db"))

    manager = NotificationManager(
        webhook_url="https://example.invalid/hook",
        min_severity="HIGH",
        cooldown_seconds=300,
        transport=lambda payload: sent.append(payload) or 200,
    )

    high = Alert(
        alert_type="SSH Brute Force",
        severity="HIGH",
        source_ip="45.33.32.156",
        detail="high severity",
        timestamp=BASE,
        rule_id="SSH-BRUTE-001",
    )

    low = Alert(
        alert_type="Path Traversal Attempt",
        severity="LOW",
        source_ip="45.33.32.156",
        detail="low severity",
        timestamp=BASE,
        rule_id="WEB-TRAVERSAL-001",
    )

    results = manager.notify([high, low], database)

    assert len(results) == 1
    assert sent[0]["rule_id"] == "SSH-BRUTE-001"
    assert sent[0]["severity"] == "HIGH"

    # Immediate repeat is suppressed by the cooldown.
    assert manager.notify([high], database) == []


def test_notifications_are_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv("SENTRY_WEBHOOK_URL", raising=False)

    manager = NotificationManager(webhook_url="")

    assert manager.enabled is False
    assert manager.notify([], None) == []


# -------------------------------------------------------------------
# Database support features
# -------------------------------------------------------------------

def test_audit_log_records_status_and_investigation_changes(tmp_path):
    database = SentryDatabase(str(tmp_path / "audit.db"))

    database.save_alert(
        Alert(
            alert_type="SQL Injection Attempt",
            severity="CRITICAL",
            source_ip="192.0.2.99",
            detail="audited alert",
            timestamp=BASE,
            rule_id="WEB-SQLI-001",
        )
    )

    database.update_alert_status(1, "INVESTIGATING")
    database.update_investigation(1, "notes", "action")

    actions = {
        row["action"]
        for row in database.get_audit_log()
    }

    assert "ALERT_STATUS_CHANGED" in actions
    assert "ALERT_INVESTIGATION_UPDATED" in actions


def test_intel_cache_and_ml_baseline_round_trip(tmp_path):
    database = SentryDatabase(str(tmp_path / "support.db"))

    database.set_intel_cache(
        {
            "ip": "8.8.8.8",
            "status": "unknown",
            "source": None,
            "score": None,
            "details": "no data",
            "last_checked": "2026-01-01T00:00:00",
        }
    )

    assert database.get_intel_cache("8.8.8.8")["status"] == "unknown"

    baseline = {
        "count": 3,
        "mean": {"event_count": 1.0},
        "std": {"event_count": 0.0},
    }

    database.set_ml_baseline(baseline)

    assert database.get_ml_baseline()["count"] == 3


# -------------------------------------------------------------------
# Pipeline integration
# -------------------------------------------------------------------

def test_pipeline_enriches_alerts_with_threat_intel(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "pipeline_intel.db")
    )

    assert pipeline.anomaly_enabled is False

    alerts = pipeline.process_events(
        failure_events("45.33.32.156", 5)
    )

    assert alerts
    assert alerts[0].threat_intel is not None
    assert alerts[0].threat_intel["status"] == "unknown"

    row = pipeline.database.get_recent_alerts(limit=1)[0]

    stored = pipeline.database.get_alert_threat_intel(row["id"])

    assert stored["status"] == "unknown"
    assert stored["last_checked"]


def test_pipeline_anomaly_layer_produces_explained_alert(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "pipeline_ml.db"),
        anomaly_enabled=True,
    )

    normal = [
        SecurityEvent(
            timestamp=BASE,
            source="network",
            event_type="connection",
            source_ip=f"192.0.2.{i}",
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="TCP",
        )
        for i in range(1, 7)
    ]

    pipeline.process_events(normal)
    pipeline.process_events(normal)

    anomalous = [
        SecurityEvent(
            timestamp=BASE + timedelta(seconds=i),
            source="network",
            event_type="connection",
            source_ip="45.33.32.156",
            destination_ip=f"10.0.0.{i % 5}",
            destination_port=1000 + i,
            protocol="TCP",
        )
        for i in range(20)
    ]

    alerts = pipeline.process_events(anomalous)

    ml_alerts = [
        alert
        for alert in alerts
        if alert.rule_id == "ML-ANOMALY-001"
    ]

    assert len(ml_alerts) == 1

    evidence = ml_alerts[0].evidence

    assert evidence["model"]["name"] == "sentry-statistical-baseline"
    assert evidence["anomaly_score"] > 0
    assert evidence["features"]["event_count"] == 20
    assert evidence["reasons"]
    assert evidence["confidence"]["score"] is None
    assert "not probabilities" in evidence["confidence"]["basis"]
