import sqlite3
from datetime import datetime, timedelta

from scapy.all import DNS, IP, TCP, UDP, DNSQR

from core.database import SentryDatabase
from core.generator import EventGenerator
from core.models import Alert, SecurityEvent
from core.pipeline import SentryPipeline
from sensors.network_sensor import NetworkSensor


# -------------------------------------------------------------------
# Generator labelling
# -------------------------------------------------------------------

def test_all_generator_scenarios_are_marked_synthetic():
    generator = EventGenerator()

    scenarios = [
        "normal",
        "ssh_brute_force",
        "sql_injection",
        "path_traversal",
        "mixed",
    ]

    for scenario in scenarios:
        events = generator.generate(
            scenario=scenario,
            intensity="low",
        )

        assert events, scenario
        assert all(
            event.event_origin == "SYNTHETIC"
            for event in events
        ), scenario


def test_direct_generator_methods_are_marked_synthetic():
    generator = EventGenerator()

    for events in (
        generator.generate_normal_events(3),
        generator.generate_ssh_brute_force(3),
        generator.generate_sql_injection(3),
        generator.generate_path_traversal(3),
        generator.generate_mixed_attack_campaign(),
    ):
        assert events
        assert all(
            event.event_origin == "SYNTHETIC"
            for event in events
        )


# -------------------------------------------------------------------
# Network sensor labelling
# -------------------------------------------------------------------

def test_sensor_labels_connection_events_live():
    packet = (
        IP(src="192.0.2.10", dst="192.0.2.20")
        / TCP(sport=50000, dport=80, flags="S")
    )

    event = NetworkSensor().packet_to_event(packet)

    assert event is not None
    assert event.event_origin == "LIVE"


def test_sensor_labels_dns_events_live():
    packet = (
        IP(src="192.0.2.10", dst="8.8.8.8")
        / UDP(sport=5555, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    event = NetworkSensor().packet_to_event(packet)

    assert event is not None
    assert event.event_origin == "LIVE"


# -------------------------------------------------------------------
# Pipeline propagation
# -------------------------------------------------------------------

def test_pipeline_labels_synthetic_alerts(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "synthetic.db"),
        threat_intel=_NullIntel(),
    )

    events = EventGenerator().generate(
        scenario="ssh_brute_force",
        intensity="high",
    )

    alerts = pipeline.process_events(events)

    assert alerts
    assert all(
        alert.event_origin == "SYNTHETIC"
        for alert in alerts
    )

    stored = pipeline.database.get_recent_alerts(50)

    assert stored
    assert all(
        alert["event_origin"] == "SYNTHETIC"
        for alert in stored
    )


def test_pipeline_labels_live_alerts(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "live.db"),
        threat_intel=_NullIntel(),
    )

    now = datetime.now()
    events = [
        SecurityEvent(
            timestamp=now + timedelta(seconds=index),
            source="network",
            event_type="connection",
            source_ip="198.51.100.7",
            destination_ip="192.0.2.20",
            destination_port=1000 + index,
            protocol="TCP",
            event_origin="LIVE",
        )
        for index in range(12)
    ]

    alerts = pipeline.process_events(events)

    assert alerts
    assert all(
        alert.event_origin == "LIVE"
        for alert in alerts
    )


def test_pipeline_marks_mixed_origin_alerts_unknown(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "mixed.db"),
        threat_intel=_NullIntel(),
    )

    now = datetime.now()

    events = [
        SecurityEvent(
            timestamp=now + timedelta(seconds=index),
            source="network",
            event_type="connection",
            source_ip="203.0.113.5",
            destination_ip="192.0.2.20",
            destination_port=2000 + index,
            protocol="TCP",
            event_origin=(
                "SYNTHETIC" if index % 2 else "LIVE"
            ),
        )
        for index in range(12)
    ]

    alerts = pipeline.process_events(events)

    assert alerts
    assert all(
        alert.event_origin == "UNKNOWN"
        for alert in alerts
    )


# -------------------------------------------------------------------
# Database migration and filtering
# -------------------------------------------------------------------

def _create_legacy_database(path):
    connection = sqlite3.connect(path)

    connection.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            protocol TEXT,
            username TEXT,
            method TEXT,
            path TEXT,
            status INTEGER,
            outcome TEXT,
            direction TEXT,
            initiated INTEGER,
            raw TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            detail TEXT,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            confidence REAL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            analyst_notes TEXT,
            recommended_action TEXT,
            evidence_json TEXT,
            threat_intel_json TEXT
        )
        """
    )

    connection.execute(
        """
        INSERT INTO events (
            timestamp, source, event_type, source_ip
        ) VALUES (?, ?, ?, ?)
        """,
        (
            "2026-01-01T00:00:00",
            "network",
            "connection",
            "192.0.2.99",
        ),
    )

    connection.execute(
        """
        INSERT INTO alerts (
            alert_type, severity, source_ip, detail, timestamp,
            rule_id, confidence, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Legacy Alert",
            "HIGH",
            "192.0.2.99",
            "legacy row",
            "2026-01-01T00:00:00",
            "LEGACY-001",
            0.9,
            "OPEN",
        ),
    )

    connection.commit()
    connection.close()


def test_migration_adds_origin_columns_without_classifying_history(
    tmp_path,
):
    path = tmp_path / "legacy.db"
    _create_legacy_database(path)

    database = SentryDatabase(str(path))

    connection = database.get_connection()

    event_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(events)"
        )
    ]

    alert_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(alerts)"
        )
    ]

    connection.close()

    assert "event_origin" in event_columns
    assert "event_origin" in alert_columns

    event = database.get_recent_events(1)[0]
    alert = database.get_recent_alerts(1)[0]

    assert event["event_origin"] is None
    assert alert["event_origin"] is None

    event_counts = {
        row["origin"]: row["count"]
        for row in database.get_event_origin_counts()
    }

    alert_counts = {
        row["origin"]: row["count"]
        for row in database.get_alert_origin_counts()
    }

    assert event_counts == {"UNKNOWN": 1}
    assert alert_counts == {"UNKNOWN": 1}


def test_origin_migration_is_idempotent(tmp_path):
    path = tmp_path / "repeat.db"

    first = SentryDatabase(str(path))
    first.save_event(
        SecurityEvent(
            timestamp=datetime.now(),
            source="network",
            event_type="connection",
            source_ip="192.0.2.10",
            event_origin="LIVE",
        )
    )

    second = SentryDatabase(str(path))

    connection = second.get_connection()

    event_columns = [
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(events)"
        )
    ]

    connection.close()

    assert event_columns.count("event_origin") == 1
    assert second.get_event_count() == 1


def test_event_explorer_origin_filters(tmp_path):
    database = SentryDatabase(str(tmp_path / "filters.db"))

    now = datetime.now()

    for origin in ("LIVE", "SYNTHETIC", None):
        database.save_event(
            SecurityEvent(
                timestamp=now,
                source="network",
                event_type="connection",
                source_ip="192.0.2.10",
                event_origin=origin,
            )
        )

    assert database.count_events("All") == 3
    assert database.count_events("LIVE") == 1
    assert database.count_events("SYNTHETIC") == 1
    assert database.count_events("UNKNOWN") == 1

    live_rows = database.get_events_page("LIVE")
    unknown_rows = database.get_events_page("UNKNOWN")

    assert len(live_rows) == 1
    assert live_rows[0]["event_origin"] == "LIVE"
    assert len(unknown_rows) == 1
    assert unknown_rows[0]["event_origin"] is None


def test_dashboard_aggregate_queries(tmp_path):
    database = SentryDatabase(str(tmp_path / "aggregates.db"))
    now = datetime.now()

    database.save_event(
        SecurityEvent(
            timestamp=now,
            source="network",
            event_type="connection",
            source_ip="192.0.2.10",
            destination_port=443,
            event_origin="LIVE",
        )
    )
    database.save_event(
        SecurityEvent(
            timestamp=now,
            source="network",
            event_type="connection",
            source_ip="192.0.2.10",
            destination_port=443,
            event_origin="LIVE",
        )
    )
    database.save_event(
        SecurityEvent(
            timestamp=now,
            source="network",
            event_type="connection",
            source_ip="198.51.100.9",
            destination_port=22,
            event_origin="SYNTHETIC",
        )
    )

    database.save_alert(
        Alert(
            alert_type="Network Reconnaissance",
            severity="HIGH",
            source_ip="192.0.2.10",
            detail="aggregate test",
            timestamp=now,
            rule_id="NET-RECON-001",
            event_origin="LIVE",
        )
    )

    top_sources = database.get_top_source_ips(5)
    assert top_sources[0]["source_ip"] == "192.0.2.10"
    assert top_sources[0]["count"] == 2

    top_ports = database.get_top_destination_ports(5)
    assert top_ports[0]["destination_port"] == 443
    assert top_ports[0]["count"] == 2

    timeline = database.get_event_timeline(24)
    assert sum(row["count"] for row in timeline) == 3

    rules = database.get_rule_distribution(5)
    assert rules[0]["rule_id"] == "NET-RECON-001"
    assert rules[0]["count"] == 1


def test_origin_filter_normalisation():
    assert SentryDatabase.normalise_origin_filter("LIVE") == "LIVE"
    assert (
        SentryDatabase.normalise_origin_filter("SYNTHETIC")
        == "SYNTHETIC"
    )
    assert (
        SentryDatabase.normalise_origin_filter("All")
        == "UNKNOWN"
    )


class _NullIntel:
    """Deterministic, offline threat-intel stub for pipeline tests."""

    def enrich_ip(self, ip_address):
        return {
            "ip": ip_address,
            "status": "unknown",
            "source": None,
            "score": None,
            "details": None,
            "last_checked": datetime.now().isoformat(),
        }
