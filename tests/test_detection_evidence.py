import json
import sqlite3
from datetime import datetime, timedelta

from core.database import SentryDatabase
from core.detector import DetectionEngine, RULE_METADATA
from core.generator import EventGenerator
from core.models import Alert, SecurityEvent
from core.pipeline import SentryPipeline


BASE_TIME = datetime(2026, 1, 1, 12, 0, 0)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def make_engine(database_path):
    database = SentryDatabase(str(database_path))
    return DetectionEngine(database=database), database


def auth_event(event_type, source_ip, timestamp, username="admin"):
    return SecurityEvent(
        timestamp=timestamp,
        source="authentication",
        event_type=event_type,
        source_ip=source_ip,
        username=username,
    )


def web_event(
    path,
    timestamp,
    source_ip="203.0.113.5",
    method="GET",
    status=200,
):
    return SecurityEvent(
        timestamp=timestamp,
        source="web",
        event_type="web_request",
        source_ip=source_ip,
        method=method,
        path=path,
        status=status,
    )


def network_event(
    source_ip,
    destination_port,
    timestamp,
    destination_ip="10.0.0.5",
):
    return SecurityEvent(
        timestamp=timestamp,
        source="network",
        event_type="connection",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=40000 + destination_port,
        destination_port=destination_port,
        protocol="TCP",
    )


def brute_force_events(
    source_ip="198.51.100.7",
    attempts=5,
    spacing=10,
    start=BASE_TIME,
):
    return [
        auth_event(
            "login_failure",
            source_ip,
            start + timedelta(seconds=spacing * i),
        )
        for i in range(attempts)
    ]


# -------------------------------------------------------------------
# Model
# -------------------------------------------------------------------

def test_alert_evidence_is_optional_and_backwards_compatible():
    alert = Alert(
        alert_type="SQL Injection Attempt",
        severity="CRITICAL",
        source_ip="192.0.2.10",
        detail="legacy construction",
        timestamp=BASE_TIME,
        rule_id="WEB-SQLI-001",
    )

    assert alert.evidence is None
    assert alert.confidence == 1.0
    assert alert.to_dict()["evidence"] is None


# -------------------------------------------------------------------
# SSH brute force
# -------------------------------------------------------------------

def test_ssh_brute_force_evidence(tmp_path):
    engine, _ = make_engine(tmp_path / "ssh.db")

    alerts = engine.detect(brute_force_events())

    assert len(alerts) == 1

    alert = alerts[0]
    evidence = alert.evidence

    assert alert.rule_id == "SSH-BRUTE-001"
    assert evidence["rule_id"] == "SSH-BRUTE-001"
    assert evidence["rule_name"] == "SSH Brute Force"
    assert evidence["rule_description"]
    assert evidence["mitre"]["technique_id"] == "T1110"
    assert evidence["source_ip"] == "198.51.100.7"
    assert evidence["threshold"] == 5
    assert evidence["observed_failures"] == 5
    assert evidence["window"]["seconds"] == 120
    assert evidence["triggering_event_count"] == 5
    assert len(evidence["triggering_events"]) == 5
    assert all(
        event["event_type"] == "login_failure"
        for event in evidence["triggering_events"]
    )
    assert evidence["conditions"][0]["result"] == "MET"
    assert "brute-force" in evidence["explanation"]
    assert evidence["recommended_actions"]

    # Evidence must be JSON serializable.
    assert json.loads(json.dumps(evidence))


def test_ssh_brute_force_below_threshold_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "ssh_below.db")

    assert engine.detect(brute_force_events(attempts=4)) == []


def test_ssh_brute_force_outside_window_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "ssh_window.db")

    # 5 failures spread over 124 seconds: no 120-second window holds 5.
    events = brute_force_events(attempts=5, spacing=31)

    assert engine.detect(events) == []


def test_ssh_brute_force_requires_source_ip(tmp_path):
    engine, _ = make_engine(tmp_path / "ssh_no_ip.db")

    events = [
        auth_event("login_failure", None, BASE_TIME + timedelta(seconds=i))
        for i in range(6)
    ]

    assert engine.detect(events) == []


def test_repeated_detection_calls_are_deduplicated(tmp_path):
    engine, _ = make_engine(tmp_path / "repeat.db")

    events = brute_force_events()

    first = engine.detect(events)
    second = engine.detect(events)

    # SSH alerts now use persistent deduplication: reprocessing the same
    # burst inside the cooldown must not create a second alert.
    assert len(first) == 1
    assert len(second) == 0


# -------------------------------------------------------------------
# Web signatures
# -------------------------------------------------------------------

def test_sql_injection_evidence(tmp_path):
    engine, _ = make_engine(tmp_path / "sqli.db")

    event = web_event(
        "/login?username=' OR '1'='1",
        BASE_TIME,
        status=500,
    )

    alerts = engine.detect([event])

    assert len(alerts) == 1

    alert = alerts[0]
    evidence = alert.evidence

    assert alert.rule_id == "WEB-SQLI-001"
    assert evidence["mitre"]["technique_id"] == "T1190"
    assert evidence["matched_pattern"]
    assert evidence["request_path"] == event.path
    assert evidence["triggering_event_count"] == 1
    assert evidence["triggering_events"][0]["path"] == event.path
    assert evidence["triggering_events"][0]["status"] == 500
    assert evidence["conditions"][0]["result"] == "MET"
    assert "not expected in normal application input" in evidence["explanation"]


def test_path_traversal_evidence(tmp_path):
    engine, _ = make_engine(tmp_path / "traversal.db")

    event = web_event(
        "/download?file=../../etc/passwd",
        BASE_TIME,
        status=400,
    )

    alerts = engine.detect([event])

    assert len(alerts) == 1

    alert = alerts[0]
    evidence = alert.evidence

    assert alert.rule_id == "WEB-TRAVERSAL-001"
    assert evidence["mitre"]["technique_id"] == "T1083"
    assert evidence["matched_pattern"]
    assert evidence["triggering_events"][0]["status"] == 400
    assert "web root" in evidence["explanation"]


def test_benign_web_requests_do_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "benign.db")

    events = [
        web_event("/products", BASE_TIME),
        web_event("/api/users", BASE_TIME + timedelta(seconds=5)),
    ]

    assert engine.detect(events) == []


def test_web_events_without_source_ip_are_detected_without_crashing(tmp_path):
    engine, _ = make_engine(tmp_path / "web_no_ip.db")

    event = web_event(
        "/search?q=' UNION SELECT password FROM users--",
        BASE_TIME,
        source_ip=None,
    )

    alerts = engine.detect([event])

    assert len(alerts) == 1
    assert alerts[0].source_ip is None
    assert alerts[0].evidence["source_ip"] is None


# -------------------------------------------------------------------
# Successful login after brute force
# -------------------------------------------------------------------

def test_auth_compromise_evidence(tmp_path):
    engine, _ = make_engine(tmp_path / "auth.db")

    source_ip = "198.51.100.9"
    username = "root"

    events = brute_force_events(
        source_ip=source_ip,
    )

    for event in events:
        event.username = username

    events.append(
        auth_event(
            "login_success",
            source_ip,
            events[-1].timestamp + timedelta(seconds=15),
            username=username,
        )
    )

    alerts = engine.detect(events)

    compromise = [
        alert
        for alert in alerts
        if alert.rule_id == "AUTH-COMPROMISE-001"
    ]

    assert len(compromise) == 1

    evidence = compromise[0].evidence

    assert evidence["mitre"]["technique_id"] == "T1078"
    assert evidence["threshold"] == 5
    assert evidence["failure_count"] == 5
    assert evidence["triggering_event_count"] == 6
    assert evidence["successful_login"]["event_type"] == "login_success"
    assert evidence["triggering_events"][-1]["event_type"] == "login_success"
    # The recorded window is the observed span from the first failure to
    # the successful login (5 failures 10s apart, then +15s).
    assert evidence["window"]["seconds"] == 55


def test_auth_success_without_enough_failures_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "auth_below.db")

    events = brute_force_events(attempts=4)

    events.append(
        auth_event(
            "login_success",
            "198.51.100.7",
            events[-1].timestamp + timedelta(seconds=5),
        )
    )

    assert engine.detect(events) == []


# -------------------------------------------------------------------
# Network reconnaissance
# -------------------------------------------------------------------

def test_network_reconnaissance_evidence(tmp_path):
    engine, _ = make_engine(tmp_path / "recon.db")

    events = [
        network_event(
            "203.0.113.77",
            port,
            BASE_TIME + timedelta(seconds=5 * i),
        )
        for i, port in enumerate(range(20, 32))
    ]

    alerts = engine.detect(events)

    recon = [
        alert
        for alert in alerts
        if alert.rule_id == "NET-RECON-001"
    ]

    assert len(recon) == 1

    evidence = recon[0].evidence

    assert evidence["mitre"]["technique_id"] == "T1046"
    assert evidence["threshold"] == 10
    assert evidence["unique_port_count"] == 12
    assert sorted(evidence["unique_destination_ports"]) == list(
        range(20, 32)
    )
    assert evidence["protocols"] == ["TCP"]
    assert evidence["triggering_event_count"] == 12
    assert evidence["window"]["seconds"] == 120


def test_network_reconnaissance_below_threshold_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "recon_below.db")

    events = [
        network_event(
            "203.0.113.79",
            port,
            BASE_TIME + timedelta(seconds=5 * i),
        )
        for i, port in enumerate(range(20, 29))
    ]

    assert engine.detect(events) == []


def test_network_events_without_destination_port_do_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "recon_no_port.db")

    events = [
        SecurityEvent(
            timestamp=BASE_TIME + timedelta(seconds=i),
            source="network",
            event_type="connection",
            source_ip="203.0.113.80",
            destination_ip="10.0.0.5",
            protocol="IP",
        )
        for i in range(12)
    ]

    assert engine.detect(events) == []


def test_network_reconnaissance_is_deduplicated(tmp_path):
    engine, _ = make_engine(tmp_path / "recon_dedup.db")

    events = [
        network_event(
            "203.0.113.78",
            port,
            BASE_TIME + timedelta(seconds=5 * i),
        )
        for i, port in enumerate(range(20, 32))
    ]

    assert len(engine.detect(events)) == 1
    assert engine.detect(events) == []


def test_network_reconnaissance_outside_window_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "recon_window.db")

    events = [
        network_event(
            "203.0.113.81",
            port,
            BASE_TIME + timedelta(seconds=20 * i),
        )
        for i, port in enumerate(range(20, 32))
    ]

    assert engine.detect(events) == []


# -------------------------------------------------------------------
# Persistence and migration
# -------------------------------------------------------------------

def test_evidence_round_trips_through_database(tmp_path):
    engine, database = make_engine(tmp_path / "persist.db")

    alerts = engine.detect(brute_force_events())

    database.save_alerts(alerts)

    row = database.get_recent_alerts(limit=1)[0]

    assert row["evidence_json"]

    evidence = database.get_alert_evidence(row["id"])

    assert evidence["rule_id"] == "SSH-BRUTE-001"
    assert evidence["threshold"] == 5
    assert evidence["recommended_actions"]

    analysis = database.get_investigation(row["id"])

    assert analysis["analyst_notes"] is None
    assert analysis["recommended_action"] is None


def test_legacy_alert_without_evidence_remains_readable(tmp_path):
    database = SentryDatabase(str(tmp_path / "legacy.db"))

    alert = Alert(
        alert_type="SQL Injection Attempt",
        severity="CRITICAL",
        source_ip="192.0.2.10",
        detail="historical alert",
        timestamp=BASE_TIME,
        rule_id="WEB-SQLI-001",
    )

    database.save_alert(alert)

    row = database.get_recent_alerts(limit=1)[0]

    assert row["status"] == "OPEN"
    assert row["evidence_json"] is None
    assert database.get_alert_evidence(row["id"]) is None
    assert database.get_alert_count() == 1


def test_malformed_evidence_is_handled_safely(tmp_path):
    database = SentryDatabase(str(tmp_path / "malformed.db"))

    database.save_alert(
        Alert(
            alert_type="SQL Injection Attempt",
            severity="CRITICAL",
            source_ip="192.0.2.11",
            detail="bad evidence",
            timestamp=BASE_TIME,
            rule_id="WEB-SQLI-001",
        )
    )

    connection = database.get_connection()
    connection.execute(
        "UPDATE alerts SET evidence_json = ? WHERE id = 1",
        ("{not valid json",),
    )
    connection.commit()
    connection.close()

    assert database.get_alert_evidence(1) is None


def test_migration_adds_evidence_column_without_data_loss(tmp_path):
    path = tmp_path / "old_schema.db"

    connection = sqlite3.connect(path)

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
            recommended_action TEXT
        )
        """
    )

    connection.execute(
        """
        INSERT INTO alerts (
            alert_type, severity, source_ip, detail,
            timestamp, rule_id, confidence, status,
            analyst_notes, recommended_action
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "SQL Injection Attempt",
            "CRITICAL",
            "192.0.2.55",
            "pre-existing alert",
            BASE_TIME.isoformat(),
            "WEB-SQLI-001",
            0.99,
            "INVESTIGATING",
            "existing notes",
            "existing action",
        ),
    )

    connection.commit()
    connection.close()

    database = SentryDatabase(str(path))

    cursor = database.get_connection().cursor()
    cursor.execute("PRAGMA table_info(alerts)")
    columns = [row["name"] for row in cursor.fetchall()]

    assert "evidence_json" in columns
    assert database.get_alert_count() == 1

    row = database.get_recent_alerts(limit=1)[0]

    assert row["status"] == "INVESTIGATING"
    assert row["analyst_notes"] == "existing notes"
    assert row["recommended_action"] == "existing action"
    assert database.get_alert_evidence(row["id"]) is None


# -------------------------------------------------------------------
# Pipeline
# -------------------------------------------------------------------

def test_pipeline_shares_database_instance_and_path(tmp_path):
    database_path = tmp_path / "custom.db"

    pipeline = SentryPipeline(
        database_path=str(database_path)
    )

    assert pipeline.detector.database is pipeline.database
    assert str(pipeline.database.database_path) == str(database_path)
    assert database_path.exists()


def test_pipeline_persists_evidence_and_detection_state(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "pipeline.db")
    )

    events = [
        network_event(
            "203.0.113.90",
            port,
            BASE_TIME + timedelta(seconds=5 * i),
        )
        for i, port in enumerate(range(20, 32))
    ]

    alerts = pipeline.process_events(events)

    assert len(alerts) == 1

    row = pipeline.database.get_recent_alerts(limit=1)[0]

    assert pipeline.database.get_alert_evidence(row["id"])["rule_id"] == (
        "NET-RECON-001"
    )

    assert pipeline.database.get_detection_state(
        "NET-RECON-001",
        "203.0.113.90",
    ) is not None


def test_generated_campaign_produces_explained_alerts(tmp_path):
    pipeline = SentryPipeline(
        database_path=str(tmp_path / "campaign.db")
    )

    events = EventGenerator().generate(
        scenario="mixed",
        intensity="high",
    )

    alerts = pipeline.process_events(events)

    rule_ids = {alert.rule_id for alert in alerts}

    assert {
        "SSH-BRUTE-001",
        "WEB-SQLI-001",
        "WEB-TRAVERSAL-001",
        "AUTH-COMPROMISE-001",
    }.issubset(rule_ids)

    for alert in alerts:
        assert alert.evidence is not None
        assert alert.evidence["rule_id"] == alert.rule_id
        assert alert.evidence["rule_id"] in RULE_METADATA
        assert alert.evidence["explanation"]
        assert alert.evidence["triggering_events"]

    stored = pipeline.database.get_recent_alerts(limit=100)

    assert len(stored) == len(alerts)

    for row in stored:
        evidence = pipeline.database.get_alert_evidence(row["id"])

        assert evidence is not None
        assert evidence["rule_id"] == row["rule_id"]
