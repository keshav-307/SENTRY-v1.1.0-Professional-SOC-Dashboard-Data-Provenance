"""Persistent alert deduplication and cooldown tests."""

import sqlite3
from datetime import datetime, timedelta

import pytest

from core.database import SentryDatabase
from core.detector import DetectionEngine
from core.models import SecurityEvent
from core.pipeline import SentryPipeline


BASE = datetime(2026, 6, 1, 9, 0, 0)
COOLDOWNS = {
    "SSH-BRUTE-001": 300,
    "WEB-SQLI-001": 300,
    "WEB-TRAVERSAL-001": 300,
    "AUTH-COMPROMISE-001": 900,
}


def auth(event_type, source_ip, timestamp, username="root"):
    return SecurityEvent(
        timestamp=timestamp,
        source="authentication",
        event_type=event_type,
        source_ip=source_ip,
        username=username,
    )


def web(path, timestamp, source_ip="203.0.113.50"):
    return SecurityEvent(
        timestamp=timestamp,
        source="web",
        event_type="web_request",
        source_ip=source_ip,
        method="GET",
        path=path,
        status=200,
    )


def network(source_ip, port, timestamp, initiated=True):
    return SecurityEvent(
        timestamp=timestamp,
        source="network",
        event_type="connection",
        source_ip=source_ip,
        destination_ip="10.0.0.5",
        source_port=40000,
        destination_port=port,
        protocol="TCP",
        direction="inbound",
        initiated=initiated,
    )


def ssh_events(source_ip="198.51.100.7", username="root", base=BASE):
    return [
        auth("login_failure", source_ip, base + timedelta(seconds=10 * i), username)
        for i in range(5)
    ]


def auth_compromise_events(source_ip="198.51.100.9", username="root", base=BASE):
    events = [
        auth("login_failure", source_ip, base + timedelta(seconds=10 * i), username)
        for i in range(5)
    ]
    events.append(
        auth("login_success", source_ip, base + timedelta(seconds=55), username)
    )
    return events


def sqli_events(path="/login?username=' OR '1'='1", source_ip="203.0.113.50", base=BASE):
    return [web(path, base, source_ip)]


def traversal_events(
    path="/f?p=..%2f..%2fetc%2fpasswd",
    source_ip="203.0.113.60",
    base=BASE,
):
    return [web(path, base, source_ip)]


BUILDERS = {
    "SSH-BRUTE-001": ssh_events,
    "WEB-SQLI-001": sqli_events,
    "WEB-TRAVERSAL-001": traversal_events,
    "AUTH-COMPROMISE-001": auth_compromise_events,
}


def make_engine(path):
    return DetectionEngine(database=SentryDatabase(str(path)))


def rule_alerts(engine, events, rule_id):
    return [alert for alert in engine.detect(events) if alert.rule_id == rule_id]


def alert_count(db_path, rule_id=None):
    connection = sqlite3.connect(db_path)
    try:
        if rule_id:
            return connection.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = ?",
                (rule_id,),
            ).fetchone()[0]
        return connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    finally:
        connection.close()


def event_count(db_path):
    connection = sqlite3.connect(db_path)
    try:
        return connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        connection.close()


@pytest.mark.parametrize("rule_id", list(BUILDERS))
def test_first_detection_then_suppression_and_cooldown_expiry(tmp_path, rule_id):
    db_path = tmp_path / "dedup.db"
    engine = make_engine(db_path)
    builder = BUILDERS[rule_id]

    assert len(rule_alerts(engine, builder(), rule_id)) == 1
    assert rule_alerts(engine, builder(), rule_id) == []

    restarted = make_engine(db_path)
    assert rule_alerts(restarted, builder(), rule_id) == []

    cooldown = COOLDOWNS[rule_id]
    later = builder(base=BASE + timedelta(seconds=cooldown + 1))
    assert len(rule_alerts(restarted, later, rule_id)) == 1


@pytest.mark.parametrize("rule_id", list(BUILDERS))
def test_pipeline_restart_suppression_preserves_events(tmp_path, rule_id):
    db_path = tmp_path / "pipeline.db"
    builder = BUILDERS[rule_id]
    events = builder()

    first = SentryPipeline(database_path=str(db_path))
    first.process_events(list(events))

    second = SentryPipeline(database_path=str(db_path))
    second.process_events(list(events))

    assert alert_count(str(db_path), rule_id) == 1
    assert event_count(str(db_path)) == len(events) * 2


@pytest.mark.parametrize("rule_id", list(BUILDERS))
def test_different_source_ip_is_not_merged(tmp_path, rule_id):
    db_path = tmp_path / "ip.db"
    engine = make_engine(db_path)
    builder = BUILDERS[rule_id]

    original_ip = builder()[0].source_ip
    assert len(rule_alerts(engine, builder(), rule_id)) == 1
    assert len(
        rule_alerts(engine, builder(source_ip="198.51.100.200"), rule_id)
    ) == 1
    assert original_ip != "198.51.100.200"


def test_ssh_different_account_is_not_merged(tmp_path):
    engine = make_engine(tmp_path / "ssh_account.db")

    assert len(rule_alerts(engine, ssh_events(username="root"), "SSH-BRUTE-001")) == 1
    assert (
        len(rule_alerts(engine, ssh_events(username="deploy"), "SSH-BRUTE-001")) == 1
    )


def test_sqli_different_endpoint_is_not_merged(tmp_path):
    engine = make_engine(tmp_path / "sqli_endpoint.db")

    assert (
        len(
            rule_alerts(
                engine,
                sqli_events(path="/login?username=' OR '1'='1"),
                "WEB-SQLI-001",
            )
        )
        == 1
    )
    assert (
        len(
            rule_alerts(
                engine,
                sqli_events(path="/admin?id=1 UNION SELECT a FROM b"),
                "WEB-SQLI-001",
            )
        )
        == 1
    )


def test_sqli_same_endpoint_and_signature_is_suppressed(tmp_path):
    engine = make_engine(tmp_path / "sqli_same.db")

    assert len(rule_alerts(engine, sqli_events(), "WEB-SQLI-001")) == 1
    assert (
        rule_alerts(
            engine,
            sqli_events(path="/login?username=' OR '2'='2"),
            "WEB-SQLI-001",
        )
        == []
    )


def test_sqli_same_endpoint_different_signature_is_not_merged(tmp_path):
    engine = make_engine(tmp_path / "sqli_signature.db")

    assert len(rule_alerts(engine, sqli_events(), "WEB-SQLI-001")) == 1
    assert (
        len(
            rule_alerts(
                engine,
                sqli_events(path="/login?q=1 UNION SELECT a FROM b"),
                "WEB-SQLI-001",
            )
        )
        == 1
    )


def test_traversal_different_target_is_not_merged(tmp_path):
    engine = make_engine(tmp_path / "trav_target.db")

    assert (
        len(
            rule_alerts(
                engine,
                traversal_events(path="/f?p=..%2f..%2fetc%2fpasswd"),
                "WEB-TRAVERSAL-001",
            )
        )
        == 1
    )
    assert (
        len(
            rule_alerts(
                engine,
                traversal_events(path="/f?p=..%2f..%2fvar%2flog"),
                "WEB-TRAVERSAL-001",
            )
        )
        == 1
    )


def test_auth_compromise_different_account_is_not_merged(tmp_path):
    engine = make_engine(tmp_path / "auth_account.db")

    assert (
        len(
            rule_alerts(
                engine, auth_compromise_events(username="root"), "AUTH-COMPROMISE-001"
            )
        )
        == 1
    )
    assert (
        len(
            rule_alerts(
                engine, auth_compromise_events(username="backup"), "AUTH-COMPROMISE-001"
            )
        )
        == 1
    )


def test_cooldown_boundary_is_inclusive_then_expires(tmp_path):
    engine = make_engine(tmp_path / "boundary.db")

    assert len(rule_alerts(engine, sqli_events(base=BASE), "WEB-SQLI-001")) == 1
    assert (
        rule_alerts(
            engine,
            sqli_events(base=BASE + timedelta(seconds=300)),
            "WEB-SQLI-001",
        )
        == []
    )
    assert (
        len(
            rule_alerts(
                engine,
                sqli_events(base=BASE + timedelta(seconds=301)),
                "WEB-SQLI-001",
            )
        )
        == 1
    )


def test_out_of_order_batch_is_suppressed_without_moving_cooldown(tmp_path):
    db_path = tmp_path / "out_of_order.db"
    engine = make_engine(db_path)

    assert (
        len(
            rule_alerts(
                engine,
                sqli_events(base=BASE + timedelta(seconds=100)),
                "WEB-SQLI-001",
            )
        )
        == 1
    )
    assert (
        rule_alerts(engine, sqli_events(base=BASE), "WEB-SQLI-001") == []
    )

    connection = sqlite3.connect(str(db_path))
    try:
        row = connection.execute(
            "SELECT last_alert_timestamp, suppressed_count FROM alert_dedup "
            "WHERE rule_id = 'WEB-SQLI-001'"
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    assert row[0] == (BASE + timedelta(seconds=100)).isoformat()
    assert row[1] == 1


def test_suppression_updates_metadata_but_not_alert_status(tmp_path):
    db_path = tmp_path / "status.db"
    events = ssh_events()

    pipeline = SentryPipeline(database_path=str(db_path))
    pipeline.process_events(list(events))

    alert = [
        row
        for row in pipeline.database.get_recent_alerts(limit=10)
        if row["rule_id"] == "SSH-BRUTE-001"
    ][0]
    pipeline.database.update_alert_status(alert["id"], "RESOLVED")

    pipeline.process_events(list(events))

    current = pipeline.database.get_alert_by_id(alert["id"])
    assert current["status"] == "RESOLVED"

    connection = sqlite3.connect(str(db_path))
    try:
        row = connection.execute(
            "SELECT suppressed_count, last_seen_timestamp, last_alert_timestamp "
            "FROM alert_dedup WHERE rule_id = 'SSH-BRUTE-001'"
        ).fetchone()
    finally:
        connection.close()

    assert row[0] == 1
    assert row[1] is not None
    assert row[2] == BASE.isoformat() or row[2] == (
        BASE + timedelta(seconds=40)
    ).isoformat()


def test_short_cooldown_allows_alert_after_ten_seconds(tmp_path):
    engine = DetectionEngine(
        database=SentryDatabase(str(tmp_path / "config2.db")),
        rules_config={"WEB-SQLI-001": {"dedup_cooldown_seconds": 10}},
    )

    assert len(rule_alerts(engine, sqli_events(base=BASE), "WEB-SQLI-001")) == 1
    assert rule_alerts(
        engine, sqli_events(base=BASE + timedelta(seconds=10)), "WEB-SQLI-001"
    ) == []
    assert len(
        rule_alerts(
            engine,
            sqli_events(base=BASE + timedelta(seconds=11)),
            "WEB-SQLI-001",
        )
    ) == 1


def test_network_recon_suppression_and_window_expiry(tmp_path):
    engine = make_engine(tmp_path / "recon.db")
    scan = [network("203.0.113.77", port, BASE + timedelta(seconds=2 * i)) for i, port in enumerate(range(20, 32))]

    assert len(rule_alerts(engine, scan, "NET-RECON-001")) == 1
    assert rule_alerts(engine, scan, "NET-RECON-001") == []

    later = [
        network("203.0.113.77", port, BASE + timedelta(seconds=121 + 2 * i))
        for i, port in enumerate(range(20, 32))
    ]
    assert len(rule_alerts(engine, later, "NET-RECON-001")) == 1


def test_network_recon_ignores_replies_during_dedup(tmp_path):
    engine = make_engine(tmp_path / "recon_replies.db")
    replies = [
        network("172.64.146.73", 50000 + i, BASE + timedelta(seconds=i), initiated=False)
        for i in range(12)
    ]

    assert rule_alerts(engine, replies, "NET-RECON-001") == []
