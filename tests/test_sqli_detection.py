"""Tests for contextual SQL injection detection and false-positive control."""

from datetime import datetime

import pytest

from core.database import SentryDatabase
from core.detector import DetectionEngine
from core.models import SecurityEvent


BASE_TIME = datetime(2026, 6, 1, 9, 0, 0)

BENIGN_URLS = [
    "/products?search=select from catalog",
    "/help?q=how to select from menu",
    "/blog/post--draft",
    "/orders?note=well--known",
    "/articles/2024--2025-summary",
]

BENIGN_SQL_WORD_URLS = [
    "/search?q=select+from+catalog",
    "/search?q=union+station+schedule",
    "/docs/sql/select-statement",
    "/guide/select-and-from-clauses",
    "/blog/drop-table-manners",
    "/download?file=report--final",
    "/users?name=O'Reilly",
    "/faq/what-is-a-where-clause",
]

ATTACK_URLS = [
    # Previously successful payloads
    "/login?username=' OR '1'='1",
    "/item?id=1 UNION SELECT password FROM users",
    "/p?x=1 OR 1=1",
    "/admin?q=; DROP TABLE users",
    # Other injection structures
    "/login?user=admin'--",
    "/search?q=x+union+all+select+1,2,3--",
    "/account?id=1 AND 1=1",
    "/?name=' OR 'x'='x",
    "/?q=' SELECT username, password FROM users",
    "/x?id=1; DELETE FROM users",
    "/x?id=1'--",
    "/login?u=AdMiN' Or '1'='1",
    # Encoded payloads
    "/login?u=%27%20OR%201%3D1",
    "/item?id=1%20UNION%20SELECT%20password%20FROM%20users",
    "/login?u=admin%27--",
]


def make_engine(tmp_path):
    return DetectionEngine(database=SentryDatabase(str(tmp_path / "sqli.db")))


def web_event(path, source_ip="203.0.113.50"):
    return SecurityEvent(
        timestamp=BASE_TIME,
        source="web",
        event_type="web_request",
        source_ip=source_ip,
        method="GET",
        path=path,
        status=200,
    )


def sqli_alerts(engine, path, source_ip="203.0.113.50"):
    return [
        alert
        for alert in engine.detect([web_event(path, source_ip=source_ip)])
        if alert.rule_id == "WEB-SQLI-001"
    ]


@pytest.mark.parametrize("path", BENIGN_URLS)
def test_known_benign_urls_do_not_alert(tmp_path, path):
    engine = make_engine(tmp_path)

    assert sqli_alerts(engine, path) == []


@pytest.mark.parametrize("path", BENIGN_SQL_WORD_URLS)
def test_sql_words_in_ordinary_urls_do_not_alert(tmp_path, path):
    engine = make_engine(tmp_path)

    assert sqli_alerts(engine, path) == []


@pytest.mark.parametrize("path", ATTACK_URLS)
def test_sql_injection_payloads_alert(tmp_path, path):
    engine = make_engine(tmp_path)

    alerts = sqli_alerts(engine, path)

    assert len(alerts) == 1, path
    alert = alerts[0]
    evidence = alert.evidence

    assert alert.rule_id == "WEB-SQLI-001"
    assert alert.severity == "CRITICAL"
    assert alert.confidence == 0.99
    assert alert.source_ip == "203.0.113.50"
    assert evidence["mitre"]["technique_id"] == "T1190"
    assert evidence["mitre"]["tactic"] == "Initial Access"
    assert evidence["request_path"] == path
    assert evidence["matched_pattern"]
    assert evidence["triggering_event_count"] == 1
    assert evidence["triggering_events"][0]["path"] == path
    assert evidence["conditions"][0]["result"] == "MET"
    assert "not expected in normal application input" in evidence["explanation"]
    assert evidence["recommended_actions"]
    assert evidence["window"]["seconds"] == 0


@pytest.mark.parametrize("source_ip", ["203.0.113.50", "2001:db8::1"])
def test_sqli_preserves_source_ip(tmp_path, source_ip):
    engine = make_engine(tmp_path)

    alerts = sqli_alerts(engine, "/login?username=' OR '1'='1", source_ip=source_ip)

    assert len(alerts) == 1
    assert alerts[0].source_ip == source_ip
    assert alerts[0].evidence["source_ip"] == source_ip


def test_encoded_payload_records_decoded_evidence(tmp_path):
    engine = make_engine(tmp_path)

    alerts = sqli_alerts(engine, "/login?u=%27%20OR%201%3D1")

    assert len(alerts) == 1
    assert alerts[0].evidence["request_path"] == "/login?u=%27%20OR%201%3D1"
    assert alerts[0].evidence["decoded_path"] == "/login?u=' OR 1=1"


def test_literal_payload_has_no_decoded_evidence(tmp_path):
    engine = make_engine(tmp_path)

    alerts = sqli_alerts(engine, "/login?username=' OR '1'='1")

    assert len(alerts) == 1
    assert alerts[0].evidence["decoded_path"] is None


def test_multiple_signatures_produce_one_alert(tmp_path):
    engine = make_engine(tmp_path)

    alerts = sqli_alerts(
        engine,
        "/x?id=1' OR 1=1 UNION SELECT password FROM users--",
    )

    assert len(alerts) == 1


def test_non_web_events_do_not_trigger(tmp_path):
    engine = make_engine(tmp_path)

    event = SecurityEvent(
        timestamp=BASE_TIME,
        source="authentication",
        event_type="login_failure",
        source_ip="203.0.113.50",
        username="' OR '1'='1",
    )

    assert [
        alert for alert in engine.detect([event]) if alert.rule_id == "WEB-SQLI-001"
    ] == []
