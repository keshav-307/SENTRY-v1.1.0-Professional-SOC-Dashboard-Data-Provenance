"""Tests for encoded and mixed-encoding path traversal detection."""

from datetime import datetime

import pytest

from core.database import SentryDatabase
from core.detector import DetectionEngine
from core.models import SecurityEvent


BASE_TIME = datetime(2026, 6, 1, 9, 0, 0)

ATTACK_PATHS = [
    "/download?file=../../etc/passwd",
    "/download?file=..\\windows\\system32",
    "/f?p=%2e%2e%2fetc%2fpasswd",
    "/f?p=%2e%2e%5cwindows%5csystem32",
    "/f?p=..%2f..%2fetc%2fpasswd",
    "/f?p=..%2F",
    "/f?p=..%5c",
    "/f?p=..%252f",
    "/f?p=..%252F..%255cwindows",
    "/f?p=..%2f..\\etc",
    "/f?p=%2e%2e/..\\etc",
    "/f?p=%2E%2E%2F",
    "/f?p=%2E%2E%5C",
    "/f?p=%2E%2E%2F%2E%2E%5Cwindows",
]

BENIGN_PATHS = [
    "/docs/guide..html",
    "/download?file=report..pdf",
    "/files/version.2/final",
    "/assets/2024-2025/report",
]


def make_engine(tmp_path):
    database = SentryDatabase(str(tmp_path / "traversal.db"))
    return DetectionEngine(database=database)


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


def traversal_alerts(engine, path, source_ip="203.0.113.50"):
    return [
        alert
        for alert in engine.detect([web_event(path, source_ip=source_ip)])
        if alert.rule_id == "WEB-TRAVERSAL-001"
    ]


@pytest.mark.parametrize("path", ATTACK_PATHS)
def test_encoded_traversal_patterns_alert(tmp_path, path):
    engine = make_engine(tmp_path)

    alerts = traversal_alerts(engine, path)

    assert len(alerts) == 1, path
    alert = alerts[0]
    evidence = alert.evidence

    assert alert.rule_id == "WEB-TRAVERSAL-001"
    assert alert.severity == "HIGH"
    assert alert.confidence == 0.97
    assert evidence["mitre"]["technique_id"] == "T1083"
    assert evidence["mitre"]["tactic"] == "Discovery"
    assert evidence["request_path"] == path
    assert evidence["matched_pattern"]
    assert evidence["triggering_event_count"] == 1
    assert evidence["triggering_events"][0]["path"] == path
    assert evidence["conditions"][0]["result"] == "MET"
    assert "web root" in evidence["explanation"]
    assert evidence["recommended_actions"]


@pytest.mark.parametrize("path", BENIGN_PATHS)
def test_benign_dot_sequences_do_not_alert(tmp_path, path):
    engine = make_engine(tmp_path)

    assert traversal_alerts(engine, path) == []


@pytest.mark.parametrize("source_ip", ["203.0.113.50", "2001:db8::1"])
def test_encoded_traversal_preserves_source_ip(tmp_path, source_ip):
    engine = make_engine(tmp_path)

    alerts = traversal_alerts(engine, "/f?p=..%2f..%2fetc%2fpasswd", source_ip=source_ip)

    assert len(alerts) == 1
    assert alerts[0].source_ip == source_ip
    assert alerts[0].evidence["source_ip"] == source_ip


def test_double_encoded_path_records_decoded_evidence(tmp_path):
    engine = make_engine(tmp_path)

    alerts = traversal_alerts(engine, "/f?p=..%252f..%252fetc%252fpasswd")

    assert len(alerts) == 1
    evidence = alerts[0].evidence
    assert evidence["request_path"] == "/f?p=..%252f..%252fetc%252fpasswd"
    assert evidence["decoded_path"] == "/f?p=../../etc/passwd"


def test_literal_path_has_no_decoded_evidence(tmp_path):
    engine = make_engine(tmp_path)

    alerts = traversal_alerts(engine, "/download?file=../../etc/passwd")

    assert len(alerts) == 1
    assert alerts[0].evidence["decoded_path"] is None


def test_multiple_traversal_signatures_produce_one_alert(tmp_path):
    engine = make_engine(tmp_path)

    alerts = traversal_alerts(engine, "/f?p=..%2f..\\..%252fetc")

    assert len(alerts) == 1


def test_encoded_traversal_does_not_double_decode_benign_input(tmp_path):
    engine = make_engine(tmp_path)

    # A literal percent sequence that is not traversal must stay benign.
    assert traversal_alerts(engine, "/search?q=100%25%2b%2b") == []
