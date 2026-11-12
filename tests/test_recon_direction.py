import sqlite3
from datetime import datetime, timedelta

from scapy.all import DNS, DNSQR, IP, IPv6, TCP, UDP

from core.database import SentryDatabase
from core.detector import DetectionEngine
from core.models import SecurityEvent
from sensors.network_sensor import NetworkSensor


BASE_TIME = datetime(2026, 5, 1, 12, 0, 0)

LOCAL_IPV4 = "192.168.29.40"
LOCAL_IPV6 = "2405:201:5500:5974:bc3b:a26e:9f5c:e8ef"

CDN_IPV4 = "172.64.146.73"
GATEWAY_IPV6 = "2405:201:5500:5974::c0a8:1d01"
SCANNER_IPV4 = "203.0.113.77"
SCANNER_IPV6 = "2001:db8:bad::77"


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def make_engine(database_path):
    database = SentryDatabase(str(database_path))
    return DetectionEngine(database=database), database


def connection_event(
    source_ip,
    destination_port,
    timestamp,
    destination_ip="203.0.113.10",
    source_port=50000,
    initiated=True,
    direction="unknown",
    protocol="TCP",
):
    return SecurityEvent(
        timestamp=timestamp,
        source="network",
        event_type="connection",
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        direction=direction,
        initiated=initiated,
    )


def recon_alerts(alerts):
    return [
        alert
        for alert in alerts
        if alert.rule_id == "NET-RECON-001"
    ]


class StubInterface:
    """Minimal stand-in for a Scapy interface."""

    name = "stub0"
    description = "Stub interface"
    ip = LOCAL_IPV4
    ips = {4: [LOCAL_IPV4], 6: [LOCAL_IPV6, "fe80::1"]}


# -------------------------------------------------------------------
# Regression: bidirectional traffic must not look like reconnaissance
# -------------------------------------------------------------------

def test_bidirectional_cdn_traffic_does_not_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "cdn.db")

    events = []

    # Local client connects out to the CDN on 443 from ephemeral ports.
    for i in range(5):
        events.append(
            connection_event(
                LOCAL_IPV4,
                443,
                BASE_TIME + timedelta(seconds=i),
                destination_ip=CDN_IPV4,
                source_port=51920 + i,
                initiated=True,
                direction="outbound",
            )
        )

    # CDN replies to twelve different local ephemeral ports. Before the
    # fix this produced a NET-RECON alert naming the CDN as the scanner.
    for i, port in enumerate(
        (51920, 51927, 51943, 51952, 51957, 51960,
         51982, 51991, 52002, 63874, 51999, 52011)
    ):
        events.append(
            connection_event(
                CDN_IPV4,
                port,
                BASE_TIME + timedelta(seconds=10 + i),
                destination_ip=LOCAL_IPV4,
                source_port=443,
                initiated=False,
                direction="inbound",
            )
        )

    assert recon_alerts(engine.detect(events)) == []


def test_gateway_reply_traffic_does_not_alert_ipv6(tmp_path):
    engine, _ = make_engine(tmp_path / "gateway6.db")

    events = [
        connection_event(
            GATEWAY_IPV6,
            port,
            BASE_TIME + timedelta(seconds=i),
            destination_ip=LOCAL_IPV6,
            source_port=443,
            initiated=False,
            direction="inbound",
        )
        for i, port in enumerate(
            (49202, 50738, 51033, 55004, 55424, 56931,
             57847, 60239, 60977, 61476, 63362, 63413)
        )
    ]

    assert recon_alerts(engine.detect(events)) == []


def test_local_ephemeral_ports_are_not_counted_for_remote_hosts(tmp_path):
    engine, _ = make_engine(tmp_path / "ephemeral.db")

    events = [
        connection_event(
            CDN_IPV4,
            port,
            BASE_TIME + timedelta(seconds=i),
            destination_ip=LOCAL_IPV4,
            source_port=443,
            initiated=False,
            direction="inbound",
        )
        for i, port in enumerate(range(50000, 50012))
    ]

    # One real initiation from the CDN is not enough to reach threshold.
    events.append(
        connection_event(
            CDN_IPV4,
            443,
            BASE_TIME + timedelta(seconds=20),
            destination_ip=LOCAL_IPV4,
            source_port=51920,
            initiated=True,
            direction="inbound",
        )
    )

    assert recon_alerts(engine.detect(events)) == []


# -------------------------------------------------------------------
# Genuine scanning must still be detected
# -------------------------------------------------------------------

def test_inbound_port_scan_alerts(tmp_path):
    engine, _ = make_engine(tmp_path / "inbound_scan.db")

    events = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            destination_ip=LOCAL_IPV4,
            source_port=40000 + i,
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(20, 32))
    ]

    alerts = recon_alerts(engine.detect(events))

    assert len(alerts) == 1

    evidence = alerts[0].evidence

    assert evidence["mitre"]["technique_id"] == "T1046"
    assert evidence["threshold"] == 10
    assert evidence["unique_port_count"] == 12
    assert sorted(evidence["unique_destination_ports"]) == list(
        range(20, 32)
    )
    assert evidence["connection_initiations"] == 12
    assert evidence["direction_counts"] == {"inbound": 12}
    assert evidence["triggering_event_count"] == 12
    assert all(
        event["initiated"] is True
        for event in evidence["triggering_events"]
    )


def test_outbound_scan_from_local_host_alerts(tmp_path):
    engine, _ = make_engine(tmp_path / "outbound_scan.db")

    events = [
        connection_event(
            LOCAL_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            destination_ip=SCANNER_IPV4,
            source_port=52000 + i,
            initiated=True,
            direction="outbound",
        )
        for i, port in enumerate(range(20, 32))
    ]

    alerts = recon_alerts(engine.detect(events))

    assert len(alerts) == 1
    assert alerts[0].source_ip == LOCAL_IPV4
    assert alerts[0].evidence["direction_counts"] == {"outbound": 12}


def test_ipv6_scan_alerts(tmp_path):
    engine, _ = make_engine(tmp_path / "scan6.db")

    events = [
        connection_event(
            SCANNER_IPV6,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            destination_ip=LOCAL_IPV6,
            source_port=41000 + i,
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(80, 92))
    ]

    alerts = recon_alerts(engine.detect(events))

    assert len(alerts) == 1
    assert alerts[0].source_ip == SCANNER_IPV6
    assert alerts[0].evidence["unique_port_count"] == 12


def test_udp_first_contact_counts_but_udp_replies_do_not(tmp_path):
    initiation_engine, _ = make_engine(tmp_path / "udp_scan.db")

    initiations = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            destination_ip=LOCAL_IPV4,
            source_port=45000 + i,
            initiated=True,
            direction="inbound",
            protocol="UDP",
        )
        for i, port in enumerate(range(500, 512))
    ]

    assert len(recon_alerts(initiation_engine.detect(initiations))) == 1

    reply_engine, _ = make_engine(tmp_path / "udp_replies.db")

    replies = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            destination_ip=LOCAL_IPV4,
            source_port=53,
            initiated=False,
            direction="inbound",
            protocol="UDP",
        )
        for i, port in enumerate(range(50000, 50012))
    ]

    assert recon_alerts(reply_engine.detect(replies)) == []


# -------------------------------------------------------------------
# Preserved behaviour: threshold, window, dedup, legacy events
# -------------------------------------------------------------------

def test_threshold_is_still_ten(tmp_path):
    below_engine, _ = make_engine(tmp_path / "below.db")

    below = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=i),
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(20, 29))
    ]

    assert recon_alerts(below_engine.detect(below)) == []

    exact_engine, _ = make_engine(tmp_path / "exact.db")

    exact = [
        connection_event(
            "203.0.113.78",
            port,
            BASE_TIME + timedelta(seconds=i),
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(20, 30))
    ]

    assert len(recon_alerts(exact_engine.detect(exact))) == 1


def test_window_is_still_120_seconds(tmp_path):
    engine, _ = make_engine(tmp_path / "window.db")

    events = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=20 * i),
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(20, 32))
    ]

    assert recon_alerts(engine.detect(events)) == []


def test_initiated_alert_is_deduplicated(tmp_path):
    engine, _ = make_engine(tmp_path / "dedup.db")

    events = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            initiated=True,
            direction="inbound",
        )
        for i, port in enumerate(range(20, 32))
    ]

    assert len(recon_alerts(engine.detect(events))) == 1
    assert recon_alerts(engine.detect(events)) == []


def test_legacy_events_without_direction_still_alert(tmp_path):
    engine, _ = make_engine(tmp_path / "legacy.db")

    events = [
        connection_event(
            SCANNER_IPV4,
            port,
            BASE_TIME + timedelta(seconds=2 * i),
            initiated=None,
            direction=None,
        )
        for i, port in enumerate(range(20, 32))
    ]

    alerts = recon_alerts(engine.detect(events))

    assert len(alerts) == 1
    assert alerts[0].evidence["direction_counts"] == {"unknown": 12}


# -------------------------------------------------------------------
# Database: migration and metadata round-trip
# -------------------------------------------------------------------

def test_migration_adds_direction_columns_and_preserves_rows(tmp_path):
    path = tmp_path / "legacy_schema.db"

    connection = sqlite3.connect(path)
    cursor = connection.cursor()

    cursor.execute(
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
            raw TEXT
        )
        """
    )

    cursor.execute(
        """
        INSERT INTO events (
            timestamp, source, event_type, source_ip
        ) VALUES (?, ?, ?, ?)
        """,
        ("2026-01-01T00:00:00", "network", "connection", CDN_IPV4),
    )

    cursor.execute(
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

    cursor.execute(
        """
        INSERT INTO alerts (
            alert_type, severity, timestamp, rule_id, status
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            "Network Reconnaissance",
            "HIGH",
            "2026-01-01T00:00:00",
            "NET-RECON-001",
            "OPEN",
        ),
    )

    connection.commit()
    connection.close()

    SentryDatabase(str(path))

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row

    event_columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(events)")
    ]
    alert_columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(alerts)")
    ]

    assert "direction" in event_columns
    assert "initiated" in event_columns
    assert "evidence_json" in alert_columns

    assert connection.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0] == 1
    assert connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0] == 1

    row = connection.execute(
        "SELECT direction, initiated FROM events"
    ).fetchone()

    assert row["direction"] is None
    assert row["initiated"] is None

    connection.close()


def test_direction_metadata_round_trips_through_database(tmp_path):
    database = SentryDatabase(str(tmp_path / "roundtrip.db"))

    database.save_events(
        [
            connection_event(
                LOCAL_IPV4,
                443,
                BASE_TIME,
                destination_ip=CDN_IPV4,
                initiated=True,
                direction="outbound",
            ),
            connection_event(
                CDN_IPV4,
                51920,
                BASE_TIME + timedelta(seconds=1),
                destination_ip=LOCAL_IPV4,
                source_port=443,
                initiated=False,
                direction="inbound",
            ),
        ]
    )

    rows = database.get_recent_events(limit=2)

    by_direction = {
        row["direction"]: row for row in rows
    }

    assert by_direction["outbound"]["initiated"] == 1
    assert by_direction["inbound"]["initiated"] == 0


# -------------------------------------------------------------------
# Sensor: direction and initiation metadata
# -------------------------------------------------------------------

def test_sensor_marks_outbound_syn_as_initiation():
    sensor = NetworkSensor(interface=StubInterface())

    packet = (
        IP(src=LOCAL_IPV4, dst=CDN_IPV4)
        / TCP(sport=51920, dport=443, flags="S")
    )

    event = sensor.packet_to_event(packet)

    assert event.direction == "outbound"
    assert event.initiated is True


def test_sensor_marks_inbound_syn_ack_as_non_initiation():
    sensor = NetworkSensor(interface=StubInterface())

    packet = (
        IP(src=CDN_IPV4, dst=LOCAL_IPV4)
        / TCP(sport=443, dport=51920, flags="SA")
    )

    event = sensor.packet_to_event(packet)

    assert event.direction == "inbound"
    assert event.initiated is False


def test_sensor_marks_inbound_syn_as_initiation():
    sensor = NetworkSensor(interface=StubInterface())

    packet = (
        IP(src=SCANNER_IPV4, dst=LOCAL_IPV4)
        / TCP(sport=40000, dport=22, flags="S")
    )

    event = sensor.packet_to_event(packet)

    assert event.direction == "inbound"
    assert event.initiated is True


def test_sensor_direction_supports_ipv6():
    sensor = NetworkSensor(interface=StubInterface())

    outbound = (
        IPv6(src=LOCAL_IPV6, dst="2606:4700::1")
        / TCP(sport=51000, dport=443, flags="S")
    )
    inbound = (
        IPv6(src="2606:4700::1", dst=LOCAL_IPV6)
        / TCP(sport=443, dport=51000, flags="SA")
    )

    outbound_event = sensor.packet_to_event(outbound)
    inbound_event = sensor.packet_to_event(inbound)

    assert outbound_event.direction == "outbound"
    assert outbound_event.initiated is True
    assert inbound_event.direction == "inbound"
    assert inbound_event.initiated is False


def test_sensor_udp_first_packet_is_initiation_and_repeat_is_not():
    sensor = NetworkSensor(interface=StubInterface())

    query = (
        IP(src=LOCAL_IPV4, dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )
    reply = (
        IP(src="8.8.8.8", dst=LOCAL_IPV4)
        / UDP(sport=53, dport=53000)
    )

    first = sensor.packet_to_event(query)
    second = sensor.packet_to_event(query)
    answer = sensor.packet_to_event(reply)

    assert first.initiated is True
    assert second.initiated is False
    assert answer.initiated is False
    assert answer.direction == "inbound"


def test_sensor_marks_dns_query_events_with_direction():
    sensor = NetworkSensor(interface=StubInterface())

    packet = (
        IP(src=LOCAL_IPV4, dst="8.8.8.8")
        / UDP(sport=53001, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    event = sensor.packet_to_event(packet)

    assert event.event_type == "dns_query"
    assert event.path == "example.com"
    assert event.direction == "outbound"
    assert event.initiated is True


def test_sensor_resolves_local_addresses_from_interface():
    sensor = NetworkSensor(interface=StubInterface())

    addresses = sensor._resolve_local_addresses()

    assert LOCAL_IPV4 in addresses
    assert LOCAL_IPV6 in addresses
    assert "fe80::1" in addresses
    assert "127.0.0.1" in addresses
    assert "::1" in addresses


def test_sensor_falls_back_to_interface_ip_without_ips_attribute():
    class LegacyInterface:
        name = "legacy0"
        ip = LOCAL_IPV4

    sensor = NetworkSensor(interface=LegacyInterface())

    addresses = sensor._resolve_local_addresses()

    assert LOCAL_IPV4 in addresses
    assert "127.0.0.1" in addresses
