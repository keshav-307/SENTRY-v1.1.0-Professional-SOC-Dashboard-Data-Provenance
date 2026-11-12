from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


@dataclass
class SecurityEvent:
    """
    Represents one normalized security event.
    """

    timestamp: datetime
    source: str
    event_type: str

    # Where this event came from:
    #   "SYNTHETIC" - produced by SENTRY's built-in event generator
    #   "LIVE"      - captured from real network traffic
    #   "UNKNOWN"   - historical rows whose origin cannot be established
    # None means the producer did not state an origin; the dashboard
    # presents that as UNKNOWN.
    event_origin: Optional[str] = None

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    protocol: Optional[str] = None

    username: Optional[str] = None

    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None

    # Authentication result.
    # Examples: "success", "failure"
    outcome: Optional[str] = None

    # Direction of this packet relative to the local host:
    # "outbound", "inbound", "local", "unknown".
    # None means the producer did not provide direction information
    # (legacy events, synthetic data).
    direction: Optional[str] = None

    # True when this packet begins a connection: a TCP SYN without
    # ACK, or the first packet of a UDP flow. False for replies and
    # mid-stream packets. None means unknown (legacy/synthetic).
    initiated: Optional[bool] = None

    raw: Optional[str] = None

    def to_dict(self):
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class Alert:
    alert_type: str
    severity: str
    source_ip: Optional[str]
    detail: str
    timestamp: datetime
    rule_id: str
    confidence: float = 1.0
    evidence: Optional[dict] = None

    # Origin of the events that produced this alert.
    # SYNTHETIC, LIVE, or UNKNOWN for historical alerts.
    event_origin: Optional[str] = None

    # Threat intelligence enrichment for the alert's source IP.
    # Populated by the pipeline; None means enrichment was not run.
    threat_intel: Optional[dict] = None

    def to_dict(self):
        data = asdict(self)
        data["timestamp"] = data["timestamp"].isoformat()
        return data