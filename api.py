from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel, Field

from core.normalizer import EventNormalizer
from core.pipeline import SentryPipeline


app = FastAPI(
    title="SENTRY Security Monitoring API",
    description="API for submitting security events to SENTRY.",
    version="1.1.0",
)


class SecurityEventRequest(BaseModel):
    timestamp: datetime | None = Field(
        default=None,
        description="Original event timestamp in ISO 8601 format",
    )
    source: str = Field(
        ...,
        description="Origin of the event",
    )

    event_type: str = Field(
        ...,
        description="Type of security event",
    )

    source_ip: str | None = Field(
        default=None,
        description="Source IP address",
    )

    destination_ip: str | None = Field(
        default=None,
        description="Destination IP address",
    )

    source_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source network port",
    )

    destination_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination network port",
    )

    protocol: str | None = Field(
        default=None,
        description="Network protocol such as TCP, UDP, ICMP",
    )

    username: str | None = Field(
        default=None,
        description="Username involved in the event",
    )

    method: str | None = Field(
        default=None,
        description="HTTP method",
    )

    path: str | None = Field(
        default=None,
        description="HTTP request path",
    )

    status: int | None = Field(
        default=None,
        description="HTTP response status",
    )

    outcome: str | None = Field(
        default=None,
        description="Authentication outcome such as success or failure",
    )


class SecurityEventBatchRequest(BaseModel):
    events: list[SecurityEventRequest] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Security events to process",
    )


normalizer = EventNormalizer()

pipeline = SentryPipeline()


def normalize_event(event: SecurityEventRequest):
    """
    Convert an API request into SENTRY's internal
    SecurityEvent representation.
    """

    return normalizer.normalize(
        source=event.source,
        event_type=event.event_type,

        timestamp=event.timestamp,

        source_ip=event.source_ip,
        destination_ip=event.destination_ip,

        source_port=event.source_port,
        destination_port=event.destination_port,

        protocol=event.protocol,

        username=event.username,

        method=event.method,
        path=event.path,
        status=event.status,

        outcome=event.outcome,

        raw=None,
    )


@app.get("/")
def root():
    return {
        "service": "SENTRY Security Monitoring API",
        "status": "online",
        "version": "1.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/events")
def receive_event(event: SecurityEventRequest):
    """
    Receive and process a single security event.
    """

    normalized_event = normalize_event(event)

    alerts = pipeline.process_events(
        [normalized_event]
    )

    return {
        "message": "Security event processed",
        "event": normalized_event.to_dict(),
        "alerts_generated": len(alerts),
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }


@app.post("/api/events/batch")
def receive_event_batch(
    request: SecurityEventBatchRequest,
):
    """
    Receive and process multiple security events.
    """

    normalized_events = [
        normalize_event(event)
        for event in request.events
    ]

    alerts = pipeline.process_events(
        normalized_events
    )

    return {
        "message": "Security event batch processed",
        "events_received": len(normalized_events),
        "alerts_generated": len(alerts),
        "events": [
            event.to_dict()
            for event in normalized_events
        ],
        "alerts": [
            alert.to_dict()
            for alert in alerts
        ],
    }