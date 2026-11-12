from datetime import datetime, timezone
from urllib.parse import unquote

from core.models import SecurityEvent


class EventNormalizer:
    """
    Converts external security events into SENTRY's
    internal SecurityEvent format.
    """

    WEB_SOURCES = {
        "web",
        "web_server",
        "nginx",
        "apache",
        "http_server",
    }

    WEB_EVENT_TYPES = {
        "web_request",
        "http_request",
        "http_access",
        "access_log",
        "web_access",
    }

    AUTH_SOURCES = {
        "authentication",
        "linux",
        "windows",
        "auth",
        "ssh",
    }

    AUTH_EVENT_TYPES = {
        "authentication",
        "auth",
        "login",
        "login_attempt",
        "ssh_login",
    }

    def normalize(
        self,
        source,
        event_type,
        source_ip=None,
        destination_ip=None,
        source_port=None,
        destination_port=None,
        protocol=None,
        username=None,
        method=None,
        path=None,
        status=None,
        outcome=None,
        raw=None,
        timestamp=None,
    ):
        """
        Normalize an external event into a SecurityEvent.

        If an external timestamp is provided, SENTRY preserves it.

        If no timestamp is provided, SENTRY uses the current
        UTC ingestion time.
        """

        normalized_source = self._normalize_source(
            source=source,
            event_type=event_type,
        )

        normalized_event_type = self._normalize_event_type(
            source=source,
            event_type=event_type,
            outcome=outcome,
        )

        normalized_path = self._normalize_path(path)
        normalized_outcome = self._normalize_outcome(outcome)

        normalized_protocol = self._normalize_protocol(protocol)

        normalized_timestamp = self._normalize_timestamp(
            timestamp
        )

        return SecurityEvent(
            timestamp=normalized_timestamp,

            source=normalized_source,
            event_type=normalized_event_type,

            source_ip=source_ip,
            destination_ip=destination_ip,

            source_port=source_port,
            destination_port=destination_port,

            protocol=normalized_protocol,

            username=username,

            method=method,
            path=normalized_path,
            status=status,

            outcome=normalized_outcome,

            raw=raw,
        )

    def _normalize_source(self, source, event_type):
        source_value = source.strip().lower() if source else ""
        event_value = event_type.strip().lower() if event_type else ""

        if (
            source_value in self.WEB_SOURCES
            or event_value in self.WEB_EVENT_TYPES
        ):
            return "web"

        if (
            source_value in self.AUTH_SOURCES
            or event_value in self.AUTH_EVENT_TYPES
        ):
            return "authentication"

        if not source_value:
            return "unknown"

        return source_value

    def _normalize_event_type(self, source, event_type, outcome):
        source_value = source.strip().lower() if source else ""
        event_value = event_type.strip().lower() if event_type else ""

        if (
            source_value in self.WEB_SOURCES
            or event_value in self.WEB_EVENT_TYPES
        ):
            return "web_request"

        if (
            source_value in self.AUTH_SOURCES
            or event_value in self.AUTH_EVENT_TYPES
        ):
            normalized_outcome = self._normalize_outcome(
                outcome
            )

            if normalized_outcome == "failure":
                return "login_failure"

            if normalized_outcome == "success":
                return "login_success"

            return "authentication"

        if not event_value:
            return "unknown"

        return event_value

    def _normalize_outcome(self, outcome):
        if outcome is None:
            return None

        value = outcome.strip().lower()

        if value in {
            "failure",
            "failed",
            "fail",
            "denied",
            "error",
        }:
            return "failure"

        if value in {
            "success",
            "successful",
            "succeeded",
            "accepted",
            "allow",
            "allowed",
        }:
            return "success"

        return value

    def _normalize_protocol(self, protocol):
        """
        Normalize network protocol names.

        Examples:

        tcp -> TCP
        TCP -> TCP
        udp -> UDP
        http -> HTTP
        """

        if protocol is None:
            return None

        return protocol.strip().upper()

    def _normalize_path(self, path):
        if path is None:
            return None

        return unquote(path)

    def _normalize_timestamp(self, timestamp):
        """
        Normalize an event timestamp.

        External timestamps may be:

        - datetime objects
        - ISO 8601 strings
        - timezone-aware timestamps
        - timezone-naive timestamps

        SENTRY stores timestamps as UTC without timezone
        information so they remain compatible with the
        existing database and detection engine.
        """

        if timestamp is None:
            return self._current_timestamp()

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        if not isinstance(timestamp, datetime):
            raise TypeError(
                "timestamp must be a datetime, ISO 8601 string, or None"
            )

        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(
                timezone.utc
            ).replace(tzinfo=None)

        return timestamp

    def _current_timestamp(self):
        """
        Generate a UTC timestamp.

        Used when an external event does not provide
        its original event timestamp.
        """

        return datetime.now(timezone.utc).replace(
            tzinfo=None
        )