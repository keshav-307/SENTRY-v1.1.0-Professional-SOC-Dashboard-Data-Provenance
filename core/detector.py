import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

from core.database import SentryDatabase
from core.models import Alert, SecurityEvent


DEFAULT_RULES_CONFIG = {
    "SSH-BRUTE-001": {
        "enabled": True,
        "threshold": 5,
        "window_seconds": 120,
        "dedup_cooldown_seconds": 300,
    },
    "WEB-SQLI-001": {
        "enabled": True,
        "dedup_cooldown_seconds": 300,
    },
    "WEB-TRAVERSAL-001": {
        "enabled": True,
        "dedup_cooldown_seconds": 300,
    },
    "AUTH-COMPROMISE-001": {
        "enabled": True,
        "threshold": 5,
        "window_seconds": 120,
        "dedup_cooldown_seconds": 900,
    },
    "NET-RECON-001": {
        "enabled": True,
        "threshold": 10,
        "window_seconds": 120,
    },
    "DNS-SUSPICIOUS-001": {
        "enabled": True,
        "threshold": 20,
        "window_seconds": 60,
    },
}

DEFAULT_RULES_CONFIG_PATH = (
    Path(__file__).resolve().parent.parent
    / "config"
    / "detection_rules.json"
)


def load_rules_config(config=None):
    """
    Load detection rule settings.

    `config` may be None (load config/detection_rules.json when it
    exists), a path to a JSON file, or an already-loaded dict. Missing
    or invalid settings fall back to the documented defaults, so an
    operator cannot accidentally disable a rule by typo alone.
    """

    resolved = {
        rule_id: dict(values)
        for rule_id, values in DEFAULT_RULES_CONFIG.items()
    }

    loaded = {}

    if isinstance(config, dict):
        loaded = config
    else:
        path = Path(config) if config else DEFAULT_RULES_CONFIG_PATH

        if path.exists():
            try:
                loaded = json.loads(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                loaded = {}

    if isinstance(loaded, dict):
        for rule_id, values in loaded.items():
            if rule_id not in resolved:
                continue

            if not isinstance(values, dict):
                continue

            for key in (
                "enabled",
                "threshold",
                "window_seconds",
                "dedup_cooldown_seconds",
            ):
                if key in values:
                    resolved[rule_id][key] = values[key]

    return resolved


# Maximum number of triggering events copied into an alert's evidence.
# The evidence always records the true total as well.
MAX_TRIGGERING_EVENTS = 50


RULE_METADATA = {
    "SSH-BRUTE-001": {
        "name": "SSH Brute Force",
        "severity": "HIGH",
        "description": (
            "Detects repeated failed authentication attempts from the same "
            "source IP inside a rolling time window."
        ),
        "mitre": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force",
        },
        "recommended_actions": [
            "Block or rate-limit the source IP at the firewall.",
            "Confirm multi-factor authentication is enforced on the targeted account.",
            "Review successful logins from the same source after the burst.",
            "Rotate credentials for any targeted account.",
        ],
    },
    "WEB-SQLI-001": {
        "name": "SQL Injection Attempt",
        "severity": "CRITICAL",
        "description": (
            "Detects SQL syntax signatures in web request paths or query "
            "strings that are not part of normal application input."
        ),
        "mitre": {
            "tactic": "Initial Access",
            "technique_id": "T1190",
            "technique": "Exploit Public-Facing Application",
        },
        "recommended_actions": [
            "Verify the web application uses parameterized queries.",
            "Inspect the request and response for evidence of data access.",
            "Block the source IP if the request was not an authorized test.",
            "Review database logs for unexpected queries.",
        ],
    },
    "WEB-TRAVERSAL-001": {
        "name": "Path Traversal Attempt",
        "severity": "HIGH",
        "description": (
            "Detects parent-directory traversal sequences in web requests "
            "that attempt to escape the web root."
        ),
        "mitre": {
            "tactic": "Discovery",
            "technique_id": "T1083",
            "technique": "File and Directory Discovery",
        },
        "recommended_actions": [
            "Confirm the web server rejects raw and encoded traversal sequences.",
            "Check whether the requested file was served from outside the web root.",
            "Block the source IP if the request was not an authorized test.",
            "Review file access logs for the requested path.",
        ],
    },
    "AUTH-COMPROMISE-001": {
        "name": "Successful Login After Brute Force",
        "severity": "CRITICAL",
        "description": (
            "Detects a successful authentication immediately following the "
            "configured number of failed attempts from the same source IP."
        ),
        "mitre": {
            "tactic": "Initial Access",
            "technique_id": "T1078",
            "technique": "Valid Accounts",
        },
        "recommended_actions": [
            "Treat the account as compromised and force a password reset.",
            "Terminate active sessions for the account.",
            "Preserve the correlated failure and success events as incident evidence.",
            "Review what the account accessed after the login.",
        ],
    },
    "NET-RECON-001": {
        "name": "Network Reconnaissance",
        "severity": "HIGH",
        "description": (
            "Detects one source host contacting many different destination "
            "ports inside a rolling time window, consistent with a port scan."
        ),
        "mitre": {
            "tactic": "Discovery",
            "technique_id": "T1046",
            "technique": "Network Service Discovery",
        },
        "recommended_actions": [
            "Identify the scanning host and confirm whether the activity is authorized.",
            "Review firewall and IDS logs for follow-up exploitation attempts.",
            "Restrict unnecessary exposed services on the scanned host.",
            "Consider blocking the scanning host at the network boundary.",
        ],
    },
    "DNS-SUSPICIOUS-001": {
        "name": "Suspicious DNS Activity",
        "severity": "HIGH",
        "description": (
            "Detects one source resolving an unusually high number of "
            "unique domains inside a rolling time window."
        ),
        "mitre": {
            "tactic": "Command and Control",
            "technique_id": "T1071.004",
            "technique": "Application Layer Protocol: DNS",
        },
        "recommended_actions": [
            "Review the queried domains for encoded or random-looking names.",
            "Confirm the source host is not running unauthorized discovery or tunneling tools.",
            "Check DNS logs for NXDOMAIN bursts and long or unusual labels.",
            "Consider blocking the source host if the activity is not authorized.",
        ],
    },
}


class DetectionEngine:
    """
    SENTRY detection engine.

    Receives normalized SecurityEvent objects and produces
    security Alerts.

    Every alert carries structured evidence describing the rule that
    fired, the exact events and conditions that triggered it, and why
    that behaviour indicates suspicious activity.

    Detection state is persisted in SQLite so important
    correlation/deduplication state can survive application restarts.
    """

    def __init__(self, database=None, rules_config=None):
        # Use the supplied database when available.
        # Otherwise create the default SENTRY database connection.
        self.database = database or SentryDatabase()

        # Detection settings can be overridden by operators without
        # editing code. Defaults preserve the documented thresholds.
        self.rules_config = load_rules_config(rules_config)

        # Recent network events are kept in memory for fast
        # cross-request correlation during the current process.
        self.recent_network_events = []

        self.rules = {
            "SSH-BRUTE-001": {
                "name": "SSH Brute Force",
                "severity": "HIGH",
            },
            "WEB-SQLI-001": {
                "name": "SQL Injection Attempt",
                "severity": "CRITICAL",
            },
            "WEB-TRAVERSAL-001": {
                "name": "Path Traversal Attempt",
                "severity": "HIGH",
            },
            "AUTH-COMPROMISE-001": {
                "name": "Successful Login After Brute Force",
                "severity": "CRITICAL",
            },
            "NET-RECON-001": {
                "name": "Network Reconnaissance",
                "severity": "HIGH",
            },
        }

        self.rule_metadata = RULE_METADATA

        # SQL injection signatures require SQL context (quotes,
        # operators, statement separators or comments) so ordinary
        # prose containing words like "select" or "from", and double
        # hyphens in filenames, do not raise alerts.
        self.sqli_patterns = [
            # UNION-based injection
            r"(?i)\bunion\b[^&]{0,60}?\bselect\b",
            # Boolean tautologies: ' OR 1=1, 1 AND 1=1, ' OR '1'='1
            (
                r"(?i)(?:['\"`)]|\d)\s*(?:or|and)\s+"
                r"['\"]?(?:\d+|true)['\"]?\s*=\s*"
                r"['\"]?(?:\d+|true)\b"
            ),
            # Quote break into another boolean clause
            r"(?i)['\"]\s*(?:or|and)\s*['\"]",
            # Quote or stacked statement introducing a SQL verb
            (
                r"(?i)(?:['\"`]|;)\s*"
                r"(?:select|insert|update|delete|drop|alter|create)\b"
            ),
            # SELECT ... FROM with SQL context before it
            (
                r"(?i)(?:['\"`]|;|\bunion\b)[^&]{0,80}?"
                r"\bselect\b[^&]{0,80}?\bfrom\b"
            ),
            # SELECT ... FROM followed by quote, comment or comparison
            (
                r"(?i)\bselect\b[^&]{0,80}?\bfrom\b[^&]{0,80}?"
                r"(?:['\"`]|--|;|\bwhere\b\s+['\"]?\d+['\"]?\s*=)"
            ),
            # Destructive statements
            r"(?i)\bdrop\s+(?:table|database)\b",
            # SQL comment only after a quote, semicolon or SQL keyword
            (
                r"(?i)(?:['\"`);]|\b(?:select|union|where|having|"
                r"order\s+by|drop|insert|update|delete|or|and)\b"
                r"[^&\s]{0,25})\s*--"
            ),
        ]

        self.traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"%2e%2e%5c",
        ]

    def detect(self, events):
        """
        Run all SENTRY detection rules against a list of events.
        """

        alerts = []

        alerts.extend(self.detect_ssh_brute_force(events))
        alerts.extend(self.detect_sql_injection(events))
        alerts.extend(self.detect_path_traversal(events))
        alerts.extend(self.detect_success_after_brute_force(events))

        # Network correlation covers both connection metadata and DNS
        # queries. Individual rules filter the event types they use.
        network_events = [
            event
            for event in events
            if (
                event.source == "network"
                and event.event_type in (
                    "connection",
                    "dns_query",
                )
            )
        ]

        combined_network_events = (
            self.recent_network_events + network_events
        )

        alerts.extend(
            self.detect_network_reconnaissance(
                combined_network_events
            )
        )

        alerts.extend(
            self.detect_suspicious_dns(
                combined_network_events
            )
        )

        self._update_network_event_buffer(
            combined_network_events
        )

        alerts.sort(key=lambda alert: alert.timestamp)

        return alerts

    # ---------------------------------------------------------
    # SSH BRUTE FORCE
    # ---------------------------------------------------------

    def detect_ssh_brute_force(self, events):
        if not self._rule_enabled("SSH-BRUTE-001"):
            return []

        failures = defaultdict(list)

        for event in events:
            if (
                event.event_type == "login_failure"
                and event.source == "authentication"
                and event.source_ip
            ):
                failures[event.source_ip].append(event)

        alerts = []

        rule_config = self.rules_config["SSH-BRUTE-001"]
        threshold = rule_config["threshold"]
        window = timedelta(
            seconds=rule_config["window_seconds"]
        )

        for source_ip, attempts in failures.items():
            attempts.sort(key=lambda event: event.timestamp)

            for i in range(len(attempts)):
                window_start = attempts[i].timestamp
                window_end = window_start + window

                matching_attempts = [
                    event
                    for event in attempts[i:]
                    if event.timestamp <= window_end
                ]

                if len(matching_attempts) >= threshold:
                    observed_attempts = len(matching_attempts)

                    usernames = sorted(
                        {
                            event.username
                            for event in matching_attempts
                            if event.username
                        }
                    )

                    if self._is_duplicate_alert(
                        "SSH-BRUTE-001",
                        source_ip,
                        matching_attempts[-1].timestamp,
                        {"targeted_usernames": usernames},
                    ):
                        break

                    alerts.append(
                        Alert(
                            alert_type="SSH Brute Force",
                            severity="HIGH",
                            source_ip=source_ip,
                            detail=(
                                f"Detected {observed_attempts} failed "
                                f"authentication attempts within 2 minutes."
                            ),
                            timestamp=matching_attempts[-1].timestamp,
                            rule_id="SSH-BRUTE-001",
                            confidence=0.98,
                            evidence=self._build_evidence(
                                rule_id="SSH-BRUTE-001",
                                source_ip=source_ip,
                                summary=(
                                    f"{observed_attempts} failed authentication "
                                    f"attempts from {source_ip} within 2 minutes."
                                ),
                                explanation=(
                                    f"{observed_attempts} failed SSH authentication "
                                    f"attempts were observed from {source_ip} inside "
                                    f"the 120-second detection window. The rule "
                                    f"threshold is {threshold} failures, so the "
                                    f"volume and rate of failures are consistent "
                                    f"with an automated brute-force attempt."
                                ),
                                conditions=[
                                    {
                                        "condition": (
                                            "Failed authentication attempts from "
                                            "one source inside the window"
                                        ),
                                        "expected": f">= {threshold} failures",
                                        "observed": f"{observed_attempts} failures",
                                        "result": "MET",
                                    },
                                    {
                                        "condition": "Correlation window",
                                        "expected": "120 seconds",
                                        "observed": (
                                            f"{window_start.isoformat()} to "
                                            f"{window_end.isoformat()}"
                                        ),
                                        "result": "MET",
                                    },
                                    {
                                        "condition": "Targeted accounts",
                                        "expected": "any",
                                        "observed": (
                                            ", ".join(usernames)
                                            if usernames
                                            else "unknown"
                                        ),
                                        "result": "INFO",
                                    },
                                ],
                                window_start=window_start,
                                window_end=window_end,
                                triggering_events=matching_attempts,
                                confidence=0.98,
                                extra={
                                    "threshold": threshold,
                                    "observed_failures": observed_attempts,
                                    "targeted_usernames": usernames,
                                },
                            ),
                        )
                    )

                    self._remember_alert(
                        "SSH-BRUTE-001",
                        source_ip,
                        matching_attempts[-1].timestamp,
                        {"targeted_usernames": usernames},
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # SQL INJECTION
    # ---------------------------------------------------------

    def _matched_sqli_patterns(self, path, decoded_path=None):
        """
        Yield the first SQL injection signature matched by the request.

        The raw path and its bounded-decoded form are both checked so
        encoded payloads are detected, and matching stops after the
        first signature so one request produces at most one alert.
        """

        if decoded_path is None:
            decoded_path = self._decode_web_path(path)

        for candidate in dict.fromkeys((path, decoded_path)):
            for pattern in self.sqli_patterns:
                if re.search(pattern, candidate, re.IGNORECASE):
                    yield pattern
                    return

    def detect_sql_injection(self, events):
        if not self._rule_enabled("WEB-SQLI-001"):
            return []

        alerts = []

        for event in events:
            if event.source != "web":
                continue

            if event.event_type != "web_request":
                continue

            path = event.path or ""
            decoded_path = self._decode_web_path(path)

            for pattern in self._matched_sqli_patterns(
                path,
                decoded_path,
            ):
                if pattern:
                    dedup_context = {
                        "signature": pattern,
                        "endpoint": path.split("?", 1)[0],
                        "method": event.method or "",
                    }

                    if self._is_duplicate_alert(
                        "WEB-SQLI-001",
                        event.source_ip,
                        event.timestamp,
                        dedup_context,
                    ):
                        break

                    alerts.append(
                        Alert(
                            alert_type="SQL Injection Attempt",
                            severity="CRITICAL",
                            source_ip=event.source_ip,
                            detail=(
                                f"SQL injection pattern detected in request: {path}"
                            ),
                            timestamp=event.timestamp,
                            rule_id="WEB-SQLI-001",
                            confidence=0.99,
                            evidence=self._build_evidence(
                                rule_id="WEB-SQLI-001",
                                source_ip=event.source_ip,
                                summary=(
                                    f"Request {path} matched SQL injection "
                                    f"signature {pattern}."
                                ),
                                explanation=(
                                    f"The request path or query string "
                                    f"\"{path}\" matched the configured SQL "
                                    f"injection signature \"{pattern}\". This "
                                    f"syntax is not expected in normal "
                                    f"application input and is the pattern used "
                                    f"to make a database return, modify, or "
                                    f"destroy data."
                                ),
                                conditions=[
                                    {
                                        "condition": (
                                            "Request contains a known SQL "
                                            "injection signature"
                                        ),
                                        "expected": "no SQL injection signature",
                                        "observed": f"matched \"{pattern}\"",
                                        "result": "MET",
                                    },
                                    {
                                        "condition": "Request method",
                                        "expected": "any",
                                        "observed": event.method or "unknown",
                                        "result": "INFO",
                                    },
                                    {
                                        "condition": "HTTP status returned",
                                        "expected": "any",
                                        "observed": (
                                            str(event.status)
                                            if event.status is not None
                                            else "unknown"
                                        ),
                                        "result": "INFO",
                                    },
                                ],
                                window_start=event.timestamp,
                                window_end=event.timestamp,
                                triggering_events=[event],
                                confidence=0.99,
                                extra={
                                    "matched_pattern": pattern,
                                    "request_path": path,
                                    "decoded_path": (
                                        decoded_path
                                        if decoded_path != path
                                        else None
                                    ),
                                    "request_method": event.method,
                                    "http_status": event.status,
                                },
                            ),
                        )
                    )

                    self._remember_alert(
                        "WEB-SQLI-001",
                        event.source_ip,
                        event.timestamp,
                        dedup_context,
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # PATH TRAVERSAL
    # ---------------------------------------------------------

    def _decode_web_path(self, path):
        """
        Decode percent-encoding in a request path using a bounded
        number of passes.

        Two passes cover literal, single-encoded, mixed-encoding and
        double-encoded separators without allowing recursive or
        uncontrolled decoding of the request.
        """

        decoded = path

        for _ in range(2):
            try:
                candidate = unquote(decoded)
            except (UnicodeDecodeError, ValueError):
                break

            if candidate == decoded:
                break

            decoded = candidate

        return decoded

    def _matched_traversal_patterns(self, path, decoded_path=None):
        """
        Yield the first traversal signature matched by the request.

        The original path and its bounded-decoded form are both checked,
        case-insensitively, so `..%2f`, `%2E%2E%2F` and `..%252f` are
        detected without treating every occurrence of `..` as traversal.
        """

        if decoded_path is None:
            decoded_path = self._decode_web_path(path)

        for candidate in dict.fromkeys((path, decoded_path)):
            for pattern in self.traversal_patterns:
                if re.search(pattern, candidate, re.IGNORECASE):
                    yield pattern
                    return

    def detect_path_traversal(self, events):
        if not self._rule_enabled("WEB-TRAVERSAL-001"):
            return []

        alerts = []

        for event in events:
            if event.source != "web":
                continue

            if event.event_type != "web_request":
                continue

            path = event.path or ""
            decoded_path = self._decode_web_path(path)

            for pattern in self._matched_traversal_patterns(
                path,
                decoded_path,
            ):
                if pattern:
                    dedup_context = {
                        "signature": pattern,
                        "decoded_path": decoded_path,
                    }

                    if self._is_duplicate_alert(
                        "WEB-TRAVERSAL-001",
                        event.source_ip,
                        event.timestamp,
                        dedup_context,
                    ):
                        break

                    alerts.append(
                        Alert(
                            alert_type="Path Traversal Attempt",
                            severity="HIGH",
                            source_ip=event.source_ip,
                            detail=(
                                f"Path traversal pattern detected: {path}"
                            ),
                            timestamp=event.timestamp,
                            rule_id="WEB-TRAVERSAL-001",
                            confidence=0.97,
                            evidence=self._build_evidence(
                                rule_id="WEB-TRAVERSAL-001",
                                source_ip=event.source_ip,
                                summary=(
                                    f"Request {path} matched traversal "
                                    f"pattern {pattern}."
                                ),
                                explanation=(
                                    f"The request \"{path}\" contains the "
                                    f"parent-directory sequence \"{pattern}\", "
                                    f"which attempts to escape the web root. "
                                    f"Successful traversal exposes "
                                    f"configuration, credential, or "
                                    f"operating-system files."
                                ),
                                conditions=[
                                    {
                                        "condition": (
                                            "Request contains a parent-directory "
                                            "traversal sequence"
                                        ),
                                        "expected": "no traversal sequence",
                                        "observed": f"matched \"{pattern}\"",
                                        "result": "MET",
                                    },
                                    {
                                        "condition": "Request method",
                                        "expected": "any",
                                        "observed": event.method or "unknown",
                                        "result": "INFO",
                                    },
                                    {
                                        "condition": "HTTP status returned",
                                        "expected": "any",
                                        "observed": (
                                            str(event.status)
                                            if event.status is not None
                                            else "unknown"
                                        ),
                                        "result": "INFO",
                                    },
                                ],
                                window_start=event.timestamp,
                                window_end=event.timestamp,
                                triggering_events=[event],
                                confidence=0.97,
                                extra={
                                    "matched_pattern": pattern,
                                    "request_path": path,
                                    "decoded_path": (
                                        decoded_path
                                        if decoded_path != path
                                        else None
                                    ),
                                    "request_method": event.method,
                                    "http_status": event.status,
                                },
                            ),
                        )
                    )

                    self._remember_alert(
                        "WEB-TRAVERSAL-001",
                        event.source_ip,
                        event.timestamp,
                        dedup_context,
                    )

                    break

        return alerts

    # ---------------------------------------------------------
    # SUCCESSFUL LOGIN AFTER BRUTE FORCE
    # ---------------------------------------------------------

    def detect_success_after_brute_force(self, events):
        if not self._rule_enabled("AUTH-COMPROMISE-001"):
            return []

        failures = defaultdict(list)

        for event in events:
            if (
                event.event_type == "login_failure"
                and event.source == "authentication"
                and event.source_ip
            ):
                failures[event.source_ip].append(event)

        alerts = []

        rule_config = self.rules_config["AUTH-COMPROMISE-001"]
        threshold = rule_config["threshold"]
        window = timedelta(
            seconds=rule_config["window_seconds"]
        )

        for event in events:
            if event.event_type != "login_success":
                continue

            if event.source != "authentication":
                continue

            if not event.source_ip:
                continue

            previous_failures = [
                failure
                for failure in failures.get(event.source_ip, [])
                if (
                    timedelta(0)
                    <= event.timestamp - failure.timestamp
                    <= window
                )
            ]

            if len(previous_failures) >= threshold:
                previous_failures.sort(
                    key=lambda failure: failure.timestamp
                )

                window_start = previous_failures[0].timestamp

                seconds_since_last_failure = int(
                    (
                        event.timestamp
                        - previous_failures[-1].timestamp
                    ).total_seconds()
                )

                dedup_context = {
                    "username": event.username or "unknown",
                }

                if self._is_duplicate_alert(
                    "AUTH-COMPROMISE-001",
                    event.source_ip,
                    event.timestamp,
                    dedup_context,
                ):
                    continue

                alerts.append(
                    Alert(
                        alert_type="Successful Login After Brute Force",
                        severity="CRITICAL",
                        source_ip=event.source_ip,
                        detail=(
                            f"Successful login for {event.username} after "
                            f"{len(previous_failures)} failed attempts."
                        ),
                        timestamp=event.timestamp,
                        rule_id="AUTH-COMPROMISE-001",
                        confidence=0.99,
                        evidence=self._build_evidence(
                            rule_id="AUTH-COMPROMISE-001",
                            source_ip=event.source_ip,
                            summary=(
                                f"Login as {event.username} from "
                                f"{event.source_ip} succeeded after "
                                f"{len(previous_failures)} failures."
                            ),
                            explanation=(
                                f"A successful login for "
                                f"{event.username or 'an unknown account'} from "
                                f"{event.source_ip} followed "
                                f"{len(previous_failures)} failed attempts inside "
                                f"the 120-second window. The rule threshold is "
                                f"{threshold} failures. A success immediately "
                                f"after a burst of failures indicates the "
                                f"guessing attack may have worked."
                            ),
                            conditions=[
                                {
                                    "condition": (
                                        "Failed logins from the same source "
                                        "before the successful login"
                                    ),
                                    "expected": f">= {threshold} failures",
                                    "observed": (
                                        f"{len(previous_failures)} failures"
                                    ),
                                    "result": "MET",
                                },
                                {
                                    "condition": (
                                        "Time between the last failure and "
                                        "the successful login"
                                    ),
                                    "expected": "<= 120 seconds",
                                    "observed": (
                                        f"{seconds_since_last_failure} seconds"
                                    ),
                                    "result": "MET",
                                },
                                {
                                    "condition": "Account that logged in",
                                    "expected": "any",
                                    "observed": event.username or "unknown",
                                    "result": "INFO",
                                },
                            ],
                            window_start=window_start,
                            window_end=event.timestamp,
                            triggering_events=(
                                previous_failures + [event]
                            ),
                            confidence=0.99,
                            extra={
                                "threshold": threshold,
                                "failure_count": len(previous_failures),
                                "successful_login": self._event_evidence(
                                    event
                                ),
                            },
                        ),
                    )
                )

                self._remember_alert(
                    "AUTH-COMPROMISE-001",
                    event.source_ip,
                    event.timestamp,
                    dedup_context,
                )

        return alerts

    # ---------------------------------------------------------
    # NETWORK RECONNAISSANCE
    # ---------------------------------------------------------

    def detect_network_reconnaissance(self, events):
        if not self._rule_enabled("NET-RECON-001"):
            return []

        connections = defaultdict(list)

        for event in events:
            if event.source != "network":
                continue

            if event.event_type != "connection":
                continue

            if not event.source_ip:
                continue

            if event.destination_port is None:
                continue

            # Only packets that begin a connection count. Reply packets
            # from a remote host carry the local ephemeral port as their
            # destination_port and must never look like that host probing
            # services. Legacy and synthetic events have initiated=None
            # and keep the historical behaviour.
            if event.initiated is False:
                continue

            connections[event.source_ip].append(event)

        alerts = []

        rule_config = self.rules_config["NET-RECON-001"]
        threshold = rule_config["threshold"]
        window = timedelta(
            seconds=rule_config["window_seconds"]
        )

        for source_ip, attempts in connections.items():
            attempts.sort(key=lambda event: event.timestamp)

            for i in range(len(attempts)):
                window_start = attempts[i].timestamp
                window_end = window_start + window

                matching_attempts = [
                    event
                    for event in attempts[i:]
                    if event.timestamp <= window_end
                ]

                unique_ports = {
                    event.destination_port
                    for event in matching_attempts
                    if event.destination_port is not None
                }

                if len(unique_ports) < threshold:
                    continue

                detection_timestamp = matching_attempts[-1].timestamp

                # -------------------------------------------------
                # Persistent deduplication
                # -------------------------------------------------
                #
                # Previously this state existed only in memory.
                # Now SENTRY checks SQLite so the state survives
                # an application restart.
                # -------------------------------------------------

                last_alert_timestamp = self._get_persistent_alert_timestamp(
                    rule_id="NET-RECON-001",
                    source_ip=source_ip,
                )

                if last_alert_timestamp is not None:
                    try:
                        last_alert_time = datetime.fromisoformat(
                            last_alert_timestamp
                        )

                        # Make timestamps comparable if one is naive
                        # and the other is timezone-aware.
                        if (
                            detection_timestamp.tzinfo is None
                            and last_alert_time.tzinfo is not None
                        ):
                            last_alert_time = last_alert_time.replace(
                                tzinfo=None
                            )

                        elif (
                            detection_timestamp.tzinfo is not None
                            and last_alert_time.tzinfo is None
                        ):
                            last_alert_time = last_alert_time.replace(
                                tzinfo=detection_timestamp.tzinfo
                            )

                        if (
                            detection_timestamp - last_alert_time
                            <= window
                        ):
                            continue

                    except ValueError:
                        # If old state is malformed, don't let it
                        # break the detection engine.
                        pass

                destinations = sorted(
                    {
                        event.destination_ip
                        for event in matching_attempts
                        if event.destination_ip
                    }
                )

                protocols = sorted(
                    {
                        event.protocol
                        for event in matching_attempts
                        if event.protocol
                    }
                )

                direction_counts = {}

                for event in matching_attempts:
                    label = event.direction or "unknown"

                    direction_counts[label] = (
                        direction_counts.get(label, 0) + 1
                    )

                alert = Alert(
                    alert_type="Network Reconnaissance",
                    severity="HIGH",
                    source_ip=source_ip,
                    detail=(
                        f"Detected connections to "
                        f"{len(unique_ports)} unique destination "
                        f"ports within 2 minutes."
                    ),
                    timestamp=detection_timestamp,
                    rule_id="NET-RECON-001",
                    confidence=0.95,
                    evidence=self._build_evidence(
                        rule_id="NET-RECON-001",
                        source_ip=source_ip,
                        summary=(
                            f"{source_ip} contacted {len(unique_ports)} "
                            f"unique destination ports within 2 minutes."
                        ),
                        explanation=(
                            f"{source_ip} contacted {len(unique_ports)} unique "
                            f"destination ports inside the 120-second detection "
                            f"window. The rule threshold is {threshold} unique "
                            f"ports. Legitimate clients usually talk to a small "
                            f"set of services, so a wide port spread is "
                            f"consistent with a port scan mapping the network. "
                            f"Only connection initiations are counted, so "
                            f"replies from a remote service are never mistaken "
                            f"for that service scanning ports."
                        ),
                        conditions=[
                            {
                                "condition": (
                                    "Unique destination ports contacted by one "
                                    "source through connection initiations "
                                    "inside the window"
                                ),
                                "expected": f">= {threshold} unique ports",
                                "observed": f"{len(unique_ports)} unique ports",
                                "result": "MET",
                            },
                            {
                                "condition": "Correlation window",
                                "expected": "120 seconds",
                                "observed": (
                                    f"{window_start.isoformat()} to "
                                    f"{window_end.isoformat()}"
                                ),
                                "result": "MET",
                            },
                            {
                                "condition": "Connection attempts in window",
                                "expected": "any",
                                "observed": str(len(matching_attempts)),
                                "result": "INFO",
                            },
                        ],
                        window_start=window_start,
                        window_end=window_end,
                        triggering_events=matching_attempts,
                        confidence=0.95,
                        extra={
                            "threshold": threshold,
                            "unique_port_count": len(unique_ports),
                            "unique_destination_ports": sorted(unique_ports),
                            "destination_ips": destinations,
                            "protocols": protocols,
                            "connection_initiations": len(
                                matching_attempts
                            ),
                            "direction_counts": direction_counts,
                            "direction_filter": (
                                "Packets explicitly marked as not initiating "
                                "a connection are excluded."
                            ),
                        },
                    ),
                )

                alerts.append(alert)

                # Persist the detection state immediately.
                self._set_persistent_alert_timestamp(
                    rule_id="NET-RECON-001",
                    source_ip=source_ip,
                    timestamp=detection_timestamp,
                )

                break

        return alerts

    # ---------------------------------------------------------
    # SUSPICIOUS DNS ACTIVITY
    # ---------------------------------------------------------

    def detect_suspicious_dns(self, events):
        if not self._rule_enabled("DNS-SUSPICIOUS-001"):
            return []

        rule_config = self.rules_config["DNS-SUSPICIOUS-001"]
        rule_id = "DNS-SUSPICIOUS-001"
        threshold = rule_config["threshold"]
        window = timedelta(
            seconds=rule_config["window_seconds"]
        )

        queries = defaultdict(list)

        for event in events:
            if event.source != "network":
                continue

            if event.event_type != "dns_query":
                continue

            if not event.source_ip or not event.path:
                continue

            queries[event.source_ip].append(event)

        alerts = []

        for source_ip, attempts in queries.items():
            attempts.sort(key=lambda event: event.timestamp)

            for i in range(len(attempts)):
                window_start = attempts[i].timestamp
                window_end = window_start + window

                matching_attempts = [
                    event
                    for event in attempts[i:]
                    if event.timestamp <= window_end
                ]

                domains = {
                    event.path
                    for event in matching_attempts
                    if event.path
                }

                if len(domains) < threshold:
                    continue

                detection_timestamp = matching_attempts[-1].timestamp

                if self._recently_alerted(
                    rule_id,
                    source_ip,
                    detection_timestamp,
                    window,
                ):
                    continue

                nxdomain_count = sum(
                    1
                    for event in matching_attempts
                    if event.status == 3
                )

                alerts.append(
                    Alert(
                        alert_type="Suspicious DNS Activity",
                        severity="HIGH",
                        source_ip=source_ip,
                        detail=(
                            f"Resolved {len(domains)} unique domains "
                            f"within {rule_config['window_seconds']} seconds."
                        ),
                        timestamp=detection_timestamp,
                        rule_id=rule_id,
                        confidence=0.8,
                        evidence=self._build_evidence(
                            rule_id=rule_id,
                            source_ip=source_ip,
                            summary=(
                                f"{source_ip} resolved {len(domains)} unique "
                                f"domains in {rule_config['window_seconds']} "
                                f"seconds."
                            ),
                            explanation=(
                                f"{source_ip} issued DNS queries for "
                                f"{len(domains)} unique domains inside the "
                                f"{rule_config['window_seconds']}-second "
                                f"detection window. The rule threshold is "
                                f"{threshold} unique domains. High-volume "
                                f"resolution, especially with NXDOMAIN "
                                f"responses, is consistent with automated "
                                f"discovery or DNS tunneling."
                            ),
                            conditions=[
                                {
                                    "condition": (
                                        "Unique domains resolved by one "
                                        "source inside the window"
                                    ),
                                    "expected": (
                                        f">= {threshold} unique domains"
                                    ),
                                    "observed": (
                                        f"{len(domains)} unique domains"
                                    ),
                                    "result": "MET",
                                },
                                {
                                    "condition": "Correlation window",
                                    "expected": (
                                        f"{rule_config['window_seconds']} "
                                        f"seconds"
                                    ),
                                    "observed": (
                                        f"{window_start.isoformat()} to "
                                        f"{window_end.isoformat()}"
                                    ),
                                    "result": "MET",
                                },
                                {
                                    "condition": "NXDOMAIN responses",
                                    "expected": "any",
                                    "observed": str(nxdomain_count),
                                    "result": "INFO",
                                },
                            ],
                            window_start=window_start,
                            window_end=window_end,
                            triggering_events=matching_attempts,
                            confidence=0.8,
                            extra={
                                "threshold": threshold,
                                "unique_domain_count": len(domains),
                                "unique_domains": sorted(domains)[
                                    :MAX_TRIGGERING_EVENTS
                                ],
                                "nxdomain_count": nxdomain_count,
                            },
                        ),
                    )
                )

                self._set_persistent_alert_timestamp(
                    rule_id,
                    source_ip,
                    detection_timestamp,
                )

                break

        return alerts

    # ---------------------------------------------------------
    # EVIDENCE HELPERS
    # ---------------------------------------------------------

    def _build_evidence(
        self,
        rule_id,
        source_ip,
        summary,
        explanation,
        conditions,
        window_start=None,
        window_end=None,
        triggering_events=None,
        confidence=None,
        extra=None,
    ):
        """
        Build the structured, JSON-serializable evidence stored with
        an alert.

        Evidence describes only the events that caused the rule to
        fire. It never includes surrounding investigation context.
        """

        metadata = self.rule_metadata[rule_id]

        window_seconds = None

        if window_start is not None and window_end is not None:
            try:
                window_seconds = int(
                    (window_end - window_start).total_seconds()
                )
            except TypeError:
                window_seconds = None

        triggering_events = list(triggering_events or [])

        evidence = {
            "rule_id": rule_id,
            "rule_name": metadata["name"],
            "rule_description": metadata["description"],
            "severity": metadata["severity"],
            "mitre": metadata["mitre"],
            "source_ip": source_ip,
            "summary": summary,
            "explanation": explanation,
            "confidence": {
                "score": confidence,
                "basis": (
                    "Rule confidence value assigned by the detection rule. "
                    "This is a signal-strength value, not a statistically "
                    "validated probability."
                ),
            },
            "window": {
                "start": (
                    window_start.isoformat()
                    if window_start is not None
                    else None
                ),
                "end": (
                    window_end.isoformat()
                    if window_end is not None
                    else None
                ),
                "seconds": window_seconds,
            },
            "conditions": conditions,
            "triggering_event_count": len(triggering_events),
            "triggering_events": [
                self._event_evidence(event)
                for event in triggering_events[
                    :MAX_TRIGGERING_EVENTS
                ]
            ],
            "recommended_actions": metadata[
                "recommended_actions"
            ],
        }

        if extra:
            evidence.update(extra)

        return evidence

    @staticmethod
    def _event_evidence(event: SecurityEvent):
        """
        Serialize one event for the evidence payload.
        """

        return {
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "source_port": event.source_port,
            "destination_port": event.destination_port,
            "protocol": event.protocol,
            "username": event.username,
            "method": event.method,
            "path": event.path,
            "status": event.status,
            "outcome": event.outcome,
            "direction": event.direction,
            "initiated": event.initiated,
            "raw": event.raw,
        }

    # ---------------------------------------------------------
    # RULE CONFIGURATION AND SUPPRESSION
    # ---------------------------------------------------------

    def _dedup_fingerprint(self, rule_id, source_ip, context):
        """
        Build a stable fingerprint for one detection.

        The fingerprint combines the rule, the source IP and the
        detection-specific context (targets, accounts, signature), so
        different targets or accounts are never merged into one
        incident.
        """

        payload = json.dumps(
            {
                "rule_id": rule_id,
                "source_ip": source_ip,
                "context": context,
            },
            sort_keys=True,
            default=str,
        )

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    def _dedup_cooldown_seconds(self, rule_id):
        settings = self.rules_config.get(rule_id, {})

        try:
            return max(
                0,
                int(settings.get("dedup_cooldown_seconds", 0)),
            )
        except (TypeError, ValueError):
            return 0

    def _is_duplicate_alert(
        self,
        rule_id,
        source_ip,
        timestamp,
        context,
    ):
        """
        Return True when this detection is inside an active cooldown.

        Older or repeated timestamps are treated as duplicates too, so
        reprocessing an old batch cannot create a second alert or move
        the cooldown backwards. Suppressed detections update only the
        last-seen time and counter.
        """

        cooldown_seconds = self._dedup_cooldown_seconds(rule_id)

        if cooldown_seconds <= 0:
            return False

        fingerprint = self._dedup_fingerprint(
            rule_id,
            source_ip,
            context,
        )

        state = self.database.get_alert_dedup_state(fingerprint)

        if not state:
            return False

        try:
            last_alert_time = datetime.fromisoformat(
                state["last_alert_timestamp"]
            )
        except (TypeError, ValueError):
            return False

        if (
            timestamp.tzinfo is None
            and last_alert_time.tzinfo is not None
        ):
            last_alert_time = last_alert_time.replace(tzinfo=None)

        elif (
            timestamp.tzinfo is not None
            and last_alert_time.tzinfo is None
        ):
            last_alert_time = last_alert_time.replace(
                tzinfo=timestamp.tzinfo
            )

        try:
            within_cooldown = (
                timestamp - last_alert_time
                <= timedelta(seconds=cooldown_seconds)
            )
        except TypeError:
            return False

        if not within_cooldown:
            return False

        self.database.record_suppressed_detection(
            fingerprint,
            timestamp.isoformat(),
        )

        return True

    def _remember_alert(
        self,
        rule_id,
        source_ip,
        timestamp,
        context,
    ):
        """Persist the fingerprint and cooldown anchor for an alert."""

        if self._dedup_cooldown_seconds(rule_id) <= 0:
            return

        self.database.record_alert_dedup(
            self._dedup_fingerprint(rule_id, source_ip, context),
            rule_id,
            source_ip,
            timestamp.isoformat(),
        )

    def _rule_enabled(self, rule_id):
        settings = self.rules_config.get(rule_id, {})

        return bool(settings.get("enabled", True))

    def _recently_alerted(
        self,
        rule_id,
        source_ip,
        timestamp,
        window,
    ):
        """
        Return True when the same rule recently fired for this source.
        Used by rules that suppress repeated alerts for one ongoing
        burst (for example a port scan or DNS flood).
        """

        last_alert_timestamp = (
            self._get_persistent_alert_timestamp(
                rule_id,
                source_ip,
            )
        )

        if last_alert_timestamp is None:
            return False

        try:
            last_alert_time = datetime.fromisoformat(
                last_alert_timestamp
            )
        except ValueError:
            return False

        if (
            timestamp.tzinfo is None
            and last_alert_time.tzinfo is not None
        ):
            last_alert_time = last_alert_time.replace(
                tzinfo=None
            )

        elif (
            timestamp.tzinfo is not None
            and last_alert_time.tzinfo is None
        ):
            last_alert_time = last_alert_time.replace(
                tzinfo=timestamp.tzinfo
            )

        try:
            return (
                timedelta(0)
                <= timestamp - last_alert_time
                <= window
            )
        except TypeError:
            return False

    # ---------------------------------------------------------
    # PERSISTENT DETECTION STATE HELPERS
    # ---------------------------------------------------------

    def _get_persistent_alert_timestamp(
        self,
        rule_id,
        source_ip,
    ):
        """
        Read the last detection timestamp from SQLite.
        """

        return self.database.get_detection_state(
            rule_id,
            source_ip,
        )

    def _set_persistent_alert_timestamp(
        self,
        rule_id,
        source_ip,
        timestamp,
    ):
        """
        Store the last detection timestamp in SQLite.
        """

        self.database.set_detection_state(
            rule_id,
            source_ip,
            timestamp.isoformat(),
        )

    # ---------------------------------------------------------
    # NETWORK EVENT BUFFER
    # ---------------------------------------------------------

    def _update_network_event_buffer(self, events):
        if not events:
            return

        network_events = [
            event
            for event in events
            if (
                event.source == "network"
                and event.event_type in (
                    "connection",
                    "dns_query",
                )
                and event.source_ip
                and (
                    event.destination_port is not None
                    or event.event_type == "dns_query"
                )
            )
        ]

        if not network_events:
            return

        newest_timestamp = max(
            event.timestamp
            for event in network_events
        )

        window = timedelta(minutes=2)

        self.recent_network_events = [
            event
            for event in network_events
            if newest_timestamp - event.timestamp <= window
        ]
