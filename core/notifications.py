import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class NotificationManager:
    """
    Optional alert notifications.

    Notifications are disabled unless SENTRY_WEBHOOK_URL is configured.
    A generic JSON webhook is used so no vendor or secret is baked into
    the project. Duplicate notifications for the same rule and source
    are suppressed for a cooldown period.
    """

    def __init__(
        self,
        webhook_url=None,
        min_severity=None,
        cooldown_seconds=None,
        transport=None,
    ):
        self.webhook_url = (
            webhook_url
            if webhook_url is not None
            else os.environ.get("SENTRY_WEBHOOK_URL", "")
        )

        self.min_severity = (
            min_severity
            or os.environ.get("SENTRY_NOTIFY_MIN_SEVERITY", "HIGH")
        ).upper()

        self.cooldown_seconds = int(
            cooldown_seconds
            if cooldown_seconds is not None
            else os.environ.get("SENTRY_NOTIFY_COOLDOWN_SECONDS", "300")
        )

        self.transport = transport

    @property
    def enabled(self):
        return bool(self.webhook_url) or self.transport is not None

    def severity_allowed(self, severity):
        return SEVERITY_RANK.get(
            str(severity).upper(),
            0,
        ) >= SEVERITY_RANK.get(self.min_severity, 3)

    def _send(self, payload):
        if self.transport is not None:
            return self.transport(payload)

        request = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status

    def _in_cooldown(self, database, alert):
        if database is None or not alert.source_ip:
            return False

        last_sent = database.get_notification_state(
            alert.rule_id,
            alert.source_ip,
        )

        if not last_sent:
            return False

        try:
            last_sent_time = datetime.fromisoformat(last_sent)
        except ValueError:
            return False

        return (
            datetime.now() - last_sent_time
            <= timedelta(seconds=self.cooldown_seconds)
        )

    def notify(self, alerts, database=None):
        """
        Send notifications for eligible alerts.

        Returns a list of result dictionaries. Failures never raise and
        never hide the alert itself.
        """

        results = []

        if not self.enabled:
            return results

        for alert in alerts:
            if not self.severity_allowed(alert.severity):
                continue

            if self._in_cooldown(database, alert):
                continue

            payload = {
                "service": "SENTRY",
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "rule_id": alert.rule_id,
                "source_ip": alert.source_ip,
                "detail": alert.detail,
                "timestamp": alert.timestamp.isoformat(),
                "summary": (
                    alert.evidence or {}
                ).get("summary"),
            }

            try:
                status = self._send(payload)
                results.append(
                    {
                        "rule_id": alert.rule_id,
                        "delivered": True,
                        "status": status,
                    }
                )
            except (
                urllib.error.URLError,
                TimeoutError,
                OSError,
                ValueError,
            ) as error:
                results.append(
                    {
                        "rule_id": alert.rule_id,
                        "delivered": False,
                        "error": type(error).__name__,
                    }
                )
                continue

            if database is not None and alert.source_ip:
                database.set_notification_state(
                    alert.rule_id,
                    alert.source_ip,
                    datetime.now().isoformat(),
                )

        return results
