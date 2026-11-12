import re
from datetime import datetime

from core.models import SecurityEvent


class LogParser:
    """
    Converts raw authentication and web logs into
    normalized SecurityEvent objects.
    """

    AUTH_LOG_PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+"
        r"(?P<day>\d+)\s+"
        r"(?P<time>[\d:]+)\s+"
        r"\S+\s+sshd\[\d+\]:\s+"
        r"(?P<result>Accepted|Failed)\s+password\s+for\s+"
        r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    )

    ACCESS_LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ '
        r'\[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) '
        r'(?P<path>.+?) HTTP/\S+" '
        r'(?P<status>\d+)'
    )

    def parse_auth_line(self, line):
        """
        Parse one SSH authentication log line.
        """

        match = self.AUTH_LOG_PATTERN.match(line.strip())

        if not match:
            return None

        data = match.groupdict()

        result = data["result"]

        if result == "Failed":
            event_type = "login_failure"
        else:
            event_type = "login_success"

        current_year = datetime.now().year

        try:
            timestamp = datetime.strptime(
                f"{current_year} {data['month']} "
                f"{data['day']} {data['time']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None

        return SecurityEvent(
            timestamp=timestamp,
            source="authentication",
            event_type=event_type,
            source_ip=data["ip"],
            username=data["user"],
            raw=line.strip(),
        )

    def parse_access_line(self, line):
        """
        Parse one web access log line.
        """

        match = self.ACCESS_LOG_PATTERN.match(line.strip())

        if not match:
            return None

        data = match.groupdict()

        timestamp_text = data["time"]

        try:
            timestamp = datetime.strptime(
                timestamp_text,
                "%d/%b/%Y:%H:%M:%S %z",
            )

            # Convert timezone-aware datetime into a
            # timezone-naive datetime for consistent
            # event processing inside SENTRY.
            timestamp = timestamp.replace(tzinfo=None)

        except ValueError:
            return None

        return SecurityEvent(
            timestamp=timestamp,
            source="web",
            event_type="web_request",
            source_ip=data["ip"],
            method=data["method"],
            path=data["path"],
            status=int(data["status"]),
            raw=line.strip(),
        )

    def parse_auth_file(self, path):
        """
        Parse an authentication log file.
        """

        events = []

        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                event = self.parse_auth_line(line)

                if event:
                    events.append(event)

        return events

    def parse_access_file(self, path):
        """
        Parse a web access log file.
        """

        events = []

        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                event = self.parse_access_line(line)

                if event:
                    events.append(event)

        return events

    def parse_files(self, auth_path, access_path):
        """
        Parse authentication and web logs together.
        """

        events = []

        events.extend(self.parse_auth_file(auth_path))
        events.extend(self.parse_access_file(access_path))

        # All timestamps are normalized to timezone-naive
        # datetime objects before sorting.
        events.sort(key=lambda event: event.timestamp)

        return events