import random
from datetime import datetime, timedelta

from core.models import SecurityEvent


class EventGenerator:
    """
    Generates realistic synthetic security events for SENTRY.

    Events can represent normal activity or simulated attack
    scenarios. The generator is designed to feed the same
    processing pipeline used by SENTRY for security detection.
    """

    def __init__(self):
        self.normal_ips = [
            "192.168.1.10",
            "192.168.1.20",
            "192.168.1.30",
            "10.0.0.15",
        ]

        self.attack_ips = [
            "45.33.32.156",
            "185.220.101.42",
            "103.21.244.11",
            "172.67.181.22",
        ]

        self.users = [
            "admin",
            "john",
            "alice",
            "bob",
            "developer",
        ]

    # ---------------------------------------------------------
    # NORMAL TRAFFIC
    # ---------------------------------------------------------

    def generate_normal_events(self, count=20):
        """
        Generate normal authentication and web activity.
        """

        events = []

        start_time = datetime.now() - timedelta(minutes=5)

        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * 10)

            event_type = random.choice(
                [
                    "login_success",
                    "web_request",
                    "file_access",
                ]
            )

            source_ip = random.choice(self.normal_ips)
            username = random.choice(self.users)

            if event_type == "login_success":

                event = SecurityEvent(
                    timestamp=timestamp,
                    source="authentication",
                    event_type="login_success",
                    source_ip=source_ip,
                    username=username,
                    raw=(
                        f"Successful login for "
                        f"{username} from {source_ip}"
                    ),
                )

            elif event_type == "web_request":

                paths = [
                    "/",
                    "/home",
                    "/dashboard",
                    "/products",
                    "/profile",
                    "/api/users",
                ]

                path = random.choice(paths)

                event = SecurityEvent(
                    timestamp=timestamp,
                    source="web",
                    event_type="web_request",
                    source_ip=source_ip,
                    method="GET",
                    path=path,
                    status=200,
                    raw=f"{source_ip} GET {path} 200",
                )

            else:

                event = SecurityEvent(
                    timestamp=timestamp,
                    source="filesystem",
                    event_type="file_access",
                    source_ip=source_ip,
                    username=username,
                    raw=(
                        f"{username} accessed a file "
                        f"from {source_ip}"
                    ),
                )

            events.append(event)

        return events

    # ---------------------------------------------------------
    # SSH BRUTE FORCE
    # ---------------------------------------------------------

    def generate_ssh_brute_force(self, attempts=10):
        """
        Generate repeated failed SSH authentication attempts.
        """

        events = []

        source_ip = random.choice(self.attack_ips)
        username = random.choice(self.users)

        start_time = datetime.now() - timedelta(minutes=2)

        for i in range(attempts):

            timestamp = start_time + timedelta(seconds=i * 5)

            event = SecurityEvent(
                timestamp=timestamp,
                source="authentication",
                event_type="login_failure",
                source_ip=source_ip,
                username=username,
                raw=(
                    f"Failed SSH login for "
                    f"{username} from {source_ip}"
                ),
            )

            events.append(event)

        return events

    # ---------------------------------------------------------
    # SQL INJECTION
    # ---------------------------------------------------------

    def generate_sql_injection(self, attempts=5):
        """
        Generate SQL injection web requests.
        """

        events = []

        source_ip = random.choice(self.attack_ips)

        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1--",
            "'; DROP TABLE users;--",
        ]

        start_time = datetime.now() - timedelta(minutes=1)

        for i in range(attempts):

            timestamp = start_time + timedelta(seconds=i * 4)

            payload = random.choice(payloads)

            path = f"/login?username={payload}"

            event = SecurityEvent(
                timestamp=timestamp,
                source="web",
                event_type="web_request",
                source_ip=source_ip,
                method="GET",
                path=path,
                status=200,
                raw=f"{source_ip} GET {path} 200",
            )

            events.append(event)

        return events

    # ---------------------------------------------------------
    # PATH TRAVERSAL
    # ---------------------------------------------------------

    def generate_path_traversal(self, attempts=5):
        """
        Generate path traversal web requests.
        """

        events = []

        source_ip = random.choice(self.attack_ips)

        payloads = [
            "../../etc/passwd",
            "../../../etc/shadow",
            "..%2F..%2Fetc%2Fpasswd",
            "../../../../var/log/auth.log",
        ]

        start_time = datetime.now() - timedelta(minutes=1)

        for i in range(attempts):

            timestamp = start_time + timedelta(seconds=i * 4)

            payload = random.choice(payloads)

            path = f"/download?file={payload}"

            event = SecurityEvent(
                timestamp=timestamp,
                source="web",
                event_type="web_request",
                source_ip=source_ip,
                method="GET",
                path=path,
                status=400,
                raw=f"{source_ip} GET {path} 400",
            )

            events.append(event)

        return events

    # ---------------------------------------------------------
    # MIXED ATTACK CAMPAIGN
    # ---------------------------------------------------------

    def generate_mixed_attack_campaign(
        self,
        ssh_attempts=10,
        sql_attempts=5,
        traversal_attempts=5,
    ):
        """
        Generate a mixed attack campaign containing
        multiple types of suspicious activity.
        """

        events = []

        # -----------------------------------------------------
        # SSH BRUTE FORCE
        # -----------------------------------------------------

        brute_force_events = self.generate_ssh_brute_force(
            ssh_attempts
        )

        events.extend(brute_force_events)

        # Use the same attacker IP so the successful login
        # can be correlated with the previous failed attempts.

        attacker_ip = brute_force_events[0].source_ip
        username = brute_force_events[0].username

        # -----------------------------------------------------
        # SUCCESSFUL LOGIN AFTER BRUTE FORCE
        # -----------------------------------------------------

        successful_login_time = (
            brute_force_events[-1].timestamp
            + timedelta(seconds=10)
        )

        successful_login = SecurityEvent(
            timestamp=successful_login_time,
            source="authentication",
            event_type="login_success",
            source_ip=attacker_ip,
            username=username,
            raw=(
                f"Successful SSH login for "
                f"{username} from {attacker_ip}"
            ),
        )

        events.append(successful_login)

        # -----------------------------------------------------
        # SQL INJECTION
        # -----------------------------------------------------

        events.extend(
            self.generate_sql_injection(sql_attempts)
        )

        # -----------------------------------------------------
        # PATH TRAVERSAL
        # -----------------------------------------------------

        events.extend(
            self.generate_path_traversal(
                traversal_attempts
            )
        )

        # Keep events in chronological order.

        events.sort(
            key=lambda event: event.timestamp
        )

        return events

    # ---------------------------------------------------------
    # INTENSITY CONFIGURATION
    # ---------------------------------------------------------

    def get_intensity_settings(self, intensity):
        """
        Return event-generation settings for a given
        attack intensity.

        Supported levels:

            low
            medium
            high
            critical
        """

        settings = {
            "low": {
                "normal_events": 5,
                "ssh_attempts": 6,
                "sql_attempts": 3,
                "traversal_attempts": 3,
            },

            "medium": {
                "normal_events": 10,
                "ssh_attempts": 10,
                "sql_attempts": 5,
                "traversal_attempts": 5,
            },

            "high": {
                "normal_events": 20,
                "ssh_attempts": 20,
                "sql_attempts": 10,
                "traversal_attempts": 10,
            },

            "critical": {
                "normal_events": 30,
                "ssh_attempts": 40,
                "sql_attempts": 20,
                "traversal_attempts": 20,
            },
        }

        intensity = intensity.lower()

        if intensity not in settings:
            raise ValueError(
                f"Unknown intensity: {intensity}. "
                f"Supported values: "
                f"{', '.join(settings.keys())}"
            )

        return settings[intensity]

    # ---------------------------------------------------------
    # MAIN GENERATION INTERFACE
    # ---------------------------------------------------------

    def generate(
        self,
        scenario="mixed",
        normal_events=10,
        intensity="medium",
    ):
        """
        Main event generation interface.

        Supported scenarios:

            normal
            ssh_brute_force
            sql_injection
            path_traversal
            mixed

        Supported intensities:

            low
            medium
            high
            critical
        """

        intensity_settings = self.get_intensity_settings(
            intensity
        )

        # -----------------------------------------------------
        # NORMAL TRAFFIC
        # -----------------------------------------------------

        if scenario == "normal":

            return self.generate_normal_events(
                normal_events
            )

        # -----------------------------------------------------
        # SSH BRUTE FORCE
        # -----------------------------------------------------

        if scenario == "ssh_brute_force":

            return self.generate_ssh_brute_force(
                intensity_settings["ssh_attempts"]
            )

        # -----------------------------------------------------
        # SQL INJECTION
        # -----------------------------------------------------

        if scenario == "sql_injection":

            return self.generate_sql_injection(
                intensity_settings["sql_attempts"]
            )

        # -----------------------------------------------------
        # PATH TRAVERSAL
        # -----------------------------------------------------

        if scenario == "path_traversal":

            return self.generate_path_traversal(
                intensity_settings[
                    "traversal_attempts"
                ]
            )

        # -----------------------------------------------------
        # MIXED ATTACK CAMPAIGN
        # -----------------------------------------------------

        if scenario == "mixed":

            events = self.generate_normal_events(
                intensity_settings["normal_events"]
            )

            events.extend(
                self.generate_mixed_attack_campaign(
                    ssh_attempts=intensity_settings[
                        "ssh_attempts"
                    ],
                    sql_attempts=intensity_settings[
                        "sql_attempts"
                    ],
                    traversal_attempts=intensity_settings[
                        "traversal_attempts"
                    ],
                )
            )

            events.sort(
                key=lambda event: event.timestamp
            )

            return events

        raise ValueError(
            f"Unknown scenario: {scenario}"
        )