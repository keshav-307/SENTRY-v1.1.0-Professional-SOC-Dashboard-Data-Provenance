import json
import sqlite3
from pathlib import Path

from core.models import Alert, SecurityEvent


class SentryDatabase:
    """
    SQLite database for storing SENTRY events and alerts.
    """

    def __init__(self, database_path="sentry.db"):
        self.database_path = Path(database_path)
        self.initialize_database()

    def get_connection(self):
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize_database(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        # ---------------------------------------------------------
        # EVENTS TABLE
        # ---------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
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

        # ---------------------------------------------------------
        # EVENTS TABLE MIGRATION
        # ---------------------------------------------------------
        # These ALTER TABLE statements make the new network fields
        # available to existing SENTRY databases without deleting
        # existing events.

        cursor.execute("PRAGMA table_info(events)")

        event_columns = [
            row["name"]
            for row in cursor.fetchall()
        ]

        if "destination_ip" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN destination_ip TEXT
                """
            )

        if "source_port" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN source_port INTEGER
                """
            )

        if "destination_port" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN destination_port INTEGER
                """
            )

        if "protocol" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN protocol TEXT
                """
            )

        if "outcome" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN outcome TEXT
                """
            )

        # Direction relative to this host and whether the packet begins
        # a connection. Additive so existing events stay readable with
        # NULL/unknown metadata.
        if "direction" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN direction TEXT
                """
            )

        if "initiated" not in event_columns:
            cursor.execute(
                """
                ALTER TABLE events
                ADD COLUMN initiated INTEGER
                """
            )

        # ---------------------------------------------------------
        # ALERTS TABLE
        # ---------------------------------------------------------

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
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
                recommended_action TEXT,
                evidence_json TEXT,
                threat_intel_json TEXT
            )
            """
        )

        # ---------------------------------------------------------
        # DATABASE MIGRATION
        # ---------------------------------------------------------

        cursor.execute(
            "PRAGMA table_info(alerts)"
        )

        columns = [
            row["name"]
            for row in cursor.fetchall()
        ]

        # Add status to older databases
        if "status" not in columns:
            cursor.execute(
                """
                ALTER TABLE alerts
                ADD COLUMN status TEXT NOT NULL DEFAULT 'OPEN'
                """
            )

        # Add analyst notes to older databases
        if "analyst_notes" not in columns:
            cursor.execute(
                """
                ALTER TABLE alerts
                ADD COLUMN analyst_notes TEXT
                """
            )

        # Add recommended action to older databases
        if "recommended_action" not in columns:
            cursor.execute(
                """
                ALTER TABLE alerts
                ADD COLUMN recommended_action TEXT
                """
            )

        # Add structured detection evidence to older databases.
        # Existing alerts keep NULL and remain fully readable.
        if "evidence_json" not in columns:
            cursor.execute(
                """
                ALTER TABLE alerts
                ADD COLUMN evidence_json TEXT
                """
            )

        # Threat intelligence enrichment for the alert's source IP.
        if "threat_intel_json" not in columns:
            cursor.execute(
                """
                ALTER TABLE alerts
                ADD COLUMN threat_intel_json TEXT
                """
            )

        connection.commit()
        connection.close()

        self.initialize_detection_state()
        self.initialize_alert_dedup()
        self.initialize_support_tables()

    # =============================================================
    # EVENT METHODS
    # =============================================================

    def save_event(self, event: SecurityEvent):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO events (
                timestamp,
                source,
                event_type,

                source_ip,
                destination_ip,

                source_port,
                destination_port,

                protocol,

                username,
                method,
                path,
                status,
                outcome,

                direction,
                initiated,

                raw
            )
            VALUES (
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?
            )
            """,
            (
                event.timestamp.isoformat(),
                event.source,
                event.event_type,

                event.source_ip,
                event.destination_ip,

                event.source_port,
                event.destination_port,

                event.protocol,

                event.username,
                event.method,
                event.path,
                event.status,
                event.outcome,

                event.direction,

                (
                    None
                    if event.initiated is None
                    else int(bool(event.initiated))
                ),

                event.raw,
            ),
        )

        connection.commit()
        connection.close()

    def save_events(self, events):
        connection = self.get_connection()
        cursor = connection.cursor()

        for event in events:
            cursor.execute(
                """
                INSERT INTO events (
                    timestamp,
                    source,
                    event_type,

                    source_ip,
                    destination_ip,

                    source_port,
                    destination_port,

                    protocol,

                    username,
                    method,
                    path,
                    status,
                    outcome,

                    direction,
                    initiated,

                    raw
                )
                VALUES (
                    ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?,
                    ?, ?, ?, ?, ?,
                    ?, ?,
                    ?
                )
                """,
                (
                    event.timestamp.isoformat(),
                    event.source,
                    event.event_type,

                    event.source_ip,
                    event.destination_ip,

                    event.source_port,
                    event.destination_port,

                    event.protocol,

                    event.username,
                    event.method,
                    event.path,
                    event.status,
                    event.outcome,

                    event.direction,

                    (
                        None
                        if event.initiated is None
                        else int(bool(event.initiated))
                    ),

                    event.raw,
                ),
            )

        connection.commit()
        connection.close()

    def get_event_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM events"
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_recent_events(self, limit=50):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    def get_recent_network_events(self, limit=500):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            WHERE source = 'network'
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    def get_all_events(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp DESC, id DESC
            """
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    # =============================================================
    # ALERT METHODS
    # =============================================================

    def save_alert(self, alert: Alert):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alerts (
                alert_type,
                severity,
                source_ip,
                detail,
                timestamp,
                rule_id,
                confidence,
                status,
                analyst_notes,
                recommended_action,
                evidence_json,
                threat_intel_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.alert_type,
                alert.severity,
                alert.source_ip,
                alert.detail,
                alert.timestamp.isoformat(),
                alert.rule_id,
                alert.confidence,
                "OPEN",
                None,
                None,
                self._evidence_json(alert),
                self._threat_intel_json(alert),
            ),
        )

        connection.commit()
        connection.close()

    def save_alerts(self, alerts):
        connection = self.get_connection()
        cursor = connection.cursor()

        for alert in alerts:
            cursor.execute(
                """
                INSERT INTO alerts (
                    alert_type,
                    severity,
                    source_ip,
                    detail,
                    timestamp,
                    rule_id,
                    confidence,
                    status,
                    analyst_notes,
                    recommended_action,
                    evidence_json,
                    threat_intel_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_type,
                    alert.severity,
                    alert.source_ip,
                    alert.detail,
                    alert.timestamp.isoformat(),
                    alert.rule_id,
                    alert.confidence,
                    "OPEN",
                    None,
                    None,
                    self._evidence_json(alert),
                    self._threat_intel_json(alert),
                ),
            )

        connection.commit()
        connection.close()

    def get_alert_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM alerts"
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_open_alert_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'OPEN'
            """
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_investigating_alert_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'INVESTIGATING'
            """
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_resolved_alert_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'RESOLVED'
            """
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_false_positive_alert_count(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'FALSE_POSITIVE'
            """
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def get_recent_alerts(self, limit=50):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    def get_all_alerts(self):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY timestamp DESC, id DESC
            """
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    def get_alert_count_by_severity(self, severity):
        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM alerts
            WHERE severity = ?
            """,
            (severity,),
        )

        count = cursor.fetchone()[0]

        connection.close()

        return count

    def update_alert_status(self, alert_id, status):
        """
        Update the lifecycle status of an alert.

        Supported statuses:

        OPEN
        INVESTIGATING
        RESOLVED
        FALSE_POSITIVE
        """

        valid_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
            "FALSE_POSITIVE",
        }

        if status not in valid_statuses:
            raise ValueError(
                f"Invalid alert status: {status}"
            )

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET status = ?
            WHERE id = ?
            """,
            (
                status,
                alert_id,
            ),
        )

        connection.commit()
        connection.close()

        self.add_audit_entry(
            action="ALERT_STATUS_CHANGED",
            alert_id=alert_id,
            actor="analyst",
            detail=f"status={status}",
        )

    # =============================================================
    # DETECTION STATE METHODS
    # =============================================================

    def initialize_detection_state(self):
        """
        Create the persistent detection state table.

        Detection state allows SENTRY detection rules to preserve
        correlation information across API/process restarts.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS detection_state (
                rule_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                last_alert_timestamp TEXT NOT NULL,
                PRIMARY KEY (rule_id, source_ip)
            )
            """
        )

        connection.commit()
        connection.close()

    def get_detection_state(self, rule_id, source_ip):
        """
        Retrieve the last alert timestamp for a detection rule
        and source IP.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT last_alert_timestamp
            FROM detection_state
            WHERE rule_id = ?
            AND source_ip = ?
            """,
            (rule_id, source_ip),
        )

        row = cursor.fetchone()
        connection.close()

        if row is None:
            return None

        return row["last_alert_timestamp"]

    def set_detection_state(
        self,
        rule_id,
        source_ip,
        last_alert_timestamp,
    ):
        """Store or update persistent detection state."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO detection_state (
                rule_id,
                source_ip,
                last_alert_timestamp
            )
            VALUES (?, ?, ?)
            ON CONFLICT(rule_id, source_ip)
            DO UPDATE SET
                last_alert_timestamp = excluded.last_alert_timestamp
            """,
            (rule_id, source_ip, last_alert_timestamp),
        )

        connection.commit()
        connection.close()

    def clear_detection_state(self, rule_id, source_ip):
        """Remove persistent detection state for a rule/source pair."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM detection_state
            WHERE rule_id = ?
            AND source_ip = ?
            """,
            (rule_id, source_ip),
        )

        connection.commit()
        connection.close()

    # =============================================================
    # ALERT DEDUPLICATION METHODS
    # =============================================================

    def initialize_alert_dedup(self):
        """
        Create the persistent alert deduplication table.

        The table is additive: existing databases keep every event,
        alert and detection_state row. One row is stored per stable
        detection fingerprint, recording when its alert was emitted,
        when the detection was last seen and how often it was
        suppressed during the cooldown.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_dedup (
                fingerprint TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                source_ip TEXT,
                last_alert_timestamp TEXT NOT NULL,
                last_seen_timestamp TEXT,
                suppressed_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_dedup_rule_id
            ON alert_dedup (rule_id)
            """
        )

        connection.commit()
        connection.close()

    def get_alert_dedup_state(self, fingerprint):
        """Return the deduplication state for a detection fingerprint."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                fingerprint,
                rule_id,
                source_ip,
                last_alert_timestamp,
                last_seen_timestamp,
                suppressed_count
            FROM alert_dedup
            WHERE fingerprint = ?
            """,
            (fingerprint,),
        )

        row = cursor.fetchone()
        connection.close()

        if row is None:
            return None

        return {
            "fingerprint": row["fingerprint"],
            "rule_id": row["rule_id"],
            "source_ip": row["source_ip"],
            "last_alert_timestamp": row["last_alert_timestamp"],
            "last_seen_timestamp": row["last_seen_timestamp"],
            "suppressed_count": row["suppressed_count"],
        }

    def record_alert_dedup(
        self,
        fingerprint,
        rule_id,
        source_ip,
        alert_timestamp,
    ):
        """
        Record that an alert was emitted for this fingerprint.

        The alert timestamp anchors the cooldown. Suppression history
        is preserved across new alerts for the same fingerprint.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO alert_dedup (
                fingerprint,
                rule_id,
                source_ip,
                last_alert_timestamp,
                last_seen_timestamp,
                suppressed_count
            )
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(fingerprint)
            DO UPDATE SET
                rule_id = excluded.rule_id,
                source_ip = excluded.source_ip,
                last_alert_timestamp = excluded.last_alert_timestamp,
                last_seen_timestamp = excluded.last_seen_timestamp
            """,
            (
                fingerprint,
                rule_id,
                source_ip,
                alert_timestamp,
                alert_timestamp,
            ),
        )

        connection.commit()
        connection.close()

    def record_suppressed_detection(self, fingerprint, seen_timestamp):
        """
        Record a detection suppressed by an active cooldown.

        The alert timestamp is deliberately left unchanged so the
        cooldown is measured from the last emitted alert, not from the
        latest suppressed occurrence. This lets an ongoing campaign
        alert again once the cooldown expires.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alert_dedup
            SET
                suppressed_count = suppressed_count + 1,
                last_seen_timestamp = ?
            WHERE fingerprint = ?
            """,
            (seen_timestamp, fingerprint),
        )

        connection.commit()
        connection.close()

    # =============================================================
    # ALERT INVESTIGATION METHODS
    # =============================================================

    def get_alert_by_id(self, alert_id):
        """
        Retrieve a single alert by its database ID.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        )

        row = cursor.fetchone()

        connection.close()

        return row

    def get_related_events(
        self,
        source_ip,
        alert_timestamp,
        window_seconds=120,
    ):
        """
        Retrieve events from the same source IP around
        the time of an alert.

        The default investigation window is:

            alert time - 120 seconds
            alert time + 120 seconds
        """

        from datetime import datetime, timedelta

        alert_time = datetime.fromisoformat(
            alert_timestamp
        )

        start_time = (
            alert_time
            - timedelta(seconds=window_seconds)
        )

        end_time = (
            alert_time
            + timedelta(seconds=window_seconds)
        )

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
            AND timestamp >= ?
            AND timestamp <= ?
            ORDER BY timestamp ASC, id ASC
            """,
            (
                source_ip,
                start_time.isoformat(),
                end_time.isoformat(),
            ),
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    # =============================================================
    # INVESTIGATION NOTES
    # =============================================================

    def update_investigation(
        self,
        alert_id,
        analyst_notes,
        recommended_action,
    ):
        """
        Save analyst investigation notes and
        recommended action for an alert.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE alerts
            SET analyst_notes = ?,
                recommended_action = ?
            WHERE id = ?
            """,
            (
                analyst_notes,
                recommended_action,
                alert_id,
            ),
        )

        connection.commit()
        connection.close()

        self.add_audit_entry(
            action="ALERT_INVESTIGATION_UPDATED",
            alert_id=alert_id,
            actor="analyst",
            detail="analyst notes / recommended action updated",
        )

    def get_investigation(self, alert_id):
        """
        Retrieve investigation notes and
        recommended action for an alert.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                analyst_notes,
                recommended_action
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        )

        row = cursor.fetchone()

        connection.close()

        return row

    # =============================================================
    # SUPPORT TABLES (ENRICHMENT, AUDIT, ML BASELINE, NOTIFICATIONS)
    # =============================================================

    def initialize_support_tables(self):
        """
        Create optional-feature tables and query indexes.

        All statements are additive and safe for existing databases.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_cache (
                ip TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                source TEXT,
                score REAL,
                details_json TEXT,
                last_checked TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                alert_id INTEGER,
                actor TEXT,
                detail TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_state (
                rule_id TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                last_sent TEXT NOT NULL,
                PRIMARY KEY (rule_id, source_ip)
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ml_baseline (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                baseline_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp "
            "ON events(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_source_ip "
            "ON events(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp "
            "ON alerts(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id "
            "ON alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status "
            "ON alerts(status)",
        ):
            cursor.execute(statement)

        connection.commit()
        connection.close()

    # =============================================================
    # DETECTION EVIDENCE METHODS
    # =============================================================

    @staticmethod
    def _threat_intel_json(alert):
        """Serialize threat intelligence enrichment for storage."""

        if alert.threat_intel is None:
            return None

        try:
            return json.dumps(
                alert.threat_intel,
                default=str,
            )
        except (TypeError, ValueError):
            return None

    def get_alert_threat_intel(self, alert_id):
        """
        Return stored threat intelligence for an alert, or None.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT threat_intel_json
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        )

        row = cursor.fetchone()

        connection.close()

        if row is None or not row["threat_intel_json"]:
            return None

        try:
            parsed = json.loads(row["threat_intel_json"])
        except (TypeError, ValueError):
            return None

        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def _evidence_json(alert):
        """Serialize an alert's structured evidence for storage."""

        if alert.evidence is None:
            return None

        try:
            return json.dumps(alert.evidence, default=str)
        except (TypeError, ValueError):
            return None

    def get_alert_evidence(self, alert_id):
        """
        Return the structured detection evidence for one alert.

        Legacy alerts created before detection evidence was stored, and
        rows whose evidence cannot be parsed, return None. No evidence
        is ever fabricated.
        """

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT evidence_json
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        )

        row = cursor.fetchone()

        connection.close()

        if row is None:
            return None

        raw = row["evidence_json"]

        if not raw:
            return None

        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            return None

        if not isinstance(parsed, dict):
            return None

        return parsed

    # =============================================================
    # AUDIT LOG
    # =============================================================

    def add_audit_entry(
        self,
        action,
        alert_id=None,
        actor="analyst",
        detail=None,
    ):
        """Record an analyst or system action."""

        from datetime import datetime

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO audit_log (
                timestamp,
                action,
                alert_id,
                actor,
                detail
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                action,
                alert_id,
                actor,
                detail,
            ),
        )

        connection.commit()
        connection.close()

    def get_audit_log(self, limit=100):
        """Return recent audit entries, newest first."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT *
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

        rows = cursor.fetchall()

        connection.close()

        return rows

    # =============================================================
    # THREAT INTELLIGENCE CACHE
    # =============================================================

    def get_intel_cache(self, ip_address):
        """Return a cached reputation entry for an IP, or None."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                ip,
                status,
                source,
                score,
                details_json,
                last_checked
            FROM intel_cache
            WHERE ip = ?
            """,
            (ip_address,),
        )

        row = cursor.fetchone()

        connection.close()

        if row is None:
            return None

        return {
            "ip": row["ip"],
            "status": row["status"],
            "source": row["source"],
            "score": row["score"],
            "details": row["details_json"],
            "last_checked": row["last_checked"],
        }

    def set_intel_cache(self, entry):
        """Store or refresh a reputation cache entry."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO intel_cache (
                ip,
                status,
                source,
                score,
                details_json,
                last_checked
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip)
            DO UPDATE SET
                status = excluded.status,
                source = excluded.source,
                score = excluded.score,
                details_json = excluded.details_json,
                last_checked = excluded.last_checked
            """,
            (
                entry.get("ip"),
                entry.get("status", "unknown"),
                entry.get("source"),
                entry.get("score"),
                entry.get("details"),
                entry.get("last_checked"),
            ),
        )

        connection.commit()
        connection.close()

    # =============================================================
    # ML BASELINE
    # =============================================================

    def get_ml_baseline(self):
        """Return the stored anomaly baseline, or None."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT baseline_json FROM ml_baseline WHERE id = 1"
        )

        row = cursor.fetchone()

        connection.close()

        if row is None:
            return None

        try:
            return json.loads(row["baseline_json"])
        except (TypeError, ValueError):
            return None

    def set_ml_baseline(self, baseline):
        """Store the anomaly baseline."""

        from datetime import datetime

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO ml_baseline (
                id,
                baseline_json,
                updated_at
            )
            VALUES (1, ?, ?)
            ON CONFLICT(id)
            DO UPDATE SET
                baseline_json = excluded.baseline_json,
                updated_at = excluded.updated_at
            """,
            (
                json.dumps(baseline, default=str),
                datetime.now().isoformat(),
            ),
        )

        connection.commit()
        connection.close()

    # =============================================================
    # NOTIFICATION STATE
    # =============================================================

    def get_notification_state(self, rule_id, source_ip):
        """Return the last notification time, or None."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT last_sent
            FROM notification_state
            WHERE rule_id = ?
            AND source_ip = ?
            """,
            (rule_id, source_ip),
        )

        row = cursor.fetchone()

        connection.close()

        if row is None:
            return None

        return row["last_sent"]

    def set_notification_state(self, rule_id, source_ip, last_sent):
        """Store the last notification time for a rule/source pair."""

        connection = self.get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO notification_state (
                rule_id,
                source_ip,
                last_sent
            )
            VALUES (?, ?, ?)
            ON CONFLICT(rule_id, source_ip)
            DO UPDATE SET
                last_sent = excluded.last_sent
            """,
            (rule_id, source_ip, last_sent),
        )

        connection.commit()
        connection.close()
