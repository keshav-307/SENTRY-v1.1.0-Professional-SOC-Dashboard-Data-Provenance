from datetime import datetime

from core.database import (
    DEFAULT_DATABASE_PATH,
    PROJECT_ROOT,
    SentryDatabase,
    resolve_database_path,
)
from core.models import SecurityEvent


def sample_event(source_ip="192.0.2.10"):
    return SecurityEvent(
        timestamp=datetime.now(),
        source="network",
        event_type="connection",
        source_ip=source_ip,
        destination_port=443,
        protocol="TCP",
        event_origin="SYNTHETIC",
    )


def test_default_resolves_to_project_development_database(monkeypatch):
    monkeypatch.delenv("SENTRY_DB_PATH", raising=False)

    assert resolve_database_path() == DEFAULT_DATABASE_PATH
    assert DEFAULT_DATABASE_PATH == PROJECT_ROOT / "sentry.db"


def test_relative_path_is_project_relative_not_current_directory(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    assert resolve_database_path("sentry_demo.db") == (
        PROJECT_ROOT / "sentry_demo.db"
    )


def test_relative_environment_path_uses_project_root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SENTRY_DB_PATH", "configured-demo.db")

    assert resolve_database_path() == PROJECT_ROOT / "configured-demo.db"


def test_absolute_path_is_preserved(tmp_path):
    absolute_path = tmp_path / "absolute.db"

    assert resolve_database_path(absolute_path) == absolute_path


def test_test_environment_never_defaults_to_a_real_database(tmp_path):
    resolved = resolve_database_path()

    assert resolved == tmp_path / "sentry-test-default.db"
    assert resolved != PROJECT_ROOT / "sentry.db"
    assert resolved != PROJECT_ROOT / "sentry_demo.db"


def test_fresh_database_is_empty_and_persists_between_instances(tmp_path):
    path = tmp_path / "fresh.db"

    first = SentryDatabase(path)

    assert path.exists()
    assert first.get_event_count() == 0
    assert first.get_alert_count() == 0
    assert first.database_path == path

    connection = first.get_connection()
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    connection.close()

    assert {
        "events",
        "alerts",
        "alert_dedup",
        "audit_log",
        "detection_state",
        "intel_cache",
        "ml_baseline",
        "notification_state",
    }.issubset(tables)

    second = SentryDatabase(path)

    assert second.get_event_count() == 0
    assert second.get_alert_count() == 0


def test_development_and_demo_databases_are_independent(tmp_path):
    development = SentryDatabase(tmp_path / "development.db")
    demo = SentryDatabase(tmp_path / "demo.db")

    demo.save_event(sample_event())

    assert demo.get_event_count() == 1
    assert development.get_event_count() == 0
    assert demo.database_path != development.database_path


def test_environment_selected_demo_database_persists(monkeypatch, tmp_path):
    demo_path = tmp_path / "demo.db"
    monkeypatch.setenv("SENTRY_DB_PATH", str(demo_path))

    first = SentryDatabase()
    first.save_event(sample_event())

    assert first.database_path == demo_path
    assert first.get_event_count() == 1

    restarted = SentryDatabase()

    assert restarted.database_path == demo_path
    assert restarted.get_event_count() == 1


def test_schema_initialization_is_idempotent_on_fresh_database(tmp_path):
    path = tmp_path / "repeat.db"

    SentryDatabase(path)
    second = SentryDatabase(path)

    connection = second.get_connection()
    event_columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(events)")
    ]
    alert_columns = [
        row["name"]
        for row in connection.execute("PRAGMA table_info(alerts)")
    ]
    connection.close()

    assert event_columns.count("event_origin") == 1
    assert alert_columns.count("event_origin") == 1
    assert second.get_event_count() == 0
    assert second.get_alert_count() == 0
