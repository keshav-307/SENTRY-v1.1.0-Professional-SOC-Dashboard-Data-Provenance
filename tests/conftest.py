"""Shared pytest isolation for SENTRY database tests."""

import pytest


@pytest.fixture(autouse=True)
def isolated_default_database(tmp_path, monkeypatch):
    """
    Point SENTRY's default database at a per-test temporary file.

    Tests that pass an explicit database path keep using that path. Any test
    (or helper) that constructs a database without a path cannot fall through
    to the developer's sentry.db or sentry_demo.db.
    """

    database_path = tmp_path / "sentry-test-default.db"
    monkeypatch.setenv("SENTRY_DB_PATH", str(database_path))

    yield database_path
