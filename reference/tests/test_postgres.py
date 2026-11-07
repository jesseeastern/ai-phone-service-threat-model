"""Tests against a real Postgres. Skipped unless TEST_DATABASE_URL is set.

    TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest

These wipe the tables, so don't point them at anything you care about.
"""

import asyncio
import json
import os
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from app import main, signature
from app.store import PostgresStore

DB_URL = os.environ.get("TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DB_URL, reason="TEST_DATABASE_URL not set")

SCHEMA = (Path(__file__).parent.parent / "db-init" / "01-schema.sql").read_text()
TABLES = "sessions, messages, tool_decisions, rate_limits, daily_spend"


@pytest.fixture(autouse=True)
def clean_db():
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        conn.execute(SCHEMA)
        conn.execute(f"TRUNCATE {TABLES} RESTART IDENTITY")
    yield


def query(sql, params=None):
    with psycopg.connect(DB_URL) as conn:
        return conn.execute(sql, params).fetchall()


def with_store(fn):
    """Run an async test body with a fresh pool, like a fresh app instance."""

    async def runner():
        async with AsyncConnectionPool(DB_URL, min_size=1, max_size=20, open=False) as pool:
            await pool.open(wait=True)
            return await fn(PostgresStore(pool))

    return asyncio.run(runner())


def test_rate_limit_holds_under_concurrent_requests():
    async def body(store):
        return await asyncio.gather(*(store.hit("in:abc", 10, 600) for _ in range(50)))

    results = with_store(body)
    assert results.count(True) == 10


def test_rate_limit_survives_restart():
    async def five_hits(store):
        return [await store.hit("in:abc", 8, 600) for _ in range(5)]

    assert with_store(five_hits) == [True] * 5
    # new pool, new store: same as the app restarting
    assert with_store(five_hits) == [True, True, True, False, False]


def test_spend_cap_holds_under_concurrent_requests():
    async def body(store):
        return await asyncio.gather(*(store.reserve_spend(1, 10) for _ in range(30)))

    assert with_store(body).count(True) == 10
    assert query("SELECT cents FROM daily_spend") == [(10,)]


def test_spend_over_budget_on_first_charge_adds_nothing():
    async def body(store):
        return await store.reserve_spend(50, 10)

    assert with_store(body) is False
    assert query("SELECT * FROM daily_spend") == []


def test_messages_from_same_caller_share_a_session():
    async def body(store):
        await store.record_message("h1", "+1506***1234", "sms", "in", "hi")
        await store.record_message("h1", "+1506***1234", "sms", "out", "hello")
        await store.record_message("h2", "+1902***9999", "sms", "in", "hey")

    with_store(body)
    assert query("SELECT count(*) FROM sessions") == [(2,)]
    assert query("SELECT count(DISTINCT session_id) FROM messages") == [(2,)]


def test_app_writes_history_to_postgres(monkeypatch):
    monkeypatch.setattr(main, "DATABASE_URL", DB_URL)
    monkeypatch.setattr(main, "AUTH_TOKEN", "test-token")
    monkeypatch.setattr(main, "PUBLIC_BASE_URL", "")

    params = {"From": "+15065551234", "Body": "what are your hours"}
    sig = signature.compute_signature("test-token", "http://testserver/sms", params)
    with TestClient(main.app) as client:
        r = client.post("/sms", data=params, headers={"X-Twilio-Signature": sig})
    assert r.status_code == 200

    assert query("SELECT direction FROM messages ORDER BY id") == [("in",), ("out",)]
    assert query("SELECT tool, allowed FROM tool_decisions") == [("lookup_hours", True)]
    assert query("SELECT cents FROM daily_spend") == [(1,)]

    # the raw number shouldn't be anywhere in the database
    rows = [
        query(sql.SQL("SELECT * FROM {}").format(sql.Identifier(t))) for t in TABLES.split(", ")
    ]
    dump = json.dumps(rows, default=str)
    assert "5065551234" not in dump


def test_app_role_cannot_drop_or_delete():
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        conn.execute("ALTER ROLE assistant_app PASSWORD 'test-only'")
    app_url = psycopg.conninfo.make_conninfo(DB_URL, user="assistant_app", password="test-only")
    with psycopg.connect(app_url, autocommit=True) as conn:
        conn.execute("INSERT INTO daily_spend (day, cents) VALUES (current_date, 1)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DELETE FROM messages")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("DROP TABLE messages")
