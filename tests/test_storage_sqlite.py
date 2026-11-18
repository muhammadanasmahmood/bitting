"""Tests for the SQLite store: persistence, WAL, concurrency, and events."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from bitting import KeyRecord, SQLiteStore, StorageError
from bitting.models import AuditEvent, AuditEventKind


def _record(prefix: str, *, key_id: str = "id-1") -> KeyRecord:
    return KeyRecord(
        key_id=key_id,
        prefix=prefix,
        hash="$scrypt$test",
        algorithm="scrypt",
        scopes=frozenset({"read:users", "write:posts"}),
        created_at=datetime(2026, 1, 1, 12, tzinfo=timezone.utc),
        description="test key",
        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        metadata={"team": "platform"},
    )


class TestSQLiteStore:
    def test_persistence_across_reopen(self, tmp_path) -> None:
        path = tmp_path / "keys.db"
        store = SQLiteStore(path)
        store.save(_record("aaaabbbbccccdddd"))
        store.close()

        reopened = SQLiteStore(path)
        record = reopened.find_by_prefix("aaaabbbbccccdddd")
        assert record is not None
        assert record.key_id == "id-1"
        assert record.scopes == frozenset({"read:users", "write:posts"})
        assert record.metadata == {"team": "platform"}
        assert record.expires_at == datetime(2030, 1, 1, tzinfo=timezone.utc)
        reopened.close()

    def test_wal_mode_enabled(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        mode = store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        store.close()
        assert mode.lower() == "wal"

    def test_creates_parent_directories(self, tmp_path) -> None:
        path = tmp_path / "nested" / "deeper" / "keys.db"
        store = SQLiteStore(path)
        store.save(_record("aaaabbbbccccdddd"))
        store.close()
        assert path.exists()

    def test_update_roundtrip(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        record = _record("aaaabbbbccccdddd")
        store.save(record)
        record.revoked_at = datetime(2026, 2, 1, tzinfo=timezone.utc)
        store.save(record)
        fetched = store.find_by_prefix("aaaabbbbccccdddd")
        assert fetched is not None and fetched.revoked_at == datetime(
            2026, 2, 1, tzinfo=timezone.utc
        )
        store.close()

    def test_list_keys_ordered_by_creation(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        for i in range(3):
            record = _record(f"prefix{i:016d}", key_id=f"id-{i}")
            record.created_at = datetime(2026, 1, i + 1, tzinfo=timezone.utc)
            store.save(record)
        assert [r.key_id for r in store.list_keys()] == ["id-0", "id-1", "id-2"]
        store.close()

    def test_events_persisted(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        store.append_event(
            AuditEvent(
                kind=AuditEventKind.VERIFIED,
                prefix="aaaabbbbccccdddd",
                at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                detail={"reason": "ok"},
            )
        )
        events = store.list_events()
        assert len(events) == 1
        assert events[0].kind is AuditEventKind.VERIFIED
        assert events[0].detail == {"reason": "ok"}
        store.close()

    def test_concurrent_issue_from_threads(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")

        def save(i: int) -> str:
            prefix = f"{i:016d}"
            store.save(_record(prefix, key_id=f"id-{i}"))
            return prefix

        with ThreadPoolExecutor(max_workers=8) as pool:
            prefixes = list(pool.map(save, range(40)))
        assert len(set(prefixes)) == 40
        assert len(store.list_keys()) == 40
        store.close()

    def test_in_memory_database(self) -> None:
        store = SQLiteStore(":memory:")
        store.save(_record("aaaabbbbccccdddd"))
        assert store.find_by_prefix("aaaabbbbccccdddd") is not None
        store.close()

    def test_open_failure_raises_storage_error(self, tmp_path) -> None:
        # A directory where a database file is expected must fail cleanly.
        with pytest.raises(StorageError):
            SQLiteStore(tmp_path)  # tmp_path itself is a directory

    def test_schema_version_guard(self, tmp_path) -> None:
        path = tmp_path / "keys.db"
        store = SQLiteStore(path)
        store.close()
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA user_version=99")
        conn.commit()
        conn.close()
        with pytest.raises(StorageError):
            SQLiteStore(path)
