"""Tests for the in-memory store."""

from __future__ import annotations

from datetime import datetime, timezone

from bitting import InMemoryStore
from bitting.models import AuditEvent, AuditEventKind, KeyRecord


def _record(prefix: str = "abcdefghijklmnop") -> KeyRecord:
    return KeyRecord(
        key_id="id-1",
        prefix=prefix,
        hash="$scrypt$test",
        algorithm="scrypt",
        scopes=frozenset({"read"}),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


class TestInMemoryStore:
    def test_save_and_find(self) -> None:
        store = InMemoryStore()
        record = _record()
        store.save(record)
        assert store.find_by_prefix("abcdefghijklmnop") == record

    def test_find_missing_returns_none(self) -> None:
        assert InMemoryStore().find_by_prefix("nope") is None

    def test_delete(self) -> None:
        store = InMemoryStore()
        store.save(_record())
        assert store.delete("abcdefghijklmnop") is True
        assert store.delete("abcdefghijklmnop") is False
        assert store.find_by_prefix("abcdefghijklmnop") is None

    def test_list_keys(self) -> None:
        store = InMemoryStore()
        store.save(_record("aaaabbbbccccdddd"))
        store.save(_record("eeeeffffgggghhhh"))
        assert len(store.list_keys()) == 2

    def test_update_overwrites(self) -> None:
        store = InMemoryStore()
        record = _record()
        store.save(record)
        record.description = "updated"
        store.save(record)
        assert store.find_by_prefix(record.prefix).description == "updated"

    def test_events_roundtrip_newest_first(self) -> None:
        store = InMemoryStore()
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(5):
            store.append_event(
                AuditEvent(kind=AuditEventKind.ISSUED, prefix=f"p{i}", at=base, detail={"i": i})
            )
        events = store.list_events(limit=3)
        assert [event.prefix for event in events] == ["p4", "p3", "p2"]
