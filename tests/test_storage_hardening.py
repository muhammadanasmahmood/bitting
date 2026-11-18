"""Regression tests for storage hardening.

- mark_rotated is an atomic conditional claim in both built-in stores.
- InMemoryStore hands out and stores copies, never live records.
- list_events rejects limits < 1 in both stores.
- delete_events_before prunes audit history in both stores.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bitting import InMemoryStore, SQLiteStore
from bitting.models import AuditEvent, AuditEventKind, KeyRecord

_T0 = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)


def _record(prefix: str = "aaaabbbbccccdddd") -> KeyRecord:
    return KeyRecord(
        key_id="id-1",
        prefix=prefix,
        hash="$scrypt$test",
        algorithm="scrypt",
        scopes=frozenset({"read:users"}),
        created_at=_T0,
    )


def _event(prefix: str, at: datetime) -> AuditEvent:
    return AuditEvent(kind=AuditEventKind.ISSUED, prefix=prefix, at=at, detail={})


class TestInMemoryIsolation:
    def test_fetched_record_is_a_copy(self) -> None:
        store = InMemoryStore()
        store.save(_record())
        fetched = store.find_by_prefix("aaaabbbbccccdddd")
        assert fetched is not None
        fetched.revoked_at = _T0
        fresh = store.find_by_prefix("aaaabbbbccccdddd")
        assert fresh is not None and fresh.revoked_at is None

    def test_saving_does_not_alias_the_callers_object(self) -> None:
        store = InMemoryStore()
        record = _record()
        store.save(record)
        record.revoked_at = _T0  # caller mutates after saving
        fetched = store.find_by_prefix("aaaabbbbccccdddd")
        assert fetched is not None and fetched.revoked_at is None

    def test_list_keys_returns_copies(self) -> None:
        store = InMemoryStore()
        store.save(_record())
        listed = store.list_keys()
        listed[0].revoked_at = _T0
        fresh = store.find_by_prefix("aaaabbbbccccdddd")
        assert fresh is not None and fresh.revoked_at is None

    def test_metadata_is_copied(self) -> None:
        store = InMemoryStore()
        record = _record()
        record.metadata["team"] = "platform"
        store.save(record)
        fetched = store.find_by_prefix("aaaabbbbccccdddd")
        assert fetched is not None
        fetched.metadata["team"] = "mutated"
        again = store.find_by_prefix("aaaabbbbccccdddd")
        assert again is not None and again.metadata["team"] == "platform"


class TestListEventsLimitValidation:
    @pytest.mark.parametrize("limit", [0, -1])
    def test_in_memory_rejects_non_positive_limit(self, limit: int) -> None:
        with pytest.raises(ValueError, match="limit"):
            InMemoryStore().list_events(limit=limit)

    @pytest.mark.parametrize("limit", [0, -1])
    def test_sqlite_rejects_non_positive_limit(self, limit: int, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        try:
            with pytest.raises(ValueError, match="limit"):
                store.list_events(limit=limit)
        finally:
            store.close()


class TestMarkRotated:
    def test_in_memory_claim_semantics(self) -> None:
        store = InMemoryStore()
        store.save(_record())
        claim = dict(rotated_at=_T0, grace_until=_T0 + timedelta(hours=1))
        assert store.mark_rotated("aaaabbbbccccdddd", **claim) is True
        # Second claim loses; revoked and missing prefixes lose too.
        assert store.mark_rotated("aaaabbbbccccdddd", **claim) is False
        record = store.find_by_prefix("aaaabbbbccccdddd")
        assert record is not None and record.rotated_at == _T0

        store.save(_record("eeeeffffgggghhhh"))
        revoked = store.find_by_prefix("eeeeffffgggghhhh")
        assert revoked is not None
        revoked.revoked_at = _T0
        store.save(revoked)
        assert store.mark_rotated("eeeeffffgggghhhh", **claim) is False
        assert store.mark_rotated("missingmissing1", **claim) is False

    def test_sqlite_claim_visible_across_connections(self, tmp_path) -> None:
        path = tmp_path / "keys.db"
        first = SQLiteStore(path)
        second = SQLiteStore(path)
        try:
            first.save(_record())
            claim = dict(rotated_at=_T0, grace_until=_T0 + timedelta(hours=1))
            assert first.mark_rotated("aaaabbbbccccdddd", **claim) is True
            # A different connection (i.e. another process sharing the
            # file) cannot claim the same transition.
            assert second.mark_rotated("aaaabbbbccccdddd", **claim) is False
            record = second.find_by_prefix("aaaabbbbccccdddd")
            assert record is not None and record.rotated_at == _T0
        finally:
            first.close()
            second.close()


class TestDeleteEventsBefore:
    def test_in_memory_prune(self) -> None:
        store = InMemoryStore()
        store.append_event(_event("p1", _T0))
        store.append_event(_event("p2", _T0 + timedelta(hours=1)))
        store.append_event(_event("p3", _T0 + timedelta(hours=2)))
        cutoff = _T0 + timedelta(hours=1)
        removed = store.delete_events_before(cutoff)
        assert removed == 1  # strictly older than the cutoff
        assert [event.prefix for event in store.list_events(limit=10)] == ["p3", "p2"]

    def test_sqlite_prune(self, tmp_path) -> None:
        store = SQLiteStore(tmp_path / "keys.db")
        try:
            store.append_event(_event("p1", _T0))
            store.append_event(_event("p2", _T0 + timedelta(hours=1)))
            cutoff = _T0 + timedelta(minutes=30)
            assert store.delete_events_before(cutoff) == 1
            remaining = store.list_events(limit=10)
            assert [event.prefix for event in remaining] == ["p2"]
            assert store.delete_events_before(cutoff) == 0
        finally:
            store.close()


class TestKeyRecordRepr:
    def test_repr_redacts_the_hash(self) -> None:
        record = _record()
        assert "hash=<redacted" in repr(record)
        assert "$scrypt$test" not in repr(record)
        assert record.hash not in repr(record)
