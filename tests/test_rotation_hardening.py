"""Regression tests for rotation hardening.

- A rotated key's grace window is capped by the key's original expiry.
- The active→rotated transition is an atomic claim, so concurrent
  rotations of the same key cannot both succeed.
- Negative grace is rejected.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from tests.conftest import FrozenClock

from bitting import InMemoryStore, KeyManager, SQLiteStore, VerifyReason


class TestGraceCappedByExpiry:
    def test_expired_key_rejected_inside_grace_window(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        old = manager.issue(ttl=timedelta(hours=2))
        manager.rotate(old.prefix, grace=timedelta(hours=24))
        clock.advance(hours=3)  # 1h past expiry, well inside grace
        result = manager.verify(old.raw_key)
        assert not result.ok
        assert result.reason is VerifyReason.EXPIRED

    def test_unexpired_rotated_key_still_works_in_grace(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        old = manager.issue(ttl=timedelta(days=30))
        manager.rotate(old.prefix, grace=timedelta(hours=24))
        clock.advance(hours=1)
        result = manager.verify(old.raw_key)
        assert result.ok and result.reason is VerifyReason.ROTATED_GRACE

    def test_expiry_reason_wins_when_both_grace_and_ttl_have_passed(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        old = manager.issue(ttl=timedelta(hours=2))
        manager.rotate(old.prefix, grace=timedelta(hours=3))
        clock.advance(hours=10)
        result = manager.verify(old.raw_key)
        assert result.reason is VerifyReason.EXPIRED

    def test_grace_shorter_than_ttl_behaves_as_before(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        old = manager.issue(ttl=timedelta(days=30))
        manager.rotate(old.prefix, grace=timedelta(hours=1))
        clock.advance(hours=2)
        assert manager.verify(old.raw_key).reason is VerifyReason.ROTATED


class TestNegativeGraceRejected:
    def test_negative_grace_is_a_value_error(self, manager: KeyManager) -> None:
        issued = manager.issue()
        with pytest.raises(ValueError, match="non-negative"):
            manager.rotate(issued.prefix, grace=timedelta(hours=-1))

    def test_zero_grace_allowed_old_key_dies_immediately(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        old = manager.issue()
        manager.rotate(old.prefix, grace=timedelta(0))
        clock.advance(seconds=1)
        assert manager.verify(old.raw_key).reason is VerifyReason.ROTATED


class TestAtomicRotation:
    def test_concurrent_rotations_single_successor_on_sqlite(
        self, fast_hasher, clock, tmp_path
    ) -> None:
        """Deterministic interleaving: thread 1 holds a stale snapshot
        mid-rotate while thread 2 completes a full rotation."""
        path = tmp_path / "race.db"
        gate = threading.Event()
        proceed = threading.Event()

        class PausingStore(SQLiteStore):
            def __init__(self, p) -> None:
                super().__init__(p)
                self._first = True

            def find_by_prefix(self, prefix):  # type: ignore[override]
                record = super().find_by_prefix(prefix)
                if self._first and record is not None and record.rotated_at is None:
                    self._first = False
                    gate.set()  # thread 1 now holds a fresh, un-rotated snapshot
                    proceed.wait(5)  # ...while thread 2 finishes a whole rotation
                return record

        pausing = PausingStore(path)
        other = SQLiteStore(path)
        m1 = KeyManager(pausing, hasher=fast_hasher, now_fn=clock)
        m2 = KeyManager(other, hasher=fast_hasher, now_fn=clock)
        old = m1.issue()
        outcome: dict[str, str] = {}

        def rotate_first() -> None:
            try:
                outcome["m1"] = "won"
                m1.rotate(old.prefix)
            except ValueError:
                outcome["m1"] = "rejected"

        thread = threading.Thread(target=rotate_first)
        thread.start()
        assert gate.wait(5)
        try:
            m2.rotate(old.prefix)
            outcome["m2"] = "won"
        except ValueError:
            outcome["m2"] = "rejected"
        proceed.set()
        thread.join(5)

        successors = [r for r in other.list_keys() if r.supersedes == old.prefix]
        assert sorted(outcome.values()) == ["rejected", "won"]
        assert len(successors) == 1, "exactly one successor key may exist"
        pausing.close()
        other.close()

    def test_concurrent_rotations_single_successor_in_memory(self, fast_hasher, clock) -> None:
        manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
        old = manager.issue()
        barrier = threading.Barrier(8)
        results: list[str] = []

        def rotate() -> None:
            barrier.wait(5)
            try:
                manager.rotate(old.prefix)
                results.append("won")
            except ValueError:
                results.append("rejected")

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: rotate(), range(8)))

        successors = [r for r in manager.list_keys() if r.supersedes == old.prefix]
        assert results.count("won") == 1
        assert len(successors) == 1

    def test_mark_rotated_refuses_revoked_keys(self, fast_hasher, clock) -> None:
        manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
        issued = manager.issue()
        manager.revoke(issued.prefix)
        assert (
            manager.store.mark_rotated(
                issued.prefix,
                rotated_at=clock.now,
                grace_until=clock.now + timedelta(hours=1),
            )
            is False
        )

    def test_successor_does_not_inherit_ttl(self, manager: KeyManager, clock: FrozenClock) -> None:
        """Documented behavior: successors need their own ttl."""
        old = manager.issue(ttl=timedelta(days=1))
        new = manager.rotate(old.prefix, grace=timedelta(hours=1))
        assert new.record.expires_at is None
        new_with_ttl = manager.rotate(new.prefix, ttl=timedelta(days=7))
        assert new_with_ttl.record.expires_at == clock.now + timedelta(days=7)
