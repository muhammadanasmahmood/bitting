"""Regression tests for manager hardening.

- Verification dispatches on the algorithm stored with each key, so
  switching the primary hasher does not invalidate existing keys.
- Last-verified persistence is throttled, verify-time audit events
  can be disabled, and audit events can be pruned.
- revoke() rejects timezone-naive timestamps.
- issue()/rotate() reject empty or whitespace-containing scopes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from tests.conftest import FrozenClock

from bitting import (
    ConfigurationError,
    InMemoryStore,
    KeyManager,
    VerifyReason,
)

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ModuleNotFoundError:  # pragma: no cover
    HAS_ARGON2 = False


class CountingStore(InMemoryStore):
    """In-memory store that counts save() and mark_verified() calls.

    Since the fix for the verify-vs-revoke lost update, the
    last_verified_at touch is persisted through mark_verified() (a
    targeted single-field update) rather than a full save(), so the
    throttling tests observe touches on that path.
    """

    def __init__(self) -> None:
        super().__init__()
        self.saves = 0
        self.touches = 0

    def save(self, record) -> None:  # type: ignore[override]
        self.saves += 1
        super().save(record)

    def mark_verified(self, prefix, *, at) -> bool:  # type: ignore[override]
        self.touches += 1
        return super().mark_verified(prefix, at=at)


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
class TestHasherDispatch:
    def test_argon2_key_verifies_under_scrypt_primary_manager(self, fast_hasher, clock) -> None:
        from bitting import Argon2Hasher

        store = InMemoryStore()
        argon_manager = KeyManager(
            store, hasher=Argon2Hasher(time_cost=1, memory_cost=8192), now_fn=clock
        )
        argon_key = argon_manager.issue(scopes={"read:users"})

        manager = KeyManager(
            store,
            hasher=fast_hasher,
            now_fn=clock,
            hashers={"argon2id": Argon2Hasher(time_cost=1, memory_cost=8192)},
        )
        result = manager.verify(argon_key.raw_key)
        assert result.ok and result.reason is VerifyReason.OK

        # The primary hasher keeps issuing and verifying its own keys.
        scrypt_key = manager.issue()
        assert manager.verify(scrypt_key.raw_key).ok

    def test_unknown_algorithm_fails_closed_as_hash_mismatch(self, fast_hasher, clock) -> None:
        from bitting import Argon2Hasher

        store = InMemoryStore()
        argon_manager = KeyManager(
            store, hasher=Argon2Hasher(time_cost=1, memory_cost=8192), now_fn=clock
        )
        argon_key = argon_manager.issue()

        scrypt_only = KeyManager(store, hasher=fast_hasher, now_fn=clock)
        result = scrypt_only.verify(argon_key.raw_key)
        assert not result.ok
        assert result.reason is VerifyReason.HASH_MISMATCH

    def test_registry_name_must_match_hasher_algorithm(self, fast_hasher, clock) -> None:
        with pytest.raises(ConfigurationError, match="must match"):
            KeyManager(
                InMemoryStore(),
                hasher=fast_hasher,
                now_fn=clock,
                hashers={"bogus-name": fast_hasher},
            )

    def test_algorithm_recorded_per_key(self, fast_hasher, clock) -> None:
        manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
        assert manager.issue().record.algorithm == "scrypt"


class TestVerifyWriteThrottling:
    def test_touch_persisted_once_per_interval(self, fast_hasher, clock) -> None:
        store = CountingStore()
        manager = KeyManager(store, hasher=fast_hasher, now_fn=clock)
        issued = manager.issue()
        saves_after_issue = store.saves
        assert store.touches == 0

        manager.verify(issued.raw_key)  # first touch: persisted
        clock.advance(seconds=10)
        manager.verify(issued.raw_key)  # within interval: not persisted
        clock.advance(seconds=10)
        manager.verify(issued.raw_key)  # still within interval: not persisted
        assert store.touches == 1
        # the touch must never fall back to a full-record save
        assert store.saves - saves_after_issue == 0

        clock.advance(seconds=60)  # now past the default 60s interval
        manager.verify(issued.raw_key)
        assert store.touches == 2
        assert store.saves - saves_after_issue == 0
        # the touch really landed in the store
        assert store.find_by_prefix(issued.prefix).last_verified_at is not None

    def test_zero_interval_restores_write_on_every_verify(self, fast_hasher, clock) -> None:
        store = CountingStore()
        manager = KeyManager(
            store,
            hasher=fast_hasher,
            now_fn=clock,
            verify_touch_interval=timedelta(0),
        )
        issued = manager.issue()
        saves_after_issue = store.saves
        for _ in range(3):
            manager.verify(issued.raw_key)
        assert store.touches == 3
        assert store.saves - saves_after_issue == 0

    def test_result_record_reflects_latest_verify(self, manager: KeyManager, clock) -> None:
        issued = manager.issue()
        clock.advance(minutes=5)
        result = manager.verify(issued.raw_key)
        assert result.record is not None
        assert result.record.last_verified_at == clock.now


class TestVerifyAuditControls:
    def test_audit_verifications_false_suppresses_verify_events_only(
        self, fast_hasher, clock
    ) -> None:
        store = InMemoryStore()
        manager = KeyManager(store, hasher=fast_hasher, now_fn=clock, audit_verifications=False)
        issued = manager.issue()
        assert len(store.list_events(limit=1000)) == 1  # the ISSUED event

        manager.verify(issued.raw_key)  # success: no event
        manager.verify("garbage")  # failure: no event
        assert len(store.list_events(limit=1000)) == 1

        manager.rotate(issued.prefix, grace=timedelta(hours=1))  # lifecycle: kept
        kinds = [event.kind.value for event in store.list_events(limit=1000)]
        assert kinds == ["rotated", "issued"]

    def test_prune_events_removes_old_events(self, fast_hasher, clock) -> None:
        manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
        issued = manager.issue()  # t0
        manager.verify(issued.raw_key)  # t0
        clock.advance(hours=1)
        manager.revoke(issued.prefix)  # t0+1h

        removed = manager.prune_events(before=clock.now)
        remaining = manager.list_events(limit=1000)
        assert removed == 2  # issued + verified
        assert [event.kind.value for event in remaining] == ["revoked"]

    def test_prune_events_rejects_naive_datetime(self, manager: KeyManager) -> None:
        with pytest.raises(ValueError, match="timezone-aware"):
            manager.prune_events(before=datetime(2026, 1, 1))


class TestRevokeValidation:
    def test_naive_now_rejected(self, manager: KeyManager) -> None:
        issued = manager.issue()
        with pytest.raises(ValueError, match="timezone-aware"):
            manager.revoke(issued.prefix, now=datetime(2026, 6, 1))

    def test_aware_now_accepted(self, manager: KeyManager, clock: FrozenClock) -> None:
        issued = manager.issue()
        moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
        record = manager.revoke(issued.prefix, now=moment)
        assert record.revoked_at == moment


class TestScopeValidation:
    @pytest.mark.parametrize("scopes", [{"", "read"}, {" "}, {"read\nusers"}, {"bad scope"}])
    def test_issue_rejects_invalid_scopes(self, manager: KeyManager, scopes) -> None:
        with pytest.raises(ValueError, match="scopes must be"):
            manager.issue(scopes=scopes)

    def test_rotate_rejects_invalid_scopes(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users"})
        with pytest.raises(ValueError, match="scopes must be"):
            manager.rotate(issued.prefix, scopes={"  "})

    def test_valid_scopes_still_accepted(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users", "write:posts", "read:*", "*"})
        assert issued.record.scopes == frozenset({"read:users", "write:posts", "read:*", "*"})
