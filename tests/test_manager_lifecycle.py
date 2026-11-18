"""End-to-end lifecycle tests for KeyManager: issue → verify → rotate → revoke."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from tests.conftest import FrozenClock

from bitting import (
    InMemoryStore,
    KeyManager,
    KeyNotFoundError,
    VerifyReason,
    scope_matches,
)


class TestIssue:
    def test_issue_returns_usable_key(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users"}, description="ci")
        assert issued.raw_key.startswith("btg_live_")
        assert issued.record.scopes == frozenset({"read:users"})
        assert issued.record.algorithm == "scrypt"
        assert not issued.record.is_revoked

    def test_raw_key_never_in_repr(self, manager: KeyManager) -> None:
        issued = manager.issue()
        assert issued.raw_key not in repr(issued)
        assert issued.raw_key not in str(issued)

    def test_ttl_sets_expiry(self, manager: KeyManager, clock: FrozenClock) -> None:
        issued = manager.issue(ttl=timedelta(days=30))
        assert issued.record.expires_at == clock.now + timedelta(days=30)

    def test_ttl_and_expires_at_mutually_exclusive(self, manager: KeyManager) -> None:
        with pytest.raises(ValueError):
            manager.issue(
                ttl=timedelta(days=1), expires_at=datetime(2026, 6, 1, tzinfo=timezone.utc)
            )

    def test_naive_expires_at_rejected(self, manager: KeyManager) -> None:
        with pytest.raises(ValueError):
            manager.issue(expires_at=datetime(2026, 6, 1))  # type: ignore[arg-type]

    def test_prefix_matches_stored_record(self, manager: KeyManager) -> None:
        issued = manager.issue()
        record = manager.store.find_by_prefix(issued.prefix)
        assert record is not None
        assert record.hash != issued.raw_key  # hash stored, never the key


class TestVerify:
    def test_valid_key(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users"})
        result = manager.verify(issued.raw_key)
        assert result.ok and result.reason is VerifyReason.OK
        assert result.record is not None
        assert result.record.last_verified_at is not None

    def test_garbage_key_invalid_format(self, manager: KeyManager) -> None:
        for garbage in ("", "nonsense", "btg_live_only", "sk_live_abc123"):
            result = manager.verify(garbage)
            assert not result.ok and result.reason is VerifyReason.INVALID_FORMAT

    def test_unknown_prefix_not_found(self, manager: KeyManager) -> None:
        from bitting import generate_api_key, parse_api_key

        fresh = generate_api_key()  # well-formed but never issued
        assert parse_api_key(fresh)  # sanity: format is valid
        result = manager.verify(fresh)
        assert result.reason is VerifyReason.NOT_FOUND

    def test_tampered_secret_hash_mismatch(self, manager: KeyManager) -> None:
        from bitting.keys import compute_checksum

        issued = manager.issue()
        parts = issued.raw_key.split("_")
        tampered_secret = ("A" if parts[3][0] != "A" else "B") + parts[3][1:]
        canonical = f"{parts[0]}_{parts[1]}_{parts[2]}_{tampered_secret}"
        tampered = f"{canonical}_{compute_checksum(canonical)}"
        result = manager.verify(tampered)
        assert result.reason is VerifyReason.HASH_MISMATCH

    def test_expiry(self, manager: KeyManager, clock: FrozenClock) -> None:
        issued = manager.issue(ttl=timedelta(hours=1))
        clock.advance(hours=2)
        result = manager.verify(issued.raw_key)
        assert result.reason is VerifyReason.EXPIRED

    def test_revocation(self, manager: KeyManager) -> None:
        issued = manager.issue()
        manager.revoke(issued.prefix)
        result = manager.verify(issued.raw_key)
        assert result.reason is VerifyReason.REVOKED


class TestScopes:
    def test_exact_scope_required(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users"})
        assert manager.verify(issued.raw_key, required_scopes={"read:users"}).ok
        result = manager.verify(issued.raw_key, required_scopes={"read:billing"})
        assert result.reason is VerifyReason.SCOPE_MISSING
        assert result.missing_scopes == frozenset({"read:billing"})

    def test_wildcard_grant(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:*"})
        assert manager.verify(issued.raw_key, required_scopes={"read:users"}).ok
        assert manager.verify(issued.raw_key, required_scopes={"read:billing"}).ok
        assert not manager.verify(issued.raw_key, required_scopes={"write:users"}).ok

    def test_global_wildcard(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"*"})
        assert manager.verify(issued.raw_key, required_scopes={"anything:at:all"}).ok

    def test_multiple_requirements(self, manager: KeyManager) -> None:
        issued = manager.issue(scopes={"read:users"})
        result = manager.verify(
            issued.raw_key, required_scopes={"read:users", "write:users", "admin"}
        )
        assert result.missing_scopes == frozenset({"write:users", "admin"})

    def test_scope_matching_semantics(self) -> None:
        assert scope_matches("read:users", "read:users")
        assert scope_matches("read:*", "read:users")
        assert not scope_matches("read:*", "write:users")
        assert not scope_matches("read:*", "read")
        assert scope_matches("*", "everything")


class TestRotate:
    def test_rotation_grace_flow(self, manager: KeyManager, clock: FrozenClock) -> None:
        old = manager.issue(scopes={"read:users"}, description="service-a")
        new = manager.rotate(old.prefix, grace=timedelta(hours=24))

        assert new.raw_key != old.raw_key
        assert new.prefix != old.prefix
        assert new.record.scopes == frozenset({"read:users"})
        assert new.record.supersedes == old.prefix

        # Inside the grace window the old key still works, flagged.
        inside = manager.verify(old.raw_key)
        assert inside.ok and inside.reason is VerifyReason.ROTATED_GRACE

        # The new key works with reason OK.
        assert manager.verify(new.raw_key).reason is VerifyReason.OK

        # After the grace window the old key is rejected.
        clock.advance(hours=25)
        outside = manager.verify(old.raw_key)
        assert not outside.ok and outside.reason is VerifyReason.ROTATED

    def test_rotated_key_with_wrong_hash_inside_grace(
        self, manager: KeyManager, clock: FrozenClock
    ) -> None:
        from bitting.keys import compute_checksum

        old = manager.issue()
        manager.rotate(old.prefix, grace=timedelta(hours=1))
        parts = old.raw_key.split("_")
        tampered_secret = ("A" if parts[3][0] != "A" else "B") + parts[3][1:]
        canonical = f"{parts[0]}_{parts[1]}_{parts[2]}_{tampered_secret}"
        tampered = f"{canonical}_{compute_checksum(canonical)}"
        result = manager.verify(tampered)
        assert result.reason is VerifyReason.HASH_MISMATCH

    def test_double_rotation_rejected(self, manager: KeyManager) -> None:
        old = manager.issue()
        manager.rotate(old.prefix)
        with pytest.raises(ValueError):
            manager.rotate(old.prefix)

    def test_rotation_of_revoked_rejected(self, manager: KeyManager) -> None:
        issued = manager.issue()
        manager.revoke(issued.prefix)
        with pytest.raises(ValueError):
            manager.rotate(issued.prefix)

    def test_rotation_replaces_scopes_and_description(self, manager: KeyManager) -> None:
        old = manager.issue(scopes={"read:users"}, description="before")
        new = manager.rotate(old.prefix, scopes={"admin"}, description="after")
        assert new.record.scopes == frozenset({"admin"})
        assert new.record.description == "after"


class TestRevokeAndInspect:
    def test_revoke_unknown_prefix(self, manager: KeyManager) -> None:
        with pytest.raises(KeyNotFoundError):
            manager.revoke("doesnotexist0000")

    def test_list_keys_excludes_raw(self, manager: KeyManager) -> None:
        issued = manager.issue()
        listed = manager.list_keys()
        assert len(listed) == 1
        assert listed[0].prefix == issued.prefix
        assert not any(issued.raw_key == getattr(r, "raw_key", None) for r in listed)

    def test_record_to_json_has_no_secret(self, manager: KeyManager) -> None:
        issued = manager.issue()
        payload = issued.record.to_json()
        assert "raw_key" not in payload
        assert issued.raw_key not in str(payload)


class TestAuditTrail:
    def test_events_emitted_in_order(self, manager: KeyManager, clock: FrozenClock) -> None:
        issued = manager.issue(description="x")
        manager.verify(issued.raw_key)
        manager.rotate(issued.prefix, grace=timedelta(minutes=1))
        clock.advance(minutes=2)
        manager.verify(issued.raw_key)  # fails: ROTATED
        manager.revoke(issued.prefix)

        kinds = [event.kind.value for event in manager.list_events()]
        assert kinds == [
            "revoked",  # newest first
            "verify_failed",  # old key rejected after grace (ROTATED)
            "rotated",
            "verified",
            "issued",
        ]

    def test_custom_callback_receives_events(self, fast_hasher, clock) -> None:
        seen: list[str] = []
        manager = KeyManager(
            InMemoryStore(),
            hasher=fast_hasher,
            now_fn=clock,
            on_event=lambda event: seen.append(event.kind.value),
        )
        manager.issue()
        manager.issue()
        assert seen == ["issued", "issued"]

    def test_callback_failure_does_not_break_manager(self, fast_hasher, clock) -> None:
        def boom(_: object) -> None:
            raise RuntimeError("observer down")

        manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock, on_event=boom)
        issued = manager.issue()
        assert manager.verify(issued.raw_key).ok


class TestSqliteManagerLifecycle:
    def test_full_lifecycle_on_sqlite(self, sqlite_manager: KeyManager, clock: FrozenClock) -> None:
        issued = sqlite_manager.issue(scopes={"read:*"}, ttl=timedelta(days=1))
        assert sqlite_manager.verify(issued.raw_key, required_scopes={"read:users"}).ok
        rotated = sqlite_manager.rotate(issued.prefix, grace=timedelta(hours=1))
        assert sqlite_manager.verify(rotated.raw_key).ok
        clock.advance(hours=2)
        assert sqlite_manager.verify(issued.raw_key).reason is VerifyReason.ROTATED
        sqlite_manager.revoke(rotated.prefix)
        assert sqlite_manager.verify(rotated.raw_key).reason is VerifyReason.REVOKED
