"""Concurrency regression tests.

Each test pins a specific concurrency or lifecycle invariant, with races
forced deterministically (gated hashers, barriers) instead of sleeps.

``mark_revoked`` uses the ``at=`` keyword and returns bool: revocation is
idempotent and the first revocation timestamp wins, and the tests below
assert that semantic directly.
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from bitting import (
    InMemoryStore,
    KeyManager,
    KeyNotFoundError,
    ScryptHasher,
    SQLiteStore,
    VerifyReason,
    validate_scopes,
)
from bitting.hashing import _scrypt_memory

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ModuleNotFoundError:  # pragma: no cover
    HAS_ARGON2 = False

_RAW = "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _fast() -> ScryptHasher:
    return ScryptHasher(n=2**8, r=1, p=1)


class GatedHasher(ScryptHasher):
    """Blocks inside verify() so a lifecycle change can be interleaved."""

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self.entered = threading.Event()
        self.release = threading.Event()

    def verify(self, raw: str, encoded: str) -> bool:
        self.entered.set()
        assert self.release.wait(timeout=10), "test gate never released"
        return super().verify(raw, encoded)


class MovableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


def _stores():
    return [
        pytest.param(InMemoryStore, id="memory"),
        pytest.param(lambda: SQLiteStore(":memory:"), id="sqlite"),
    ]


# =====================================================================
# Stale authorization across the KDF window: the verdict must re-read
# =====================================================================


class TestLifecycleRecheckedAfterKdf:
    @pytest.mark.parametrize("store_factory", _stores())
    def test_revoke_during_hash_denies_the_in_flight_request(self, store_factory) -> None:
        """Pre-fix this returned ok=True: the revocation committed, but the
        in-flight verification still authorized the revoked credential."""
        store = store_factory()
        manager = KeyManager(store, hasher=GatedHasher(n=2**8))
        issued = manager.issue(scopes={"read:users"})
        outcome: dict[str, object] = {}

        thread = threading.Thread(
            target=lambda: outcome.update(
                result=manager.verify(issued.raw_key, required_scopes={"read:users"})
            )
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        manager.revoke(issued.prefix)  # commits while the KDF is parked
        assert store.find_by_prefix(issued.prefix).revoked_at is not None
        manager.hasher.release.set()
        thread.join(timeout=5)

        result = outcome["result"]
        assert not result.ok, "a revoked credential authorized in-flight"
        assert result.reason is VerifyReason.REVOKED

    def test_expiry_during_hash_denies_the_in_flight_request(self) -> None:
        clock = MovableClock()
        manager = KeyManager(InMemoryStore(), hasher=GatedHasher(n=2**8), now_fn=clock)
        issued = manager.issue(ttl=timedelta(seconds=1))
        outcome: dict[str, object] = {}
        thread = threading.Thread(
            target=lambda: outcome.update(result=manager.verify(issued.raw_key))
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        clock.advance(hours=1)  # the TTL ends while the KDF runs
        manager.hasher.release.set()
        thread.join(timeout=5)
        result = outcome["result"]
        assert not result.ok
        assert result.reason is VerifyReason.EXPIRED

    def test_grace_closing_during_hash_denies_the_in_flight_request(self) -> None:
        clock = MovableClock()
        manager = KeyManager(InMemoryStore(), hasher=GatedHasher(n=2**8), now_fn=clock)
        issued = manager.issue()
        manager.rotate(issued.prefix, grace=timedelta(seconds=1))
        outcome: dict[str, object] = {}
        thread = threading.Thread(
            target=lambda: outcome.update(result=manager.verify(issued.raw_key))
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        clock.advance(hours=1)  # grace window closes mid-KDF
        manager.hasher.release.set()
        thread.join(timeout=5)
        result = outcome["result"]
        assert not result.ok
        assert result.reason is VerifyReason.ROTATED

    def test_deletion_during_hash_denies_the_in_flight_request(self) -> None:
        store = InMemoryStore()
        manager = KeyManager(store, hasher=GatedHasher(n=2**8))
        issued = manager.issue()
        outcome: dict[str, object] = {}
        thread = threading.Thread(
            target=lambda: outcome.update(result=manager.verify(issued.raw_key))
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        store.delete(issued.prefix)
        manager.hasher.release.set()
        thread.join(timeout=5)
        result = outcome["result"]
        assert not result.ok
        assert result.reason is VerifyReason.NOT_FOUND

    def test_scope_narrowing_during_hash_is_honored(self) -> None:
        from dataclasses import replace

        store = InMemoryStore()
        manager = KeyManager(store, hasher=GatedHasher(n=2**8))
        issued = manager.issue(scopes={"read:users", "write:posts"})
        outcome: dict[str, object] = {}
        thread = threading.Thread(
            target=lambda: outcome.update(
                result=manager.verify(issued.raw_key, required_scopes={"write:posts"})
            )
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        record = store.find_by_prefix(issued.prefix)
        assert record is not None
        store.save(replace(record, scopes=frozenset({"read:users"})))
        manager.hasher.release.set()
        thread.join(timeout=5)
        result = outcome["result"]
        assert not result.ok
        assert result.reason is VerifyReason.SCOPE_MISSING
        assert result.missing_scopes == frozenset({"write:posts"})

    def test_rotation_during_hash_relabels_success_as_rotated_grace(self) -> None:
        store = InMemoryStore()
        manager = KeyManager(store, hasher=GatedHasher(n=2**8))
        issued = manager.issue()
        outcome: dict[str, object] = {}
        thread = threading.Thread(
            target=lambda: outcome.update(result=manager.verify(issued.raw_key))
        )
        thread.start()
        assert manager.hasher.entered.wait(timeout=5)
        manager.rotate(issued.prefix, grace=timedelta(hours=1))
        manager.hasher.release.set()
        thread.join(timeout=5)
        result = outcome["result"]
        assert result.ok
        assert result.reason is VerifyReason.ROTATED_GRACE

    def test_uncontended_verification_still_succeeds_and_stays_read_only(self) -> None:
        """The re-check must not reintroduce a full-record write."""

        class CountingStore(InMemoryStore):
            def __init__(self) -> None:
                super().__init__()
                self.saves = 0
                self.reads = 0

            def save(self, record) -> None:  # type: ignore[override]
                self.saves += 1
                super().save(record)

            def find_by_prefix(self, prefix):  # type: ignore[override]
                self.reads += 1
                return super().find_by_prefix(prefix)

        store = CountingStore()
        manager = KeyManager(store, hasher=_fast(), verify_touch_interval=timedelta(0))
        issued = manager.issue(scopes={"read:users"})
        saves_after_issue = store.saves
        result = manager.verify(issued.raw_key, required_scopes={"read:users"})
        assert result.ok and result.reason is VerifyReason.OK
        assert store.saves == saves_after_issue, "verify must not save() a full record"
        assert result.record is not None
        assert result.record.last_verified_at is not None

    def test_failed_verification_does_not_pay_for_a_second_lookup(self) -> None:
        """The confirmation is on the success path only: junk traffic stays cheap."""

        class CountingStore(InMemoryStore):
            def __init__(self) -> None:
                super().__init__()
                self.reads = 0

            def find_by_prefix(self, prefix):  # type: ignore[override]
                self.reads += 1
                return super().find_by_prefix(prefix)

        from bitting.keys import compute_checksum

        store = CountingStore()
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue()
        parts = issued.raw_key.split("_")
        secret = ("A" if parts[3][0] != "A" else "B") + parts[3][1:]
        canonical = f"btg_live_{parts[2]}_{secret}"
        wrong = f"{canonical}_{compute_checksum(canonical)}"
        store.reads = 0
        assert manager.verify(wrong).reason is VerifyReason.HASH_MISMATCH
        assert store.reads == 1


# =====================================================================
# revoke() must not erase a concurrent rotation (idempotent mark_revoked)
# =====================================================================


class TestRevokeIsTargeted:
    @pytest.mark.parametrize("store_factory", _stores())
    def test_revoke_preserves_a_rotation_committed_after_its_read(self, store_factory) -> None:
        """Pre-fix, revoke()'s full-record save wrote rotated_at=None back."""
        store = store_factory()
        gate = threading.Event()
        armed = {"on": False}
        original = store.mark_revoked

        def paused(prefix, *, at):
            if armed["on"]:
                assert gate.wait(timeout=10)
            return original(prefix, at=at)

        store.mark_revoked = paused  # type: ignore[method-assign]
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue(scopes={"read:users"})
        armed["on"] = True
        done: dict[str, object] = {}
        thread = threading.Thread(target=lambda: done.update(record=manager.revoke(issued.prefix)))
        thread.start()
        time.sleep(0.05)  # let the revoker reach its gate
        successor = manager.rotate(issued.prefix, grace=timedelta(hours=24))
        gate.set()
        thread.join(timeout=5)

        stored = store.find_by_prefix(issued.prefix)
        assert stored is not None
        assert stored.revoked_at is not None, "revocation must still land"
        assert stored.rotated_at is not None, "revoke erased the rotation claim"
        assert stored.grace_until is not None, "revoke erased the grace window"
        assert store.find_by_prefix(successor.prefix).supersedes == issued.prefix
        assert not manager.verify(issued.raw_key).ok

    @pytest.mark.parametrize("store_factory", _stores())
    def test_mark_revoked_touches_only_revoked_at(self, store_factory) -> None:
        from dataclasses import replace

        store = store_factory()
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue(scopes={"read:users"}, metadata={"team": "platform"})
        moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
        before = store.find_by_prefix(issued.prefix)
        assert before is not None
        assert store.mark_rotated(
            issued.prefix, rotated_at=moment, grace_until=moment + timedelta(hours=1)
        )
        rotated = store.find_by_prefix(issued.prefix)
        assert rotated is not None
        assert store.mark_revoked(issued.prefix, at=moment) is True
        after = store.find_by_prefix(issued.prefix)
        assert after is not None
        assert after.revoked_at == moment
        for field in (
            "key_id",
            "hash",
            "algorithm",
            "scopes",
            "created_at",
            "description",
            "expires_at",
            "rotated_at",
            "grace_until",
            "last_verified_at",
            "metadata",
            "supersedes",
        ):
            assert getattr(after, field) == getattr(rotated, field), field
        assert before.prefix == after.prefix
        assert replace(after).revoked_at == moment

    @pytest.mark.parametrize("store_factory", _stores())
    def test_mark_revoked_reports_missing_prefix(self, store_factory) -> None:
        store = store_factory()
        assert store.mark_revoked("nosuchprefix0000", at=datetime.now(timezone.utc)) is False

    def test_revoke_raises_for_a_genuinely_missing_prefix(self) -> None:
        """A key that vanishes before the update raises (VanishingStore
        scenario, adapted to the implementation's idempotent semantics: a store whose
        mark_revoked reports no transition for an existing key is treated as
        already-revoked — tolerated, not an error; only a truly absent key
        raises)."""

        class VanishingStore(InMemoryStore):
            def mark_revoked(self, prefix, *, at) -> bool:  # type: ignore[override]
                return False

        manager = KeyManager(VanishingStore(), hasher=_fast())
        issued = manager.issue()
        # mark reports no transition but the key exists -> tolerated, no raise
        manager.revoke(issued.prefix)
        # a genuinely missing prefix raises
        with pytest.raises(KeyNotFoundError):
            manager.revoke("nosuchprefix00000")

    def test_re_revoke_keeps_the_first_timestamp(self) -> None:
        """The documented semantics: the first revocation moment is
        authoritative (an earlier non-atomic implementation let a second revoke overwrite it; the
        idempotent fix made revocation keep the first timestamp instead)."""
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue()
        first = datetime(2030, 1, 1, tzinfo=timezone.utc)
        second = datetime(2031, 1, 1, tzinfo=timezone.utc)
        assert manager.revoke(issued.prefix, now=first).revoked_at == first
        assert manager.revoke(issued.prefix, now=second).revoked_at == first

    def test_duck_typed_store_without_mark_revoked_still_revokes(self) -> None:
        """Backwards compatibility: pre-existing adapters keep working."""

        class LegacyStore:
            def __init__(self) -> None:
                self._inner = InMemoryStore()

            def save(self, record):
                self._inner.save(record)

            def find_by_prefix(self, prefix):
                return self._inner.find_by_prefix(prefix)

            def delete(self, prefix):
                return self._inner.delete(prefix)

            def list_keys(self):
                return self._inner.list_keys()

            def append_event(self, event):
                self._inner.append_event(event)

            def list_events(self, *, limit=100):
                return self._inner.list_events(limit=limit)

            def close(self):
                self._inner.close()

        assert not hasattr(LegacyStore(), "mark_revoked")
        manager = KeyManager(LegacyStore(), hasher=_fast())
        issued = manager.issue()
        assert manager.revoke(issued.prefix).revoked_at is not None
        assert manager.verify(issued.raw_key).reason is VerifyReason.REVOKED

    def test_keystore_base_default_mark_revoked_is_available(self) -> None:
        from bitting.storage import KeyStore

        class Minimal(KeyStore):
            def __init__(self) -> None:
                self._inner = InMemoryStore()

            def save(self, record):
                self._inner.save(record)

            def find_by_prefix(self, prefix):
                return self._inner.find_by_prefix(prefix)

        store = Minimal()
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue()
        assert store.mark_revoked(issued.prefix, at=datetime.now(timezone.utc)) is True
        assert manager.verify(issued.raw_key).reason is VerifyReason.REVOKED


# =====================================================================
# Stored scrypt work budget and canonical parameter syntax
# (crafted-CPU envelope hardening)
# =====================================================================


class TestScryptWorkBudget:
    def _crafted(self, n: int, r: int, p: int) -> str:
        return f"$scrypt$n={n}$r={r}$p={p}${_b64(bytes([1]) * 16)}${_b64(bytes(32))}"

    @pytest.mark.parametrize(
        ("n", "r", "p"),
        [(131072, 2, 64), (65536, 2, 64), (32768, 4, 64), (16384, 8, 64)],
    )
    def test_crafted_work_is_rejected_before_the_kdf(self, n: int, r: int, p: int) -> None:
        """Pre-fix, n=131072,r=2,p=64 fit in 32 MiB and burned ~4 s of CPU
        (67x the default profile) on every verification of that record."""
        hasher = ScryptHasher()
        crafted = self._crafted(n, r, p)
        assert _scrypt_memory(n, r, p) < 48 * 1024**2, "must fit inside the default maxmem"
        start = time.perf_counter()
        assert hasher.verify(_RAW, crafted) is False
        elapsed = time.perf_counter() - start
        assert elapsed < 0.05, f"crafted params forced {elapsed * 1000:.1f} ms of KDF work"

    def test_legitimate_default_hash_still_verifies(self) -> None:
        hasher = ScryptHasher()
        assert hasher.verify(_RAW, hasher.hash(_RAW)) is True

    def test_own_heavy_configuration_is_exempt(self) -> None:
        hasher = ScryptHasher(n=2**16, r=8, p=1)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded) is True
        assert hasher.verify(_RAW + "x", encoded) is False

    def test_work_floor_lets_a_cheap_hasher_verify_default_cost_records(self) -> None:
        """A deployment that lowered its cost must still verify older keys."""
        cheap = ScryptHasher(n=2**8, r=1, p=1)
        default_encoded = ScryptHasher().hash(_RAW)
        assert cheap.verify(_RAW, default_encoded) is True

    def test_modest_upgrade_within_the_budget_is_accepted(self) -> None:
        hasher = ScryptHasher()  # work 131072, budget 4x = 524288
        # n=2**15, r=8, p=1 -> work 262144 (2x), memory 32 MiB: allowed.
        crafted = self._crafted(2**15, 8, 1)
        start = time.perf_counter()
        hasher.verify(_RAW, crafted)  # wrong digest, but the KDF must run
        assert time.perf_counter() - start > 0.005

    @pytest.mark.parametrize(
        "params",
        ["n=256=999$r=1$p=1", "n=+256$r=1$p=1", "n=256$r=1$p=+1", "n= 256$r=1$p=1"],
    )
    def test_non_canonical_parameter_spellings_rejected(self, params: str) -> None:
        hasher = _fast()
        encoded = hasher.hash(_RAW).split("$")
        crafted = f"$scrypt${params}${encoded[5]}${encoded[6]}"
        assert hasher.verify(_RAW, crafted) is False

    def test_renamed_parameter_keys_rejected(self) -> None:
        hasher = _fast()
        encoded = hasher.hash(_RAW).split("$")
        crafted = f"$scrypt$N=256$R=1$P=1${encoded[5]}${encoded[6]}"
        assert hasher.verify(_RAW, crafted) is False

    def test_canonical_hash_round_trips_after_strictening(self) -> None:
        hasher = _fast()
        assert hasher.verify(_RAW, hasher.hash(_RAW)) is True


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
class TestArgon2CanonicalParams:
    def test_duplicate_parameter_key_rejected(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        parts = hasher.hash(_RAW).split("$")
        crafted = f"$argon2id$v=19$m=8192,t=1,p=1,m=8${parts[4]}${parts[5]}"
        assert hasher.verify(_RAW, crafted) is False

    def test_missing_and_extra_parameters_rejected(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        parts = hasher.hash(_RAW).split("$")
        for params in ("m=8192,t=1", "m=8192,t=1,p=1,x=2", "m=8192,t=+1,p=1"):
            assert hasher.verify(_RAW, f"$argon2id$v=19${params}${parts[4]}${parts[5]}") is False

    def test_canonical_hash_still_verifies(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        assert hasher.verify(_RAW, hasher.hash(_RAW)) is True


# =====================================================================
# FastAPI integration: duplicate headers + scope validation
# =====================================================================


class TestRequireValidatesScopes:
    @pytest.mark.parametrize(
        "scopes",
        ["read:users", b"read:users", {"read: users"}, {""}, {"a\nb"}, {123}],
    )
    def test_invalid_scopes_fail_at_construction(self, scopes) -> None:
        """Pre-fix: a bare string became a set of characters (a route that
        could never authorize, silently), and invalid scopes raised at
        request time as HTTP 500."""
        from bitting.integrations.fastapi import APIKeyAuth

        auth = APIKeyAuth(KeyManager(InMemoryStore(), hasher=_fast()))
        with pytest.raises(ValueError):
            auth.require(scopes=scopes)

    def test_valid_scopes_still_work_end_to_end(self) -> None:
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from bitting.integrations.fastapi import APIKeyAuth

        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue(scopes={"read:users"})
        auth = APIKeyAuth(manager)
        app = FastAPI()

        @app.get("/x", dependencies=[Depends(auth.require(scopes={"read:users"}))])
        def route() -> dict:
            return {"ok": True}

        client = TestClient(app)
        assert client.get("/x", headers={"X-API-Key": issued.raw_key}).status_code == 200
        assert client.get("/x").status_code == 401

    def test_validate_scopes_is_public_and_shared(self) -> None:
        assert validate_scopes(["read:users"]) == frozenset({"read:users"})
        with pytest.raises(ValueError, match="iterable of scope strings"):
            validate_scopes("read:users")


class TestDuplicateHeaders:
    def _client(self, header: str):
        from fastapi import Depends, FastAPI
        from fastapi.testclient import TestClient

        from bitting.integrations.fastapi import APIKeyAuth

        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue(scopes={"read:users"})
        auth = APIKeyAuth(manager, header=header)
        app = FastAPI()

        @app.get("/x", dependencies=[Depends(auth.require(scopes={"read:users"}))])
        def route() -> dict:
            return {"ok": True}

        return TestClient(app), issued.raw_key

    def test_duplicate_x_api_key_is_refused_in_both_orders(self) -> None:
        client, key = self._client("X-API-Key")
        r1 = client.get("/x", headers=[("X-API-Key", key), ("X-API-Key", "junk")]).status_code
        r2 = client.get("/x", headers=[("X-API-Key", "junk"), ("X-API-Key", key)]).status_code
        assert r1 == 401 and r2 == 401, "an ambiguous credential must not authenticate"
        assert client.get("/x", headers={"X-API-Key": key}).status_code == 200

    def test_duplicate_authorization_is_refused(self) -> None:
        client, key = self._client("Authorization")
        headers = [("Authorization", f"Bearer {key}"), ("Authorization", "Bearer junk")]
        assert client.get("/x", headers=headers).status_code == 401
        assert client.get("/x", headers={"Authorization": f"Bearer {key}"}).status_code == 200


# =====================================================================
# SQLiteStore path expansion, CLI --json, deep-copy, Z-suffix, prefix retry
# =====================================================================


class TestHomeRelativeDatabasePath:
    def test_tilde_path_opens_and_lands_under_home(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        store = SQLiteStore("~/nested/keys.db")
        try:
            assert store.path == str(tmp_path / "nested" / "keys.db")
            assert (tmp_path / "nested" / "keys.db").exists()
            assert not os.path.isdir("~"), "a literal '~' directory was created"
        finally:
            store.close()

    def test_memory_sentinel_is_not_expanded(self) -> None:
        store = SQLiteStore(":memory:")
        try:
            assert store.path == ":memory:"
        finally:
            store.close()

    def test_plain_and_pathlib_paths_unchanged(self, tmp_path) -> None:
        for path in (str(tmp_path / "a.db"), tmp_path / "b.db"):
            store = SQLiteStore(path)
            try:
                assert store.path == str(path)
            finally:
                store.close()


class TestCliJsonFlagPlacement:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--json", "issue"],
            ["issue", "--json"],
            ["--json", "list"],
            ["list", "--json"],
            ["--json", "events"],
            ["events", "--json"],
        ],
    )
    def test_json_accepted_before_and_after_the_command(self, tmp_path, capsys, argv) -> None:
        import json

        from bitting.cli import main

        db = str(tmp_path / "cli.db")
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        assert main(["--db", db, *argv]) == 0
        out = capsys.readouterr().out
        json.loads(out)  # must be valid JSON, not the human-readable table

    def test_json_after_verify_and_revoke_and_rotate(self, tmp_path, capsys) -> None:
        import json

        from bitting.cli import main

        db = str(tmp_path / "cli.db")
        assert main(["--db", db, "--json", "issue"]) == 0
        raw = json.loads(capsys.readouterr().out)["raw_key"]
        prefix = raw.split("_")[2]
        assert main(["--db", db, "verify", raw, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["ok"] is True
        assert main(["--db", db, "rotate", prefix, "--json"]) == 0
        new_prefix = json.loads(capsys.readouterr().out)["new_prefix"]
        assert main(["--db", db, "revoke", new_prefix, "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["revoked_prefix"] == new_prefix


class TestMetadataCopyConsistency:
    def test_mark_verified_deep_copies_nested_metadata(self) -> None:
        store = InMemoryStore()
        manager = KeyManager(store, hasher=_fast(), verify_touch_interval=timedelta(0))
        issued = manager.issue(metadata={"nested": {"values": [1, 2]}})
        before = store._keys[issued.prefix].metadata["nested"]
        assert manager.verify(issued.raw_key).ok
        after = store._keys[issued.prefix].metadata["nested"]
        assert before is not after, "mark_verified aliased nested metadata"
        assert after == {"values": [1, 2]}

    def test_mark_revoked_deep_copies_nested_metadata(self) -> None:
        store = InMemoryStore()
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue(metadata={"nested": {"values": [1, 2]}})
        before = store._keys[issued.prefix].metadata["nested"]
        manager.revoke(issued.prefix)
        assert store._keys[issued.prefix].metadata["nested"] is not before


class TestIsoZSuffix:
    @pytest.mark.parametrize(
        "text",
        ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00z", "2026-01-01T00:00:00+00:00"],
    )
    def test_z_suffix_normalized_on_every_supported_python(self, text: str) -> None:
        from bitting.timeutil import from_iso

        assert from_iso(text) == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_z_suffixed_stored_row_loads(self, tmp_path) -> None:
        import sqlite3

        from bitting.cli import main

        db = tmp_path / "z.db"
        assert main(["--db", str(db), "issue"]) == 0
        conn = sqlite3.connect(db)
        conn.execute("UPDATE keys SET created_at = replace(created_at, '+00:00', 'Z')")
        conn.commit()
        conn.close()
        store = SQLiteStore(db)
        try:
            assert store.list_keys()[0].created_at.tzinfo is not None
        finally:
            store.close()


class TestIssuePrefixCollision:
    def test_collision_is_retried_not_overwritten(self, monkeypatch) -> None:
        import bitting.manager as manager_module

        store = InMemoryStore()
        manager = KeyManager(store, hasher=_fast())
        existing = manager.issue(scopes={"read:users"})
        victim_hash = store.find_by_prefix(existing.prefix).hash

        real_generate = manager_module.generate_api_key
        calls = {"n": 0}

        def colliding_then_fresh(env, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                return existing.raw_key  # force a collision on the first draw
            return real_generate(env, **kw)

        monkeypatch.setattr(manager_module, "generate_api_key", colliding_then_fresh)
        fresh = manager.issue(scopes={"admin"})
        assert fresh.prefix != existing.prefix
        untouched = store.find_by_prefix(existing.prefix)
        assert untouched is not None
        assert untouched.hash == victim_hash, "an existing credential was overwritten"
        assert untouched.scopes == frozenset({"read:users"})
        assert len(store.list_keys()) == 2


# =====================================================================
# Cross-process proof (real OS processes, real SQLite WAL file) — the
# demonstration that the targeted revoke survives a cross-process rotation
# =====================================================================

_REVOKER = """
import sys, os, time
sys.path.insert(0, sys.argv[1])
from bitting import KeyManager, ScryptHasher, SQLiteStore
db, prefix, bf = sys.argv[2:5]
class PausingStore(SQLiteStore):
    def mark_revoked(self, prefix, *, at):
        open(os.path.join(bf, "READ_DONE"), "w").close()
        while not os.path.exists(os.path.join(bf, "ROTATE_DONE")):
            time.sleep(0.005)
        return super().mark_revoked(prefix, at=at)
KeyManager(PausingStore(db), hasher=ScryptHasher(n=2**8, r=1, p=1)).revoke(prefix)
"""

_ROTATOR = """
import sys, os, time
sys.path.insert(0, sys.argv[1])
from datetime import timedelta
from bitting import KeyManager, ScryptHasher, SQLiteStore
db, prefix, bf = sys.argv[2:5]
while not os.path.exists(os.path.join(bf, "READ_DONE")):
    time.sleep(0.005)
m = KeyManager(SQLiteStore(db), hasher=ScryptHasher(n=2**8, r=1, p=1))
try:
    m.rotate(prefix, grace=timedelta(hours=24))
finally:
    open(os.path.join(bf, "ROTATE_DONE"), "w").close()
"""


class TestRevokeCrossProcess:
    def test_revoke_in_one_process_preserves_rotation_in_another(self, tmp_path) -> None:
        """The lost update was reproduced across two OS processes against a
        real WAL-mode SQLite file, not just an in-process toy store."""
        db = tmp_path / "x.db"
        barrier = tmp_path / "bar"
        barrier.mkdir()
        manager = KeyManager(SQLiteStore(db), hasher=_fast())
        issued = manager.issue(scopes={"read:users"})
        manager.close()

        src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        revoker = tmp_path / "rev.py"
        rotator = tmp_path / "rot.py"
        revoker.write_text(_REVOKER)
        rotator.write_text(_ROTATOR)
        args = [src, str(db), issued.prefix, str(barrier)]
        procs = [
            subprocess.Popen(
                [sys.executable, str(script), *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for script in (revoker, rotator)
        ]
        try:
            for proc in procs:
                _out, err = proc.communicate(timeout=120)
                assert proc.returncode == 0, err[-2000:]
        finally:
            for proc in procs:
                if proc.poll() is None:  # pragma: no cover - timeout cleanup
                    proc.kill()

        store = SQLiteStore(db)
        try:
            stored = store.find_by_prefix(issued.prefix)
            assert stored is not None
            assert stored.revoked_at is not None
            assert stored.rotated_at is not None, "cross-process rotation claim was erased"
            assert stored.grace_until is not None
            assert len([r for r in store.list_keys() if r.supersedes == issued.prefix]) == 1
        finally:
            store.close()
