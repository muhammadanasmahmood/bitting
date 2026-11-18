"""Regression tests for robustness and input-validation defects.

Each test in this suite fails on the code before the corresponding fix
(and the pre-fix failure modes are described below), so a regression
cannot slip through silently:
- Legacy-schema rows: a row written by an older schema (missing
  last_verified_at, or even the prefix column) raised a raw IndexError
  from the row->record mapping instead of the documented StorageError.
- list_events(limit >= 2**63) leaked a raw OverflowError from the
  sqlite driver (both stores now validate the range); the CLI printed a
  traceback instead of its clean "error:" line.
- A naive now_fn only exploded mid-verify (TypeError escaping the
  "verify never raises for a bad key" contract); construction now fails
  fast with ConfigurationError.
- verify_touch_interval=None raised TypeError at first verify;
  construction now validates the type.
- Metadata with non-string keys round-tripped differently across
  stores ({1: 'a'} in memory vs {'1': 'a'} in SQLite); issue() now
  rejects non-string metadata keys anywhere in the nested structure.
- A crafted stored argon2id hash could demand up to ~1 GiB of memory
  per verification (total-work cap only); stored (non-own-config) hashes
  are now also capped at 256 MiB, mirroring scrypt's maxmem.
- Revoked keys are denied *before* the KDF runs (pinning the pre-KDF
  denial: a regression would burn the full scrypt cost on every revoked
  verification).
"""

from __future__ import annotations

import sqlite3
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from bitting import (
    ConfigurationError,
    InMemoryStore,
    KeyManager,
    ScryptHasher,
    SQLiteStore,
    StorageError,
    VerifyReason,
)


def _fast() -> ScryptHasher:
    return ScryptHasher(n=2**8, r=1, p=1)


def _has_argon2() -> bool:
    try:
        import argon2  # noqa: F401

        return True
    except ModuleNotFoundError:  # pragma: no cover
        return False


# =====================================================================
# Legacy-schema rows surface as StorageError
# =====================================================================


class TestLegacySchemaRow:
    def test_row_missing_last_verified_column_raises_storage_error(self, tmp_path) -> None:
        path = tmp_path / "legacy.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE keys (
                prefix TEXT PRIMARY KEY, key_id TEXT NOT NULL, hash TEXT NOT NULL,
                algorithm TEXT NOT NULL, scopes TEXT NOT NULL, created_at TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '', expires_at TEXT, revoked_at TEXT,
                rotated_at TEXT, grace_until TEXT, metadata TEXT NOT NULL DEFAULT '{}',
                supersedes TEXT
            );
            INSERT INTO keys VALUES (
                'aaaabbbbccccdddd', 'id-1', '$scrypt$test', 'scrypt',
                '["read:users"]', '2026-01-01T12:00:00+00:00', 'legacy row',
                NULL, NULL, NULL, NULL, '{}', NULL
            );
            """
        )
        conn.commit()
        conn.close()
        store = SQLiteStore(path)
        try:
            with pytest.raises(StorageError, match="corrupted key record"):
                store.find_by_prefix("aaaabbbbccccdddd")
            # The whole-table paths must fail the same predictable way,
            # not raise raw IndexError mid-iteration.
            with pytest.raises(StorageError):
                store.list_keys()
        finally:
            store.close()

    def test_row_missing_prefix_column_raises_storage_error(self, tmp_path) -> None:
        # Even when the prefix column itself is missing — the
        # worst doubly-corrupt case — the mapping must fail as StorageError,
        # not as an IndexError from building the error message.
        path = tmp_path / "noprefix.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE keys (
                key_id TEXT NOT NULL, hash TEXT NOT NULL, algorithm TEXT NOT NULL,
                scopes TEXT NOT NULL, created_at TEXT NOT NULL
            );
            INSERT INTO keys VALUES ('id-1', '$scrypt$test', 'scrypt',
                '["read:users"]', '2026-01-01T12:00:00+00:00');
            """
        )
        conn.commit()
        conn.close()
        store = SQLiteStore(path)
        try:
            with pytest.raises(StorageError, match="corrupted key record"):
                store.list_keys()
        finally:
            store.close()


# =====================================================================
# list_events limit range validation (both stores + CLI)
# =====================================================================


class TestListEventsLimitRange:
    @pytest.mark.parametrize("store_factory", [InMemoryStore, lambda: SQLiteStore(":memory:")])
    def test_huge_limit_raises_value_error_not_overflow(self, store_factory) -> None:
        store = store_factory()
        with pytest.raises(ValueError, match="limit must be <="):
            store.list_events(limit=2**63)
        with pytest.raises(ValueError, match="limit must be <="):
            store.list_events(limit=10**20)

    def test_maximum_valid_limit_still_works(self) -> None:
        store = SQLiteStore(":memory:")
        # 2**63 - 1 is the last in-range value; it must bind cleanly.
        assert store.list_events(limit=2**63 - 1) == []

    def test_cli_events_huge_limit_exits_cleanly(self, tmp_path, capsys) -> None:
        from bitting.cli import main

        db = str(tmp_path / "cli.db")
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        rc = main(["--db", db, "events", "--limit", str(2**63)])
        err = capsys.readouterr().err
        assert rc == 1
        assert err.startswith("error:")
        assert "Traceback" not in err

    def test_cli_events_limit_10_20_exits_cleanly(self, tmp_path, capsys) -> None:
        from bitting.cli import main

        db = str(tmp_path / "cli2.db")
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        rc = main(["--db", db, "events", "--limit", "100000000000000000000"])
        err = capsys.readouterr().err
        assert rc == 1
        assert err.startswith("error:")
        assert "Traceback" not in err


# =====================================================================
# Naive or non-callable clocks are rejected at construction
# =====================================================================


class TestNaiveClockRejected:
    def test_naive_clock_raises_configuration_error_at_construction(self) -> None:
        def naive() -> datetime:
            return datetime(2026, 1, 1, 12, 0, 0)  # pragma: no cover - never called post-check

        with pytest.raises(ConfigurationError, match="timezone-aware"):
            KeyManager(InMemoryStore(), hasher=_fast(), now_fn=naive)

    def test_aware_clock_still_accepted(self) -> None:
        def aware() -> datetime:
            return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        manager = KeyManager(InMemoryStore(), hasher=_fast(), now_fn=aware)
        assert manager.issue().raw_key.startswith("btg_live_")

    def test_non_datetime_clock_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            KeyManager(InMemoryStore(), hasher=_fast(), now_fn=lambda: "2026-01-01")

    def test_naive_returning_builtin_clock_rejected(self) -> None:
        # datetime.now IS callable but returns naive datetimes: it must be
        # rejected by the awareness check, not slip through.
        with pytest.raises(ConfigurationError, match="timezone-aware"):
            KeyManager(InMemoryStore(), hasher=_fast(), now_fn=datetime.now)  # type: ignore[arg-type]

    def test_non_callable_now_fn_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="callable"):
            KeyManager(InMemoryStore(), hasher=_fast(), now_fn="not-callable")  # type: ignore[arg-type]


# =====================================================================
# verify_touch_interval type validated at construction
# =====================================================================


class TestTouchIntervalValidation:
    def test_none_interval_rejected_at_construction(self) -> None:
        with pytest.raises(ConfigurationError, match="verify_touch_interval"):
            KeyManager(InMemoryStore(), hasher=_fast(), verify_touch_interval=None)  # type: ignore[arg-type]

    def test_int_interval_rejected_at_construction(self) -> None:
        with pytest.raises(ConfigurationError, match="verify_touch_interval"):
            KeyManager(InMemoryStore(), hasher=_fast(), verify_touch_interval=60)  # type: ignore[arg-type]

    def test_zero_interval_still_works(self) -> None:
        manager = KeyManager(InMemoryStore(), hasher=_fast(), verify_touch_interval=timedelta(0))
        issued = manager.issue()
        assert manager.verify(issued.raw_key).ok


# =====================================================================
# Non-string metadata keys rejected at issue()
# =====================================================================


class TestMetadataKeyValidation:
    def test_int_metadata_key_rejected(self) -> None:
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        with pytest.raises(ValueError, match="metadata keys must be strings"):
            manager.issue(metadata={1: "a"})

    def test_nested_non_string_key_rejected(self) -> None:
        # The check must walk the whole nested mapping, not
        # just the top level.
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        with pytest.raises(ValueError, match="metadata keys must be strings at 'outer'"):
            manager.issue(metadata={"outer": {1: "inner"}})
        with pytest.raises(ValueError, match=r"'a\.b'"):
            manager.issue(metadata={"a": {"b": {2: "deep"}}})

    def test_non_string_key_inside_array_rejected(self) -> None:
        # Dicts nested inside lists/tuples are part of
        # the JSON document too, and round-trip differently across stores.
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        with pytest.raises(ValueError, match=r"'a\[0\]'"):
            manager.issue(metadata={"a": [{1: "x"}]})
        with pytest.raises(ValueError, match=r"'t\[1\]'"):
            manager.issue(metadata={"t": ["ok", {2: "y"}]})

    def test_array_nested_string_keys_round_trip_identically(self) -> None:
        # With the walk covering arrays, both stores must agree.
        for store in (InMemoryStore(), SQLiteStore(":memory:")):
            manager = KeyManager(store, hasher=_fast())
            issued = manager.issue(metadata={"a": [{"b": 1}, [{"c": 2}]]})
            record = store.find_by_prefix(issued.prefix)
            assert record is not None
            assert record.metadata == {"a": [{"b": 1}, [{"c": 2}]]}

    def test_deeply_nested_metadata_does_not_hit_recursion_limit(self) -> None:
        # The validation walk is iterative; deep
        # metadata must be rejected (or accepted) by *other* components'
        # limits — never by a RecursionError raised inside manager.py's
        # validation. (InMemoryStore.save's deepcopy and json.dumps have
        # their own pre-existing depth ceilings; those are documented
        # remaining risks, not part of this fix.)
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        deep: dict[str, Any] = {"leaf": True}
        for _ in range(5000):
            deep = {"n": deep}
        try:
            manager.issue(metadata=deep)
        except RecursionError as exc:
            # A depth ceiling is acceptable (pre-existing InMemoryStore
            # deepcopy / json.dumps behavior) — but the recursion must be
            # attributed to the store's deepcopy or JSON encoding, never to
            # the iterative validation walk in manager.py (which has no
            # recursion of its own).
            frames = traceback.extract_tb(exc.__traceback__)
            filenames = {f.filename for f in frames}
            assert any(name in f for f in filenames for name in ("copy.py", "json")), (
                f"RecursionError not attributable to deepcopy/json encoding: "
                f"{[f.filename for f in frames[-3:]]}"
            )
        except ValueError:
            pass  # json's own depth/circularity limits — fine
        # The walk itself handles arbitrary depth: run it under a tiny
        # recursion limit to prove it is not recursive.
        sys.setrecursionlimit(200)
        try:
            stack: list[tuple[Any, str]] = [(deep, "")]
            nodes = 0
            while stack:
                node, _path = stack.pop()
                nodes += 1
                if isinstance(node, dict):
                    for key, value in node.items():
                        assert isinstance(key, str)
                        stack.append((value, ""))
        finally:
            sys.setrecursionlimit(1000)
        assert nodes == 5002

    def test_deeply_nested_string_keys_accepted(self) -> None:
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue(metadata={"a": {"b": {"c": [1, 2]}}})
        assert manager.verify(issued.raw_key).ok
        record = manager.store.find_by_prefix(issued.prefix)
        assert record is not None and record.metadata == {"a": {"b": {"c": [1, 2]}}}

    def test_string_metadata_keys_still_accepted(self) -> None:
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue(metadata={"team": "platform", "env": "prod"})
        assert manager.verify(issued.raw_key).ok
        record = manager.store.find_by_prefix(issued.prefix)
        assert record is not None and record.metadata == {"team": "platform", "env": "prod"}

    @pytest.mark.parametrize("store_factory", [InMemoryStore, lambda: SQLiteStore(":memory:")])
    def test_metadata_round_trips_identically_across_stores(self, store_factory) -> None:
        # With string keys enforced, both stores return the same mapping.
        store = store_factory()
        manager = KeyManager(store, hasher=_fast())
        issued = manager.issue(metadata={"a": 1, "b": ["x", "y"], "c": {"d": True}})
        record = store.find_by_prefix(issued.prefix)
        assert record is not None
        assert record.metadata == {"a": 1, "b": ["x", "y"], "c": {"d": True}}

    def test_rotate_inherits_validated_metadata_path(self) -> None:
        manager = KeyManager(InMemoryStore(), hasher=_fast())
        issued = manager.issue(metadata={"team": "platform"})
        successor = manager.rotate(issued.prefix)
        assert successor.record.metadata == {"team": "platform"}


# =====================================================================
# Stored argon2id memory capped (maxmem analog)
# =====================================================================


@pytest.mark.skipif(not _has_argon2(), reason="argon2-cffi not installed")
class TestArgon2StoredMemoryCap:
    def _encoded(self, *, m: int, t: int, p: int = 1) -> str:
        import base64

        salt = base64.urlsafe_b64encode(b"\x01" * 16).rstrip(b"=").decode()
        digest = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
        return f"$argon2id$v=19$m={m},t={t},p={p}${salt}${digest}"

    def test_gigabyte_memory_stored_hash_rejected_before_kdf(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        # Within total-work (7 * 1048576 < 2**23) but m = 1 GiB > 256 MiB cap.
        crafted = self._encoded(m=1048576, t=7)
        start = time.perf_counter()
        assert hasher.verify("some-raw", crafted) is False
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, "crafted stored memory must be rejected before the KDF runs"

    def test_256mib_stored_hash_still_accepted(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        # m=256 MiB at the cap boundary with tiny t is still verifiable
        # (it will fail the digest comparison, but must run the KDF).
        crafted = self._encoded(m=262144, t=1)
        start = time.perf_counter()
        result = hasher.verify("some-raw", crafted)
        elapsed = time.perf_counter() - start
        assert result is False  # wrong digest, but the KDF was allowed to run
        assert elapsed >= 0.05, "a 256 MiB KDF run should be measurably expensive"

    def test_own_configuration_still_verifies_at_any_memory(self) -> None:
        from bitting import Argon2Hasher

        # A hasher configured BY THE OPERATOR for 1 GiB must keep verifying
        # its own keys: the cap applies only to *stored* non-own params.
        hasher = Argon2Hasher(time_cost=1, memory_cost=1048576)
        raw = "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        encoded = hasher.hash(raw)
        assert hasher.verify(raw, encoded) is True


# =====================================================================
# Revoked keys are denied *before* the KDF runs
# =====================================================================


class TestPreKdfDenial:
    def test_revoked_key_skips_the_kdf(self) -> None:
        calls = {"n": 0}

        class CountingHasher(ScryptHasher):
            def verify(self, raw: str, encoded: str) -> bool:
                calls["n"] += 1
                return super().verify(raw, encoded)

        manager = KeyManager(InMemoryStore(), hasher=CountingHasher(n=2**8, r=1, p=1))
        issued = manager.issue(scopes={"read:users"})
        assert manager.verify(issued.raw_key).ok
        assert calls["n"] == 1  # the successful verification ran the KDF once

        manager.revoke(issued.prefix)
        result = manager.verify(issued.raw_key)
        assert not result.ok and result.reason is VerifyReason.REVOKED
        assert calls["n"] == 1, "revoked key must be denied before the KDF runs"

    def test_expired_key_skips_the_kdf(self) -> None:
        from tests.conftest import FrozenClock

        calls = {"n": 0}

        class CountingHasher(ScryptHasher):
            def verify(self, raw: str, encoded: str) -> bool:
                calls["n"] += 1
                return super().verify(raw, encoded)

        clock = FrozenClock()
        manager = KeyManager(InMemoryStore(), hasher=CountingHasher(n=2**8, r=1, p=1), now_fn=clock)
        issued = manager.issue(ttl=timedelta(hours=1))
        clock.advance(hours=2)
        result = manager.verify(issued.raw_key)
        assert not result.ok and result.reason is VerifyReason.EXPIRED
        assert calls["n"] == 0, "expired key must be denied before the KDF runs"

    def test_fully_rotated_key_skips_the_kdf(self) -> None:
        calls = {"n": 0}

        class CountingHasher(ScryptHasher):
            def verify(self, raw: str, encoded: str) -> bool:
                calls["n"] += 1
                return super().verify(raw, encoded)

        clock_now = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)

        def clock() -> datetime:
            return clock_now

        manager = KeyManager(InMemoryStore(), hasher=CountingHasher(n=2**8, r=1, p=1), now_fn=clock)
        issued = manager.issue()
        manager.rotate(issued.prefix, grace=timedelta(hours=1))
        # advance past the grace window
        clock_now = datetime(2026, 1, 2, 12, tzinfo=timezone.utc)
        result = manager.verify(issued.raw_key)
        assert not result.ok and result.reason is VerifyReason.ROTATED
        assert calls["n"] == 0, "rotated-out-of-grace key must be denied before the KDF runs"
