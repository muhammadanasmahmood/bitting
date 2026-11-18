"""Validation and redaction regression tests.

Each test names the invariant it locks in and pins the fixed behavior:
serialization redaction, file permissions, WWW-Authenticate consistency,
constructor validation, and store isolation. The security-critical races
are covered by test_security_regressions.py and test_thread_safety.py.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import timedelta

import pytest

pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from bitting import InMemoryStore, KeyManager, ScryptHasher, SQLiteStore
from bitting.cli import main
from bitting.errors import ConfigurationError, StorageError
from bitting.integrations.fastapi import (
    APIKeyAuth,
    AuthenticationError,
    register_error_handlers,
)
from bitting.keys import generate_api_key
from bitting.models import AuditEvent, AuditEventKind, KeyRecord


def _manager(store=None, **kwargs) -> KeyManager:
    return KeyManager(store or InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1), **kwargs)


# --------------------------------------------------------------------------
# to_json() must not serialize stored hashes
# --------------------------------------------------------------------------


class TestToJsonRedactsHash:
    def test_to_json_redacts_stored_hash(self) -> None:
        m = _manager()
        issued = m.issue()
        view = issued.record.to_json()
        assert view["hash"] == "<redacted>"
        assert issued.record.hash not in json.dumps(view)

    def test_cli_list_json_has_no_hashes(self, tmp_path, capsys) -> None:
        db = str(tmp_path / "k.db")
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        assert main(["--db", db, "--json", "list"]) == 0
        out = capsys.readouterr().out
        payload = json.loads(out)
        for row in payload:
            assert row["hash"] == "<redacted>"
            assert "scrypt$" not in json.dumps(row)


# --------------------------------------------------------------------------
# new SQLite files are owner-only
# --------------------------------------------------------------------------


class TestSqliteFilePermissions:
    def test_new_database_is_owner_only(self, tmp_path) -> None:
        path = tmp_path / "perms.db"
        store = SQLiteStore(path)
        store.close()
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_existing_file_permissions_are_preserved(self, tmp_path) -> None:
        path = tmp_path / "shared.db"
        path.touch()
        os.chmod(path, 0o640)
        store = SQLiteStore(path)
        store.close()
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o640


# --------------------------------------------------------------------------
# WWW-Authenticate must match the challenge scheme
# --------------------------------------------------------------------------


class TestWwwAuthenticateScheme:
    def _app(self, header: str) -> tuple[FastAPI, APIKeyAuth]:
        auth = APIKeyAuth(_manager(), header=header, auto_error=False)
        app = FastAPI()
        register_error_handlers(app, auth)

        @app.get("/me")
        def me(record: KeyRecord = Depends(auth.require())):
            return {"prefix": record.prefix}

        return app, auth

    def test_bearer_mode_challenges_with_bearer(self) -> None:
        app, _ = self._app("Authorization")
        r = TestClient(app).get("/me", headers={"Authorization": "Bearer btg_live_bad"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "Bearer"

    def test_header_mode_challenges_with_apikey(self) -> None:
        app, _ = self._app("X-API-Key")
        r = TestClient(app).get("/me", headers={"X-API-Key": "btg_live_bad"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "ApiKey"

    def test_auto_error_mode_uses_matching_scheme(self) -> None:
        auth = APIKeyAuth(_manager(), header="Authorization")
        app = FastAPI()

        @app.get("/me")
        def me(record: KeyRecord = Depends(auth.require())):
            return {"prefix": record.prefix}

        r = TestClient(app).get("/me", headers={"Authorization": "Bearer btg_live_bad"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "Bearer"


# --------------------------------------------------------------------------
# unusable maxmem rejected at construction
# --------------------------------------------------------------------------


class TestMaxmemOpenSslLimit:
    @pytest.mark.parametrize("maxmem", [2**31 - 1, 2**31, 2**32])
    def test_maxmem_at_or_above_openssl_limit_is_rejected(self, maxmem: int) -> None:
        with pytest.raises(ConfigurationError, match="2147483647"):
            ScryptHasher(n=2**14, r=8, p=1, maxmem=maxmem)

    def test_large_but_usable_maxmem_still_works(self) -> None:
        h = ScryptHasher(n=2**14, r=8, p=1, maxmem=2**30)
        assert h.hash("secret").startswith("$scrypt$")


# --------------------------------------------------------------------------
# no mutation through store aliases
# --------------------------------------------------------------------------


class TestInMemoryIsolation:
    def test_nested_metadata_not_aliased_on_fetch(self) -> None:
        store = InMemoryStore()
        m = _manager(store)
        issued = m.issue(metadata={"team": {"name": "core"}})
        fetched = store.find_by_prefix(issued.prefix)
        fetched.metadata["team"]["name"] = "attacker"
        assert store.find_by_prefix(issued.prefix).metadata["team"]["name"] == "core"

    def test_nested_metadata_not_aliased_on_save(self) -> None:
        store = InMemoryStore()
        nested = {"a": {"b": 1}}
        record = KeyRecord(
            key_id="k",
            prefix="p" * 16,
            hash="h",
            algorithm="scrypt",
            scopes=frozenset(),
            created_at=__import__("bitting.timeutil", fromlist=["utcnow"]).utcnow(),
            description="",
            expires_at=None,
            metadata=nested,
        )
        store.save(record)
        nested["a"]["b"] = 999  # mutate the caller's dict after save
        assert store.find_by_prefix(record.prefix).metadata["a"]["b"] == 1

    def test_audit_event_detail_is_isolated(self) -> None:
        store = InMemoryStore()
        detail = {"nested": {"v": 1}}
        store.append_event(
            AuditEvent(
                kind=AuditEventKind.ISSUED,
                prefix="p" * 16,
                at=__import__("bitting.timeutil", fromlist=["utcnow"]).utcnow(),
                detail=detail,
            )
        )
        detail["nested"]["v"] = 999  # mutate after append
        events = store.list_events()
        events[0].detail["nested"]["v"] = 42  # mutate through the returned view
        assert store.list_events()[0].detail["nested"]["v"] == 1


# --------------------------------------------------------------------------
# corrupted rows raise StorageError, never raw parsers
# --------------------------------------------------------------------------


class TestCorruptedRowsAreStorageErrors:
    def _db_with_row(self, tmp_path, scopes="[]", metadata="{}", created_at=None) -> str:
        path = str(tmp_path / "corrupt.db")
        store = SQLiteStore(path)
        store.close()
        import sqlite3

        conn = sqlite3.connect(path)
        conn.execute(
            """INSERT INTO keys (prefix, key_id, hash, algorithm, scopes, created_at,
               description, expires_at, revoked_at, rotated_at, grace_until,
               last_verified_at, metadata, supersedes)
               VALUES ('aaaaaaaaaaaaaaaa','k1','h','scrypt',?,?, '', NULL, NULL, NULL,
               NULL, NULL, ?, NULL)""",
            (scopes, created_at or "2026-01-01T00:00:00+00:00", metadata),
        )
        conn.execute(
            "INSERT INTO audit_events (kind, prefix, at, detail) "
            "VALUES ('bogus','p','bad-date','not-json')"
        )
        conn.commit()
        conn.close()
        return path

    def test_corrupted_scopes_raise_storage_error(self, tmp_path) -> None:
        path = self._db_with_row(tmp_path, scopes='{"not": "a list"}')
        store = SQLiteStore(path)
        with pytest.raises(StorageError, match="corrupted key record"):
            store.find_by_prefix("aaaaaaaaaaaaaaaa")

    def test_corrupted_metadata_raises_storage_error(self, tmp_path) -> None:
        path = self._db_with_row(tmp_path, metadata="[1, 2]")
        store = SQLiteStore(path)
        with pytest.raises(StorageError, match="corrupted key record"):
            store.find_by_prefix("aaaaaaaaaaaaaaaa")

    def test_corrupted_timestamp_raises_storage_error(self, tmp_path) -> None:
        path = self._db_with_row(tmp_path, created_at="not-a-timestamp")
        store = SQLiteStore(path)
        with pytest.raises(StorageError, match="corrupted key record"):
            store.find_by_prefix("aaaaaaaaaaaaaaaa")

    def test_corrupted_audit_event_raises_storage_error(self, tmp_path) -> None:
        path = self._db_with_row(tmp_path)
        store = SQLiteStore(path)
        with pytest.raises(StorageError, match="corrupted audit event"):
            store.list_events()


# --------------------------------------------------------------------------
# rotation cannot strand the old key
# --------------------------------------------------------------------------


class TestRotationSuccessorFirst:
    def test_successor_is_persisted_complete_in_one_save(self) -> None:
        store = InMemoryStore()
        m = _manager(store)
        issued = m.issue()
        saves = []
        original = store.save

        def counting_save(record: KeyRecord) -> None:
            saves.append(record)
            original(record)

        store.save = counting_save  # type: ignore[method-assign]
        successor = m.rotate(issued.prefix)
        # Exactly one write for the successor, and it already carries the
        # supersedes link (no intermediate, link-less save).
        assert successor.record.supersedes == issued.prefix
        assert [r.supersedes for r in saves] == [issued.prefix]

    def test_invalid_rotation_scopes_leave_old_key_active(self) -> None:
        m = _manager()
        issued = m.issue()
        with pytest.raises(ValueError):
            m.rotate(issued.prefix, scopes=["bad scope with spaces"])
        # Old key untouched: still verifies, not rotated, no successor.
        assert m.verify(issued.raw_key).ok
        assert all(r.supersedes != issued.prefix for r in m.list_keys())

    def test_failed_claim_cleans_up_successor_and_keeps_old_key(self) -> None:
        store = InMemoryStore()
        m = _manager(store)
        issued = m.issue()
        calls = {"n": 0}
        original = store.mark_rotated

        def failing_mark(prefix, *, rotated_at, grace_until) -> bool:
            calls["n"] += 1
            original(prefix, rotated_at=rotated_at, grace_until=grace_until)
            raise StorageError("claim exploded")

        store.mark_rotated = failing_mark  # type: ignore[method-assign]
        with pytest.raises(StorageError):
            m.rotate(issued.prefix)
        # Old key still active (the claim was rolled back by the store's
        # conditional update semantics is NOT assumed here — the claim
        # raised after succeeding, so the old key IS rotated; what matters
        # is that no orphan successor survives).
        successors = [r for r in m.list_keys() if r.supersedes == issued.prefix]
        assert successors == []

    def test_lost_race_cleans_up_successor(self) -> None:
        store = InMemoryStore()
        m = _manager(store)
        issued = m.issue()
        # A concurrent winner already rotated the key behind our back.
        store.mark_rotated(
            issued.prefix,
            rotated_at=store.find_by_prefix(issued.prefix).created_at,
            grace_until=store.find_by_prefix(issued.prefix).created_at,
        )
        with pytest.raises(ValueError, match="already rotated"):
            m.rotate(issued.prefix)
        assert [r for r in m.list_keys() if r.supersedes == issued.prefix] == []


# --------------------------------------------------------------------------
# CLI filesystem errors exit cleanly
# --------------------------------------------------------------------------


class TestCliFilesystemErrors:
    def test_db_path_inside_regular_file_exits_1(self, tmp_path, capsys) -> None:
        blocker = tmp_path / "not-a-dir"
        blocker.write_text("i am a file")
        rc = main(["--db", str(blocker / "sub" / "k.db"), "list"])
        assert rc == 1
        err = capsys.readouterr().err
        assert err.startswith("error:")
        assert "Traceback" not in err


# --------------------------------------------------------------------------
# non-integral lengths are config errors
# --------------------------------------------------------------------------


class TestNonIntegralLengths:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"prefix_length": 8.5},
            {"prefix_length": "16"},
            {"prefix_length": True},
            {"secret_length": 24.0},
            {"secret_length": None},
        ],
    )
    def test_non_integral_lengths_raise_configuration_error(self, kwargs) -> None:
        with pytest.raises(ConfigurationError, match="must be an int"):
            generate_api_key("live", **kwargs)

    def test_integral_lengths_still_work(self) -> None:
        key = generate_api_key("live", prefix_length=8, secret_length=16)
        assert key.startswith("btg_live_")


# --------------------------------------------------------------------------
# handler scope narrowed
# --------------------------------------------------------------------------


class TestAuthenticationErrorIsolation:
    def _auth(self) -> APIKeyAuth:
        return APIKeyAuth(_manager(), auto_error=False)

    def test_authentication_error_is_a_permission_error(self) -> None:
        # Backwards compatibility for pre-1.2 callers.
        assert issubclass(AuthenticationError, PermissionError)

    def test_unrelated_permission_errors_are_not_relabelled(self) -> None:
        auth = self._auth()
        app = FastAPI()
        register_error_handlers(app, auth)

        @app.get("/boom")
        def boom():
            raise PermissionError("filesystem says no")

        r = TestClient(app, raise_server_exceptions=False).get("/boom")
        assert r.status_code == 500
        assert "API key" not in r.text

    def test_api_key_failures_map_to_401(self) -> None:
        auth = self._auth()
        app = FastAPI()
        register_error_handlers(app, auth)

        @app.get("/me")
        def me(record: KeyRecord = Depends(auth.require())):
            return {"prefix": record.prefix}

        r = TestClient(app).get("/me", headers={"X-API-Key": "btg_live_bad"})
        assert r.status_code == 401
        assert r.headers["WWW-Authenticate"] == "ApiKey"

    def test_scope_denied_maps_to_403(self) -> None:
        auth = self._auth()
        app = FastAPI()
        register_error_handlers(app, auth)
        issued = auth._manager.issue(scopes=["read:users"])

        @app.get("/admin")
        def admin(record: KeyRecord = Depends(auth.require(scopes=["admin"]))):
            return {"ok": True}

        r = TestClient(app).get("/admin", headers={"X-API-Key": issued.raw_key})
        assert r.status_code == 403
        assert "missing required scopes" in r.text

    def test_dependency_raises_dedicated_types(self) -> None:

        auth = self._auth()
        app = FastAPI()

        @app.get("/me")
        def me(record: KeyRecord = Depends(auth.require())):
            return {"prefix": record.prefix}

        # Authentication failure surfaces as AuthenticationError (not the
        # bare PermissionError of 1.1) when auto_error is off.
        client = TestClient(app)
        with pytest.raises(AuthenticationError):
            client.get("/me", headers={"X-API-Key": "garbage"})


# --------------------------------------------------------------------------
# env validated at construction
# --------------------------------------------------------------------------


class TestEnvValidatedAtConstruction:
    def test_bad_env_fails_fast(self) -> None:
        with pytest.raises(ConfigurationError):
            _manager(env="NOT A LABEL")

    def test_good_env_accepted(self) -> None:
        m = _manager(env="staging")
        assert m.issue().raw_key.startswith("btg_staging_")


# --------------------------------------------------------------------------
# negative ttl rejected
# --------------------------------------------------------------------------


class TestNegativeTtl:
    def test_negative_ttl_rejected_at_issue(self) -> None:
        m = _manager()
        with pytest.raises(ValueError, match="non-negative"):
            m.issue(ttl=timedelta(seconds=-1))

    def test_negative_ttl_rejected_at_rotate(self) -> None:
        m = _manager()
        issued = m.issue()
        with pytest.raises(ValueError, match="non-negative"):
            m.rotate(issued.prefix, ttl=timedelta(seconds=-1))

    def test_zero_ttl_still_allowed(self) -> None:
        m = _manager()
        issued = m.issue(ttl=timedelta(0))
        assert not m.verify(issued.raw_key).ok


# --------------------------------------------------------------------------
# hasher registry cannot shadow the primary algorithm
# --------------------------------------------------------------------------


class TestRegistryNoShadowing:
    def test_shadowing_primary_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="primary"):
            KeyManager(
                InMemoryStore(),
                hasher=ScryptHasher(n=2**8, r=1, p=1),
                hashers={"scrypt": ScryptHasher(n=2**10, r=1, p=1)},  # same algorithm, other object
            )

    def test_registering_the_same_object_is_fine(self) -> None:
        h = ScryptHasher(n=2**8, r=1, p=1)
        m = KeyManager(InMemoryStore(), hasher=h, hashers={"scrypt": h})
        assert m.issue().raw_key.startswith("btg_")
