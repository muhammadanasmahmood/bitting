"""Storage regression tests.

Pins storage-layer invariants: atomic claim semantics, integer-only
constructor parameters, JSON-only metadata round-trips across both
stores, and the declared dev extra.

Notes:
- ``mark_revoked`` uses the ``at=`` keyword and returns bool (idempotent).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from bitting import InMemoryStore, KeyManager, ScryptHasher, SQLiteStore


def test_targeted_revoke_preserves_rotation_state(fast_hasher, clock) -> None:
    store = InMemoryStore()
    manager = KeyManager(store, hasher=fast_hasher, now_fn=clock)
    old = manager.issue()
    manager.rotate(old.prefix, grace=timedelta(hours=1))
    before = store.find_by_prefix(old.prefix)
    assert before is not None
    revoked = manager.revoke(old.prefix)
    assert revoked.revoked_at == clock.now
    assert revoked.rotated_at == before.rotated_at
    assert revoked.grace_until == before.grace_until


def test_sqlite_targeted_revoke_preserves_rotation_state(fast_hasher, clock, tmp_path) -> None:
    store = SQLiteStore(tmp_path / "keys.db")
    manager = KeyManager(store, hasher=fast_hasher, now_fn=clock)
    old = manager.issue()
    manager.rotate(old.prefix, grace=timedelta(hours=1))
    before = store.find_by_prefix(old.prefix)
    assert before is not None
    manager.revoke(old.prefix)
    after = store.find_by_prefix(old.prefix)
    assert after is not None
    assert after.revoked_at == clock.now
    assert after.rotated_at == before.rotated_at
    assert after.grace_until == before.grace_until
    store.close()


def test_fastapi_scope_configuration_is_validated_at_construction(fast_hasher) -> None:
    pytest.importorskip("fastapi")
    from bitting.integrations.fastapi import APIKeyAuth

    auth = APIKeyAuth(KeyManager(InMemoryStore(), hasher=fast_hasher))
    with pytest.raises(ValueError):
        auth.require(scopes=["bad scope"])
    with pytest.raises(ValueError):
        auth.require(scopes="read:users")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"n": 256.0},
        {"r": 1.5},
        {"p": 1.5},
        {"salt_length": 16.0},
        {"dklen": 32.0},
        {"maxmem": 1024.0},
        {"n": True},
    ],
)
def test_scrypt_rejects_non_integer_configuration(kwargs) -> None:
    """A float n previously raised a raw TypeError from ``n & (n - 1)``,
    a float dklen constructed fine and failed at hash() time, and a bool r
    was silently accepted (True == 1)."""
    with pytest.raises(Exception, match="must be an int"):
        ScryptHasher(**kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"time_cost": 1.5},
        {"memory_cost": 8192.0},
        {"parallelism": 1.5},
        {"salt_length": 16.0},
        {"hash_length": 32.0},
        {"time_cost": True},
    ],
)
def test_argon2_rejects_non_integer_configuration(kwargs) -> None:
    pytest.importorskip("argon2")
    from bitting import Argon2Hasher

    with pytest.raises(Exception, match="must be an int"):
        Argon2Hasher(**kwargs)


def test_manager_rejects_non_json_metadata(fast_hasher, clock) -> None:
    """This was previously accepted silently and the SQLite layer then
    stringified it via json.dumps(default=str), diverging from InMemory."""
    manager = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
    with pytest.raises(ValueError, match="JSON-serializable"):
        manager.issue(metadata={"bad": {1, 2}})


def test_sqlite_rejects_non_json_metadata(fast_hasher, clock, tmp_path) -> None:
    store = SQLiteStore(tmp_path / "keys.db")
    manager = KeyManager(store, hasher=fast_hasher, now_fn=clock)
    with pytest.raises(ValueError, match="JSON-serializable"):
        manager.issue(metadata={"bad": object()})
    store.close()


def test_json_metadata_round_trips_identically_in_both_stores(fast_hasher, clock, tmp_path) -> None:
    """Same JSON metadata round-trip: the same JSON metadata must come back
    equal from both built-in stores."""
    payload = {"team": "platform", "n": 3, "tags": ["a", "b"], "nested": {"k": True}}
    mem = KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)
    k1 = mem.issue(metadata=payload)
    assert mem.store.find_by_prefix(k1.prefix).metadata == payload

    sq = SQLiteStore(tmp_path / "m.db")
    manager = KeyManager(sq, hasher=fast_hasher, now_fn=clock)
    k2 = manager.issue(metadata=payload)
    assert sq.find_by_prefix(k2.prefix).metadata == payload
    sq.close()


def test_pyproject_dev_extra_declares_pytest_cov() -> None:
    """pytest-cov must be declared in the dev extra, so a contributor
    following the coverage instructions had to install it by hand."""
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    dev_section = text.split("dev = [")[1].split("]")[0]
    assert '"pytest-cov' in dev_section
