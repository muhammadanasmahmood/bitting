"""Adversarial security regression suite.

Every test here encodes a fixed defect or a security invariant that must
hold. Tests are deterministic: race conditions are forced with explicit
synchronization instead of sleeps.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest

from bitting import (
    Argon2Hasher,
    InMemoryStore,
    KeyManager,
    ScryptHasher,
    parse_api_key,
    scope_matches,
)
from bitting.storage import SQLiteStore


def fast_manager(store, **kw):
    """A manager with cheap scrypt so tests stay fast."""
    return KeyManager(store, hasher=ScryptHasher(n=2**8, r=8, p=1), **kw)


# =====================================================================
# Verify touch-save must never resurrect revoked/rotated keys
# =====================================================================


class GatedHasher(ScryptHasher):
    """Hasher whose verify() blocks until released, to force the race window.

    The gate lets a test hold a verification between the store read and the
    touch-write, so a concurrent revoke/rotate can be interleaved
    deterministically.
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.result = True

    def verify(self, raw, encoded):
        self.entered.set()
        self.release.wait(timeout=10)
        return self.result


@pytest.mark.parametrize("store_factory", [InMemoryStore, lambda: SQLiteStore(":memory:")])
def test_revoke_during_verify_does_not_resurrect(store_factory):
    """A verification in flight when revoke() commits must not erase the revocation."""
    store = store_factory()
    m = KeyManager(store, hasher=GatedHasher(n=2**8), verify_touch_interval=timedelta(0))
    issued = m.issue(scopes={"read:users"})
    assert m.verify(issued.raw_key).ok  # sets last_verified_at

    gate = m.hasher
    gate.result = True
    outcome = {}

    def verifier():
        outcome["result"] = m.verify(issued.raw_key)

    t = threading.Thread(target=verifier)
    t.start()
    assert gate.entered.wait(timeout=5)  # verify is now between read and touch

    m.revoke(issued.prefix)  # revocation commits while verify is parked

    gate.release.set()
    t.join(timeout=5)

    stored = store.find_by_prefix(issued.prefix)
    assert stored.revoked_at is not None, "revocation was erased by concurrent verify"
    again = m.verify(issued.raw_key)
    assert not again.ok and again.reason.value == "revoked"


@pytest.mark.parametrize("store_factory", [InMemoryStore, lambda: SQLiteStore(":memory:")])
def test_rotate_during_verify_does_not_resurrect(store_factory):
    """A verification in flight when rotate() commits must not undo the rotation."""
    store = store_factory()
    m = KeyManager(store, hasher=GatedHasher(n=2**8), verify_touch_interval=timedelta(0))
    issued = m.issue(scopes={"read:users"})
    assert m.verify(issued.raw_key).ok

    gate = m.hasher
    outcome = {}

    def verifier():
        outcome["result"] = m.verify(issued.raw_key)

    t = threading.Thread(target=verifier)
    t.start()
    assert gate.entered.wait(timeout=5)

    successor = m.rotate(issued.prefix, grace=timedelta(hours=1))

    gate.release.set()
    t.join(timeout=5)

    stored = store.find_by_prefix(issued.prefix)
    assert stored.rotated_at is not None, "rotation was erased by concurrent verify"
    assert stored.grace_until is not None, "grace window was erased by concurrent verify"
    r = m.verify(issued.raw_key)
    assert (not r.ok and r.reason.value in {"rotated", "rotated_grace"}) or (
        r.ok and r.reason.value == "rotated_grace"
    )
    # the old key must never verify as a plain active key again
    if r.ok:
        assert r.reason.value == "rotated_grace"
    assert m.verify(successor.raw_key).ok


def test_touch_write_does_not_clobber_scopes_or_hash():
    """The touch write must be a targeted update, not a full-record replace."""
    store = InMemoryStore()
    m = fast_manager(store, verify_touch_interval=timedelta(0))
    issued = m.issue(scopes={"read:users"})
    assert m.verify(issued.raw_key).ok

    # operator narrows the key's scopes directly in the store (documented use
    # of store.save), then a throttled touch fires for an old snapshot
    record = store.find_by_prefix(issued.prefix)
    from dataclasses import replace

    narrowed = replace(record, scopes=frozenset({"read:nothing"}))
    store.save(narrowed)

    r = m.verify(issued.raw_key, required_scopes={"read:users"})
    assert not r.ok, "verify must honor the narrowed scopes (read the fresh record)"


# =====================================================================
# Hashers must fail safe on malformed stored hashes (no exceptions)
# =====================================================================


@pytest.mark.parametrize("bad_encoded", [None, 123, b"$scrypt$n=16384$r=8$p=1$x$y", [], {}])
def test_verify_never_raises_on_nonstring_encoded(bad_encoded):
    for hasher in (ScryptHasher(n=2**8), Argon2Hasher(time_cost=1, memory_cost=64)):
        assert hasher.verify("btg_live_x_y_z_w", bad_encoded) is False


# =====================================================================
# Crafted stored-hash parameters must not force huge verification cost
# =====================================================================


def test_argon2_total_work_is_bounded():
    """Stored argon2 params with huge t*m product must be rejected pre-KDF.

    Pre-fix, this crafted record (m=256 MiB, t=1024 — inside the old
    per-parameter sanity bounds) drives the KDF for ~170 seconds on this
    machine. The fix must reject it before any Argon2 work; we assert a
    generous 10 s ceiling (34x faster than the measured pre-fix time).
    """
    import time

    h = Argon2Hasher(time_cost=1, memory_cost=64)
    salt = "c2FsdHNhbHRzYWx0c2FsdA"
    crafted = f"$argon2id$v=19$m=262144,t=1024,p=1${salt}${'A' * 43}"
    t0 = time.monotonic()
    assert h.verify("btg_live_x_y_z_w", crafted) is False
    elapsed = time.monotonic() - t0
    assert elapsed < 10.0, f"crafted stored hash forced {elapsed:.1f}s of KDF work"
    # sanity: the hasher's own (legitimate) hashes still verify
    good = h.hash("btg_live_x_y_z_w")
    assert h.verify("btg_live_x_y_z_w", good) is True


def test_hasher_own_extreme_config_still_verifies():
    """A deliberately heavy configured hasher must still verify its own hashes."""
    h = Argon2Hasher(time_cost=64, memory_cost=65536)  # heavy but legitimate
    good = h.hash("btg_live_x_y_z_w")
    assert h.verify("btg_live_x_y_z_w", good) is True


@pytest.mark.parametrize("digest_b64_len", [200 * 1024, 1024 * 1024])
def test_oversized_digest_rejected_pre_kdf(digest_b64_len):
    """A stored hash whose base64 digest is absurdly large must be rejected
    before any allocation or KDF work (both hashers)."""
    salt = "c2FsdHNhbHRzYWx0c2FsdA"
    giant = "A" * digest_b64_len
    assert ScryptHasher(n=2**8).verify("x", f"$scrypt$n=1024$r=8$p=1${salt}${giant}") is False
    assert (
        Argon2Hasher(time_cost=1, memory_cost=64).verify(
            "x", f"$argon2id$v=19$m=64,t=1,p=1${salt}${giant}"
        )
        is False
    )


def test_oversized_salt_rejected_pre_kdf():
    salt = "A" * (512 * 1024)
    assert ScryptHasher(n=2**8).verify("x", f"$scrypt$n=1024$r=8$p=1${salt}{'A' * 43}") is False
    assert (
        Argon2Hasher(time_cost=1, memory_cost=64).verify(
            "x", f"$argon2id$v=19$m=64,t=1,p=1${salt}{'A' * 43}"
        )
        is False
    )


# =====================================================================
# issue() must reject a plain string passed as scopes
# =====================================================================


def test_scopes_as_string_rejected():
    m = fast_manager(InMemoryStore())
    with pytest.raises(ValueError, match="iterable of scope strings"):
        m.issue(scopes="read:users")  # type: ignore[arg-type]


def test_scopes_as_bytes_rejected():
    m = fast_manager(InMemoryStore())
    with pytest.raises(ValueError):
        m.issue(scopes=b"read:users")  # type: ignore[arg-type]


# =====================================================================
# verify() must validate required_scopes
# =====================================================================


def test_required_scopes_validated():
    m = fast_manager(InMemoryStore())
    issued = m.issue(scopes={"read:users"})
    with pytest.raises(ValueError, match="required scope"):
        m.verify(issued.raw_key, required_scopes={"read:users "})
    with pytest.raises(ValueError, match="required scope"):
        m.verify(issued.raw_key, required_scopes={""})
    with pytest.raises(ValueError, match="required scope"):
        m.verify(issued.raw_key, required_scopes={123})  # type: ignore[arg-type]
    # valid usages keep working
    assert m.verify(issued.raw_key).ok
    assert m.verify(issued.raw_key, required_scopes=set()).ok


# =====================================================================
# Library verify() and FastAPI layer must agree on whitespace
# =====================================================================


def test_whitespace_padded_key_verifies_like_fastapi_layer():
    """The FastAPI integration strips header whitespace before verify(); the
    library-level verify must accept the same padded key so both layers
    behave identically."""
    m = fast_manager(InMemoryStore())
    issued = m.issue()
    r = m.verify(f"  {issued.raw_key}\n")
    assert r.ok, "padded key should verify like the FastAPI layer does"


def test_parse_rejects_internal_whitespace():
    from bitting import KeyFormatError

    with pytest.raises(KeyFormatError):
        parse_api_key("btg_live AAAA 1111")


# =====================================================================
# manager-level fail-safe on a raising custom hasher
# =====================================================================


class ExplodingHasher(ScryptHasher):
    def verify(self, raw, encoded):  # pragma: no cover - deliberately broken
        raise RuntimeError("boom: corrupted hash record")


def test_manager_survives_raising_hasher():
    """A custom/corrupted hasher raising mid-verify must produce a failed
    VerifyResult, not an unhandled exception."""
    m = KeyManager(InMemoryStore(), hasher=ExplodingHasher(n=2**8))
    issued = m.issue()
    result = m.verify(issued.raw_key)
    assert not result.ok
    assert result.reason.value == "hash_mismatch"


# =====================================================================
# Scope-matching security invariants (must never regress)
# =====================================================================


@pytest.mark.parametrize(
    ("granted", "required", "expected"),
    [
        ("read:*", "read:users", True),
        ("read:*", "read:users:admin", True),  # documented prefix semantics
        ("read:users", "read:users:admin", False),  # no escalation
        ("read:users", "READ:USERS", False),  # case-sensitive
        ("read:users*", "read:users", False),  # non-colon wildcards are literal
        ("read:use*", "read:users", False),
        ("*", "admin:all", True),  # explicit global wildcard
        ("read:*", "write:users", False),
        ("read:*", "readx", False),
        ("read", "read:users", False),
    ],
)
def test_scope_invariants(granted, required, expected):
    assert scope_matches(granted, required) is expected
