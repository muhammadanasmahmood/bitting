"""Hardening regression tests.

Invariants under test:
  - ScryptHasher construction parameters stay inside the bounds its own
    verify() enforces on stored hashes, so keys that issue also verify
    (no "bricked keys").
  - revoke() is a targeted conditional update (mark_revoked) and cannot
    erase a rotation claimed concurrently.
  - The duck-typed-store touch fallback can lose a concurrent revocation
    (a revoked key verifies again) — documented residual risk, pinned
    below on purpose.
  - FastAPI require() validates scope strings at setup time, not inside
    the request handler.
  - Statistical uniformity of the RNG and constant-time comparison wiring
    are both asserted.
"""

from __future__ import annotations

import base64
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from bitting import ConfigurationError, InMemoryStore, KeyManager, ScryptHasher, VerifyReason
from bitting.storage import SQLiteStore

_RAW = "btg_live_AAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


# =====================================================================
# Scrypt construction bounds + own-config exception
# =====================================================================


class TestScryptConstructionBounds:
    @pytest.mark.parametrize("extra", [{"r": 128}, {"p": 65}, {"p": 10**5}, {"n": 2**23}])
    def test_out_of_bounds_parameters_rejected_at_construction(self, extra) -> None:
        # Pre-fix these constructed fine and hashed fine, but the stored
        # parameters exceeded the verify() sanity bounds, so every issued
        # key failed verification with hash_mismatch forever.
        kwargs: dict = {"n": 2**14, "r": 8, "p": 1, "salt_length": 8}
        kwargs.update(extra)
        with pytest.raises(Exception, match="verifiable"):
            ScryptHasher(**kwargs)

    @pytest.mark.parametrize("extra", [{"r": 64}, {"p": 64}])
    def test_boundary_parameters_accepted_and_self_verify(self, extra) -> None:
        kwargs: dict = {"n": 2**14, "r": 8, "p": 1, "salt_length": 8}
        kwargs.update(extra)
        hasher = ScryptHasher(**kwargs)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded) is True

    def test_default_configuration_still_works(self) -> None:
        hasher = ScryptHasher()
        assert hasher.verify(_RAW, hasher.hash(_RAW)) is True

    def test_cost_change_keeps_old_keys_verifying(self) -> None:
        # Documented contract: tuning parameters never invalidates existing
        # keys. Old-key params differ from the current hasher (non-own) but
        # stay within the sanity bounds.
        old = ScryptHasher(n=2**10, r=8, p=1, salt_length=8)
        encoded = old.hash(_RAW)
        upgraded = ScryptHasher(n=2**12, r=8, p=1, salt_length=8)
        assert upgraded.verify(_RAW, encoded) is True

    def test_own_config_exception_verifies_own_hashes(self) -> None:
        # Any legitimately constructible hasher must verify its own hashes
        # (scrypt + argon2). Unusual-but-in-bounds parameters, cheap
        # work: p at the bound edge, minimal n and r.
        hasher = ScryptHasher(n=2**8, r=1, p=64, salt_length=8)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded) is True
        assert hasher.verify(_RAW + "x", encoded) is False
        # Verification re-derives with the STORED parameters (hashes are
        # self-describing), so a different hasher with compatible maxmem
        # verifies the same digest — by design, not a bypass: the digest
        # can only be produced from the correct raw key.
        other = ScryptHasher(n=2**14, r=8, p=1, salt_length=8)
        assert other.verify(_RAW, encoded) is True
        assert other.verify(_RAW + "x", encoded) is False

    def test_argon2_construction_bounds_match_verify_bounds(self) -> None:
        # Argon2Hasher previously accepted construction
        # parameters (e.g. parallelism=65) that its own verify() rejects
        # outright — bricked keys, same class as the scrypt defect.
        argon2 = pytest.importorskip("argon2")
        assert argon2 is not None
        from bitting import Argon2Hasher

        for kwargs in [
            {"parallelism": 65},
            {"memory_cost": 2**20 + 8},
            {"time_cost": 2**16 + 1},
        ]:
            base: dict = {"time_cost": 1, "memory_cost": 1024, "salt_length": 8, "hash_length": 16}
            base.update(kwargs)
            with pytest.raises(Exception, match="verifiable"):
                Argon2Hasher(**base)

        # heavy but in-bounds configurations keep issuing AND verifying
        heavy = Argon2Hasher(time_cost=64, memory_cost=65536)  # t*m <= 2^23
        encoded = heavy.hash(_RAW)
        assert heavy.verify(_RAW, encoded) is True


# =====================================================================
# Atomic revocation (revoke-vs-rotate lost update)
# =====================================================================


class TestAtomicRevocation:
    @pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
    def test_revoke_never_performs_a_full_record_save(self, store_kind, tmp_path) -> None:
        """The manager's revoke must go through the targeted mark_revoked
        update. A full-record save from a stale snapshot is exactly what
        erased concurrent rotations pre-fix ."""
        store = SQLiteStore(tmp_path / "k.db") if store_kind == "sqlite" else InMemoryStore()
        original_save = store.save
        saves: list[object] = []

        def counting_save(record) -> None:
            saves.append(record.prefix)
            original_save(record)

        store.save = counting_save  # type: ignore[method-assign]
        m = KeyManager(store, hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8))
        issued = m.issue()
        assert saves, "sanity: issue() saves"
        saves.clear()

        m.revoke(issued.prefix)
        assert saves == [], "revoke() must not call save(); it must use mark_revoked"
        final = store.find_by_prefix(issued.prefix)
        assert final is not None and final.revoked_at is not None
        if store_kind == "sqlite":
            store.close()

    @pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
    def test_rotation_and_revocation_coexist(self, store_kind, tmp_path) -> None:
        """Direct stale-snapshot simulation: a rotation claimed 'behind the
        back' of a revocation keeps its metadata, and vice versa."""
        from tests.conftest import FrozenClock

        store = SQLiteStore(tmp_path / "k.db") if store_kind == "sqlite" else InMemoryStore()
        clock = FrozenClock()
        m = KeyManager(store, hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8), now_fn=clock)
        issued = m.issue()
        stale = store.find_by_prefix(issued.prefix)  # snapshot pre-transitions
        assert stale is not None and stale.revoked_at is None

        m.rotate(issued.prefix, grace=timedelta(hours=24))
        assert store.mark_revoked(issued.prefix, at=clock.now) is True

        fresh = store.find_by_prefix(issued.prefix)
        assert fresh is not None
        assert fresh.revoked_at is not None, "revocation was lost"
        assert fresh.rotated_at is not None, "revocation erased the rotation claim"
        assert fresh.grace_until is not None, "revocation erased the grace window"
        assert m.verify(issued.raw_key).reason is VerifyReason.REVOKED

        # the reverse order: revoke first, then rotation must be refused
        issued2 = m.issue()
        assert store.mark_revoked(issued2.prefix, at=clock.now) is True
        assert (
            store.mark_rotated(
                issued2.prefix, rotated_at=clock.now, grace_until=clock.now + timedelta(hours=1)
            )
            is False
        )
        if store_kind == "sqlite":
            store.close()

    def test_revoke_is_idempotent_first_timestamp_wins(self) -> None:
        m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8))
        issued = m.issue()
        first_moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        second_moment = datetime(2027, 6, 1, tzinfo=timezone.utc)
        m.revoke(issued.prefix, now=first_moment)
        record = m.revoke(issued.prefix, now=second_moment)
        assert record.revoked_at == first_moment, "revocation timestamp must not be overwritten"

    def test_repeated_revoke_records_already_revoked_detail(self) -> None:
        store = InMemoryStore()
        m = KeyManager(store, hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8))
        issued = m.issue()
        m.revoke(issued.prefix)
        m.revoke(issued.prefix)
        events = store.list_events(limit=10)
        revoked_events = [e for e in events if e.kind.value == "revoked"]
        assert len(revoked_events) == 2
        details = [e.detail for e in revoked_events]
        assert any(d.get("already_revoked") for d in details)

    def test_revoke_missing_key_still_raises(self) -> None:
        m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8))
        from bitting import KeyNotFoundError

        with pytest.raises(KeyNotFoundError):
            m.revoke("missingmissing1")

    def test_mark_revoked_atomic_claim_semantics(self, tmp_path) -> None:
        # Two SQLite connections race the claim: exactly one wins.
        path = tmp_path / "claim.db"
        s1 = SQLiteStore(path)
        s2 = SQLiteStore(path)
        from tests.conftest import FrozenClock

        clock = FrozenClock()
        m = KeyManager(s1, hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8), now_fn=clock)
        issued = m.issue()
        w1 = s1.mark_revoked(issued.prefix, at=clock.now)
        w2 = s2.mark_revoked(issued.prefix, at=clock.now)
        assert (w1, w2) == (True, False)
        s1.close()
        s2.close()


# =====================================================================
# Documented residual risk — duck-typed stores without mark_verified
# =====================================================================


class LegacyDuckStore:
    """A 1.0-era store: the five original methods, nothing more."""

    def __init__(self) -> None:
        import copy

        self._copy = copy.deepcopy
        self._keys: dict[str, object] = {}
        self._events: list[object] = []
        self._gate = threading.Event()
        self._proceed = threading.Event()
        self._armed = True

    def save(self, record) -> None:
        if self._armed and record.last_verified_at is not None and record.revoked_at is None:
            self._armed = False
            self._gate.set()  # verification touch is between read and save
            self._proceed.wait(10)
        self._keys[record.prefix] = self._copy(record)

    def find_by_prefix(self, prefix):
        record = self._keys.get(prefix)
        return self._copy(record) if record is not None else None

    def delete(self, prefix) -> bool:
        return self._keys.pop(prefix, None) is not None

    def list_keys(self):
        return [self._copy(r) for r in self._keys.values()]

    def append_event(self, event) -> None:
        self._events.append(event)

    def list_events(self, *, limit: int = 100):
        return list(reversed(self._events[-limit:]))


class TestDuckTypedStoreResidualRisk:
    def test_touch_fallback_can_lose_concurrent_revocation_documented(self) -> None:
        """DOCUMENTED RESIDUAL RISK , not a bug in the fix.

        A store that implements only the 1.0 protocol (no ``mark_verified``)
        gets a read-modify-write touch. If a revocation commits between the
        fallback's read and its save, the revocation is lost and the key
        verifies again. This cannot be fixed generically — only the store
        can make the update atomic. The test pins the CURRENT behavior so
        the risk stays visible; production stores must implement
        ``mark_verified`` (README, "Limitations").
        """
        store = LegacyDuckStore()
        m = KeyManager(
            store,
            hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8),
            verify_touch_interval=timedelta(0),
        )
        issued = m.issue(scopes={"read:users"})

        result_box: dict[str, object] = {}

        def verifier() -> None:
            result_box["result"] = m.verify(issued.raw_key)

        thread = threading.Thread(target=verifier)
        thread.start()
        assert store._gate.wait(5), "touch fallback save did not fire"
        # Revocation commits while the touch save is parked.
        m.revoke(issued.prefix)
        store._proceed.set()
        thread.join(10)

        final = store.find_by_prefix(issued.prefix)
        assert final is not None
        # KNOWN, DOCUMENTED LIMITATION : the parked touch
        # save lands on a snapshot read *before* the revocation and erases
        # revoked_at — the key verifies again. This cannot be fixed without
        # store cooperation; the assertion pins the current behavior so the
        # risk stays visible. If this assertion ever FAILS because the
        # fallback became safe, update README "Limitations" accordingly.
        assert final.revoked_at is None, (
            "legacy-store fallback changed: if it is now atomic, update the "
            "README 'Limitations' section and this test"
        )
        resurrected = m.verify(issued.raw_key)
        assert resurrected.ok and resurrected.reason is VerifyReason.OK

    def test_builtin_stores_never_use_the_fallback(self) -> None:
        """Both built-in stores implement mark_verified — the risky fallback
        path is unreachable for them."""
        assert callable(InMemoryStore.mark_verified)
        assert callable(SQLiteStore.mark_verified)
        assert callable(InMemoryStore.mark_revoked)
        assert callable(SQLiteStore.mark_revoked)


# =====================================================================
# FastAPI require() validates scopes at setup
# =====================================================================


class TestRequireScopeValidation:
    def _auth(self):
        fastapi = pytest.importorskip("fastapi")
        from bitting.integrations.fastapi import APIKeyAuth

        assert fastapi is not None
        manager = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1, salt_length=8))
        return APIKeyAuth(manager)

    @pytest.mark.parametrize("scopes", [{"read:users "}, {""}, {"bad scope"}, {"a", "ok", ""}])
    def test_malformed_scopes_raise_at_setup(self, scopes) -> None:
        with pytest.raises(ValueError, match="route-configuration"):
            self._auth().require(scopes=scopes)

    def test_non_iterable_scopes_raise_at_setup(self) -> None:
        with pytest.raises((ValueError, TypeError)):
            self._auth().require(scopes=12345)  # type: ignore[arg-type]

    def test_bare_string_scopes_raise_at_setup(self) -> None:
        # A bare string previously exploded into single
        # characters ("read:users" -> {'r','e','a',...}) and was silently
        # accepted, 403-ing every request that should have matched.
        with pytest.raises(ValueError, match="iterable of scope strings"):
            self._auth().require(scopes="read:users")  # type: ignore[arg-type]

    def test_valid_scopes_accepted(self) -> None:
        dep = self._auth().require(scopes={"read:users", "*"})
        assert callable(dep)


# =====================================================================
# RNG uniformity + constant-time comparison wiring
# =====================================================================


class TestRngUniformity:
    def test_base62_sampling_is_statistically_uniform(self) -> None:
        """Chi-square goodness-of-fit over the real generator path.

        A modulo-biased sampler (bytes % 62 without rejection) overweights
        the first 8 alphabet symbols by ~25% each; with 62*2000 draws that
        shifts chi-square far above 200, while a true-uniform generator
        stays near the degrees of freedom (61 +/- ~11). The threshold 400
        is generous on purpose: no healthy RNG can reach it, no biased
        sampler of this shape can stay under it.
        """
        from bitting.keys import _random_token

        counts = [0] * 62
        draws = 62 * 2000
        for _ in range(draws):
            counts[
                "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".index(
                    _random_token(1)
                )
            ] += 1
        expected = draws / 62
        chi2 = sum((c - expected) ** 2 / expected for c in counts)
        assert chi2 < 400, f"base62 sampling not uniform: chi2={chi2:.1f} (dof=61)"
        # sanity in the other direction: a degenerate generator (all one
        # symbol) would produce chi2 ~ 244k, so the test has real teeth.
        assert chi2 > 20, f"suspiciously perfect fit: chi2={chi2:.1f}"


class TestConstantTimeWiring:
    def test_scrypt_verify_uses_compare_digest(self, monkeypatch) -> None:
        """The constant-time comparison control must actually be wired in
        (mutation testing showed '==' replacing compare_digest survives
        every behavioral test)."""
        import bitting.hashing as hashing_module

        called = []

        def fake_compare(a, b):
            called.append((a, b))
            return True

        monkeypatch.setattr(hashing_module.hmac, "compare_digest", fake_compare)
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=8)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded) is True
        assert len(called) == 1, "ScryptHasher.verify must compare via hmac.compare_digest"

    def test_argon2_verify_uses_compare_digest(self, monkeypatch) -> None:
        pytest.importorskip("argon2")
        import bitting.hashing as hashing_module
        from bitting import Argon2Hasher

        called = []

        def fake_compare(a, b):
            called.append((a, b))
            return True

        monkeypatch.setattr(hashing_module.hmac, "compare_digest", fake_compare)
        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded) is True
        assert len(called) == 1, "Argon2Hasher.verify must compare via hmac.compare_digest"


# =====================================================================
# Crafted scrypt stored-hash work envelope (bounds documentation)
# =====================================================================


class TestCraftedScryptEnvelope:
    def test_crafted_high_parallelism_rejected_or_bounded(self) -> None:
        """A crafted p=64 record within the generic bounds runs the KDF at
        bounded memory (<= maxmem). It must return False (digest never
        matches) and finish in bounded time — the measured envelope on a
        2-vCPU container was ~0.2-4 s; the 30 s ceiling is CI-safe."""
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=8)  # tiny maxmem
        # memory for n=2^8,r=1,p=64 is ~66 KiB — far under any maxmem, so
        # this crafted record exercises the p-bound without heavy cost.
        salt = base64.urlsafe_b64encode(b"\x01" * 16).rstrip(b"=").decode()
        digest = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
        crafted = f"$scrypt$n=256$r=1$p=64${salt}${digest}"
        start = time.monotonic()
        assert hasher.verify(_RAW, crafted) is False
        assert time.monotonic() - start < 30

    def test_out_of_bounds_crafted_params_rejected_pre_kdf(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=8)
        salt = base64.urlsafe_b64encode(b"\x01" * 16).rstrip(b"=").decode()
        digest = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=").decode()
        for n, r, p in [(2**23, 8, 1), (2**14, 65, 1), (2**14, 8, 65)]:
            crafted = f"$scrypt$n={n}$r={r}$p={p}${salt}${digest}"
            start = time.monotonic()
            assert hasher.verify(_RAW, crafted) is False
            assert time.monotonic() - start < 0.5, "must reject before running the KDF"


# =====================================================================
# Scrypt r=1 with n>=2**16 is unusable on
# OpenSSL (hash() raises raw ValueError regardless of maxmem) while being
# in-bounds and under the documented 1 GiB ceiling — construction must
# fail fast instead of issuing a hasher that crashes on first use.
# =====================================================================


class TestScryptR1LargeN:
    def test_r1_large_n_rejected_at_construction(self) -> None:
        for n in (2**16, 2**18, 2**20, 2**22):
            with pytest.raises(ConfigurationError, match="r=1 with n>=2"):
                ScryptHasher(n=n, r=1, p=1, salt_length=8)

    def test_r1_small_n_and_r2_large_n_still_work(self) -> None:
        # the boundary: r=1 stays valid below 2**16 ...
        small = ScryptHasher(n=2**15, r=1, p=1, salt_length=8)
        assert small.verify(_RAW, small.hash(_RAW)) is True
        # ... and r>=2 keeps working throughout the documented range.
        big = ScryptHasher(n=2**16, r=2, p=1, salt_length=8)
        assert big.verify(_RAW, big.hash(_RAW)) is True

    def test_default_configuration_unaffected(self) -> None:
        hasher = ScryptHasher()
        assert hasher.verify(_RAW, hasher.hash(_RAW)) is True


# =====================================================================
# A duck-typed store without
# the mark_* methods used to accept the non-atomic fallback SILENTLY.
# The residual risk stays (it is architectural), but constructing such a
# manager now warns loudly once, and the risk acceptance must be explicit
# (module-level opt-out).
# =====================================================================


class LegacyStore:
    """A minimal pre-1.1 duck-typed store: five methods, no mark_*."""

    def __init__(self) -> None:
        self._records: dict = {}

    def save(self, record) -> None:  # type: ignore[override]
        self._records[record.prefix] = record

    def find_by_prefix(self, prefix: str):
        return self._records.get(prefix)

    def delete(self, prefix: str) -> bool:  # type: ignore[override]
        return self._records.pop(prefix, None) is not None

    def list_keys(self):  # type: ignore[override]
        return list(self._records.values())

    def append_event(self, event) -> None:  # type: ignore[override]
        pass

    def list_events(self, *, limit: int = 100):  # type: ignore[override]
        return []


class TestLegacyStoreWarning:
    def test_legacy_store_warns_at_construction(self) -> None:
        import warnings as warnings_mod

        from bitting.manager import LEGACY_STORE_WARNING

        assert LEGACY_STORE_WARNING is True
        with warnings_mod.catch_warnings(record=True) as caught:
            warnings_mod.simplefilter("always")
            manager = KeyManager(LegacyStore(), hasher=ScryptHasher(n=2**8, r=1, p=1))
        assert any("mark_verified, mark_rotated, mark_revoked" in str(w.message) for w in caught)
        # The fallback itself still works (documented residual risk).
        issued = manager.issue()
        assert manager.verify(issued.raw_key).ok

    def test_modern_store_does_not_warn(self) -> None:
        import warnings as warnings_mod

        with warnings_mod.catch_warnings(record=True) as caught:
            warnings_mod.simplefilter("always")
            KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1))
        assert not caught, [w.message for w in caught]
