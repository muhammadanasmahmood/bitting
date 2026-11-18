"""Regression tests for hashing hardening.

- scrypt's maxmem is derived from the configured parameters, and
  configurations that would exceed the ceiling are rejected at
  construction instead of failing on every hash().
- Parameters read back from a *stored* hash are bounds-checked, and
  too-short digests are refused, before any KDF work happens.
- Argon2Hasher rejects memory_cost < 8 * parallelism at construction.
"""

from __future__ import annotations

import hashlib
import time

import pytest

from bitting import ConfigurationError, ScryptHasher

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ModuleNotFoundError:  # pragma: no cover
    HAS_ARGON2 = False

_RAW = "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


class TestScryptMaxmem:
    def test_high_cost_configuration_hashes_and_verifies(self) -> None:
        # n=2**18 with r=8 needs ~268 MiB — above the old hard-coded
        # 256 MiB cap that silently broke every hash() call.
        hasher = ScryptHasher(n=2**18, r=8, p=1, salt_length=8)
        encoded = hasher.hash(_RAW)
        assert hasher.verify(_RAW, encoded)
        assert not hasher.verify(_RAW + "x", encoded)

    def test_explicit_maxmem_below_requirement_rejected_at_init(self) -> None:
        with pytest.raises(ConfigurationError, match="maxmem"):
            ScryptHasher(n=2**14, r=8, p=1, maxmem=1024)

    def test_absurd_cost_rejected_at_construction(self) -> None:
        # ~4.3 GiB: above the 1 GiB ceiling — must fail at init, not at
        # the first hash() call.
        with pytest.raises(ConfigurationError, match="MiB ceiling"):
            ScryptHasher(n=2**22, r=8)

    def test_short_dklen_rejected_at_init(self) -> None:
        with pytest.raises(ConfigurationError, match="dklen"):
            ScryptHasher(n=2**8, r=1, p=1, dklen=8)


class TestStoredParameterBounds:
    def _encoded(self, *, n: int, r: int, p: int, digest: bytes) -> str:
        import base64

        def b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        salt = b"\x01" * 16
        return f"$scrypt$n={n}$r={r}$p={p}${b64(salt)}${b64(digest)}"

    def test_huge_parallelism_rejected_without_kdf_work(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=8)
        crafted = self._encoded(n=2**14, r=8, p=10**6, digest=b"\x00" * 32)
        start = time.perf_counter()
        assert hasher.verify(_RAW, crafted) is False
        elapsed = time.perf_counter() - start
        assert elapsed < 0.5, "crafted stored params must be rejected before the KDF runs"

    def test_out_of_bounds_n_and_r_rejected(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=8)
        assert hasher.verify(_RAW, self._encoded(n=2**23, r=8, p=1, digest=b"\x00" * 32)) is False
        assert (
            hasher.verify(_RAW, self._encoded(n=2**14, r=2**10, p=1, digest=b"\x00" * 32)) is False
        )

    def test_too_short_digest_rejected_even_when_derivation_would_match(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=16, dklen=32)
        # Build a *genuine* 8-byte digest: without the length guard the
        # comparison would succeed; the guard must refuse it outright.
        digest = hashlib.scrypt(
            _RAW.encode(), salt=b"\x01" * 16, n=2**8, r=1, p=1, dklen=8, maxmem=64 * 1024**2
        )
        import base64

        digest_b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        salt_b64 = base64.urlsafe_b64encode(b"\x01" * 16).rstrip(b"=").decode("ascii")
        crafted = f"$scrypt$n=256$r=1$p=1${salt_b64}${digest_b64}"
        assert hasher.verify(_RAW, crafted) is False


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
class TestArgon2Validation:
    def test_memory_cost_below_parallelism_minimum_rejected_at_init(self) -> None:
        from bitting import Argon2Hasher

        with pytest.raises(ConfigurationError, match="8 \\* parallelism"):
            Argon2Hasher(time_cost=1, memory_cost=8, parallelism=4)

    def test_out_of_bounds_stored_params_rejected(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        crafted = (
            "$argon2id$v=19$m=8192,t=999999,p=1"
            "$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        assert hasher.verify(_RAW, crafted) is False

    def test_short_digest_rejected(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        crafted = "$argon2id$v=19$m=8192,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAA"
        assert hasher.verify(_RAW, crafted) is False
