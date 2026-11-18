"""Tests for the hashers: scrypt (default) and Argon2id (optional)."""

from __future__ import annotations

import pytest

from bitting import ConfigurationError, ScryptHasher

try:
    import argon2  # noqa: F401

    HAS_ARGON2 = True
except ModuleNotFoundError:  # pragma: no cover
    HAS_ARGON2 = False


class TestScryptHasher:
    def test_hash_verify_roundtrip(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1)
        encoded = hasher.hash("btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert encoded.startswith("$scrypt$")
        assert hasher.verify(
            "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", encoded
        )
        assert not hasher.verify(
            "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbX", encoded
        )

    def test_unique_salt_per_hash(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1, salt_length=16)
        raw = "some-key-material"
        assert hasher.hash(raw) != hasher.hash(raw)

    def test_default_cost_works(self) -> None:
        # One test at real production cost to prove the default path.
        hasher = ScryptHasher()
        encoded = hasher.hash("btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert hasher.verify(
            "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", encoded
        )

    def test_rejects_bad_parameters(self) -> None:
        with pytest.raises(ConfigurationError):
            ScryptHasher(n=1000)  # not a power of two
        with pytest.raises(ConfigurationError):
            ScryptHasher(r=0)
        with pytest.raises(ConfigurationError):
            ScryptHasher(salt_length=4)

    def test_verify_rejects_malformed_encoded(self) -> None:
        hasher = ScryptHasher(n=2**8, r=1, p=1)
        for garbage in ("", "$bcrypt$1$2$3$4", "$scrypt$broken", "plaintext"):
            assert not hasher.verify("anything", garbage)

    def test_algorithm_name(self) -> None:
        assert ScryptHasher().algorithm == "scrypt"


@pytest.mark.skipif(not HAS_ARGON2, reason="argon2-cffi not installed")
class TestArgon2Hasher:
    def test_hash_verify_roundtrip(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        encoded = hasher.hash("btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert encoded.startswith("$argon2id$")
        assert hasher.verify(
            "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", encoded
        )
        assert not hasher.verify(
            "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbX", encoded
        )

    def test_rejects_bad_parameters(self) -> None:
        from bitting import Argon2Hasher

        with pytest.raises(ConfigurationError):
            Argon2Hasher(time_cost=0)
        with pytest.raises(ConfigurationError):
            Argon2Hasher(memory_cost=4)

    def test_verify_rejects_malformed_encoded(self) -> None:
        from bitting import Argon2Hasher

        hasher = Argon2Hasher(time_cost=1, memory_cost=8192)
        for garbage in ("", "$scrypt$1$2$3$4", "$argon2i$v=19$m=8,t=1,p=1$a$b"):
            assert not hasher.verify("anything", garbage)

    def test_algorithm_name(self) -> None:
        from bitting import Argon2Hasher

        assert Argon2Hasher(time_cost=1, memory_cost=8192).algorithm == "argon2id"
