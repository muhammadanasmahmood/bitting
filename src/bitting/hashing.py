"""Key hashing: a protocol plus scrypt (stdlib) and Argon2id (optional) backends.

Why memory-hard hashing?
========================
An API key store is only as safe as its weakest link if the database
leaks. Fast hashes such as SHA-256 let an attacker test *billions* of
candidate keys per second on commodity GPUs. Memory-hard KDFs (scrypt,
Argon2id) are deliberately expensive in both time and memory, reducing
offline guessing to a crawl. bitting therefore hashes keys with scrypt
by default — using only the standard library — and offers Argon2id via
the optional ``bitting[argon2]`` extra.

Encoded format
==============
Hashes are self-describing so parameters can be tuned per deployment and
per key::

    $scrypt$n=16384$r=8$p=1$<salt-b64>$<hash-b64>
    $argon2id$v=19$m=65536,t=3,p=1$<salt-b64>$<hash-b64>

Verification is constant-time (:func:`hmac.compare_digest`).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from typing import Protocol, runtime_checkable

from .errors import ConfigurationError

__all__ = ["DEFAULT_SCRYPT_N", "Argon2Hasher", "Hasher", "ScryptHasher"]


@runtime_checkable
class Hasher(Protocol):
    """Anything that can hash and verify raw API keys."""

    @property
    def algorithm(self) -> str:
        """Short algorithm identifier used in the encoded hash."""
        ...

    def hash(self, raw: str) -> str:
        """Hash a raw key, returning a self-describing encoded string."""
        ...

    def verify(self, raw: str, encoded: str) -> bool:
        """Constant-time verification of a raw key against an encoded hash."""
        ...


#: Default scrypt CPU/memory cost (2**14 = 16 MiB per hash).
DEFAULT_SCRYPT_N = 2**14

#: Upper bound on scrypt memory use when ``maxmem`` is not given (1 GiB).
#: Configurations that would need more are rejected at construction.
SCRYPT_MAXMEM_CEILING = 1024 * 1024 * 1024

# Sanity bounds for parameters read back from a *stored* encoded hash.
# A crafted store record must not be able to force absurd CPU or memory
# use at verification time.
_SCRYPT_MAX_N = 2**22
_SCRYPT_MAX_R = 64
_SCRYPT_MAX_P = 64
_ARGON2_MAX_T = 2**16
_ARGON2_MAX_M = 2**20  # KiB (1 GiB)
_ARGON2_MAX_P = 64
#: Shortest digest both hashers will verify (bytes).
_MIN_DIGEST_LENGTH = 16
#: Longest salt/digest both hashers will accept from a stored encoded
#: hash (bytes). Bounds the allocation a crafted record can force.
_MAX_SALT_LENGTH = 512
_MAX_DIGEST_LENGTH = 512
#: Ceiling on total Argon2id work (time_cost * memory_cost in KiB-passes)
#: accepted from a *stored* hash unless it matches the hasher's own
#: configuration. 2**23 allows e.g. t=8 x 1 GiB or t=64 x 128 MiB while
#: rejecting pathological combinations (t=1024 x 256 MiB ≈ minutes of CPU).
_ARGON2_MAX_WORK = 2**23
#: Independent ceiling on stored Argon2id time_cost (passes).
_ARGON2_MAX_T_STRICT = 4096
#: Ceiling on the memory a *stored* (non-own-config) Argon2id hash may
#: demand per verification, in KiB — the argon2 analog of scrypt's
#: ``maxmem``. Bounding total work alone still admitted e.g. m=1 GiB x
#: t=7 (within 2**23) — a ~1 GiB allocation per crafted record verified.
#: 256 MiB covers deliberately heavy real deployments (RFC 9106 second
#: recommended option: m=256 MiB, t=3) while capping crafted records.
_ARGON2_STORED_MAX_M = 256 * 1024

#: Total scrypt work (``n * r * p``) of the documented default profile.
#: Used as the floor for the stored-hash work budget below.
_SCRYPT_DEFAULT_WORK = DEFAULT_SCRYPT_N * 8 * 1
#: How much more work a *stored* scrypt hash may demand than this
#: deployment's own configured profile. Per-parameter bounds and
#: ``maxmem`` alone do not bound CPU: ``n=131072, r=2, p=64`` fits in
#: 32 MiB yet costs ~67x the default profile (measured: ~4 s per verify).
#: Stored parameters that match the hasher's own configuration exactly
#: are always accepted, so deliberately heavy deployments keep working.
_SCRYPT_MAX_WORK_FACTOR = 4

#: Canonical parameter syntax for stored encoded hashes. Anchored and
#: digits-only: rejects ``n=+256``, ``n=256=999``, ``n=1_024``, ``n= 256``
#: and renamed keys, all of which ``int(part.split("=")[1])`` accepted.
_SCRYPT_PARAM_RES = (
    re.compile(r"n=([0-9]+)"),
    re.compile(r"r=([0-9]+)"),
    re.compile(r"p=([0-9]+)"),
)
_ARGON2_PARAM_RE = re.compile(r"([mtp])=([0-9]+)")


def _require_int(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an int")


def _scrypt_memory(n: int, r: int, p: int) -> int:
    """Bytes of memory OpenSSL's scrypt needs for these parameters."""
    return 128 * r * (n + p)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


class ScryptHasher:
    """Memory-hard hasher backed by :func:`hashlib.scrypt` (stdlib only).

    Args:
        n: CPU/memory cost (must be a power of two). Default ``2**14``
            (~16 MiB per hash) — a deliberate middle ground between
            verification latency and offline-guessing resistance.
        r: Block size for scrypt.
        p: Parallelization factor.
        salt_length: Random salt length in bytes (16 recommended).
        dklen: Derived key length in bytes (>= 16).
        maxmem: Maximum bytes scrypt may allocate. By default it is
            derived from the configured parameters (plus slack), so any
            internally consistent configuration works; configurations
            whose derived limit would exceed 1 GiB are rejected at
            construction instead of failing on every hash.

    Raises:
        ConfigurationError: If parameters are out of range or exceed
            the memory ceiling.
    """

    def __init__(
        self,
        *,
        n: int = DEFAULT_SCRYPT_N,
        r: int = 8,
        p: int = 1,
        salt_length: int = 16,
        dklen: int = 32,
        maxmem: int | None = None,
    ) -> None:
        for name, value in (
            ("n", n),
            ("r", r),
            ("p", p),
            ("salt_length", salt_length),
            ("dklen", dklen),
        ):
            _require_int(name, value)
        if maxmem is not None:
            _require_int("maxmem", maxmem)
        if n < 2 or n & (n - 1):
            raise ConfigurationError("scrypt n must be a power of two >= 2")
        if r < 1 or p < 1:
            raise ConfigurationError("scrypt r and p must be >= 1")
        if r == 1 and n >= 2**16:
            # OpenSSL rejects this combination at hash() time with a raw
            # ValueError ("memory limit exceeded") *regardless of maxmem*
            # (verified: n=2**16..2**22, r=1, maxmem up to 2**31-2 all fail;
            # r>=2 works throughout the documented range). The parameters are
            # in-bounds and under the memory ceiling, so construction used to
            # succeed and every hash() then crashed — contradicting the
            # documented "any consistent configuration up to 1 GiB works"
            # (same defect class as the bricked-key fix).
            # Fail fast with a clear error instead.
            raise ConfigurationError(
                f"scrypt r=1 with n>=2**16 is rejected by OpenSSL regardless of "
                f"maxmem; use r>=2 or lower n (got n={n}, r=1)"
            )
        # Construction bounds mirror the sanity bounds verify() enforces on
        # *stored* hashes (see _SCRYPT_MAX_*). Without them a hasher can be
        # configured to issue keys whose stored parameters verification then
        # rejects outright — keys that hash fine but never verify
        # (silently bricked keys). Parameters equal to this hasher's
        # own configuration are always accepted at verification time, so any
        # in-bounds configuration keeps working after upgrades/downgrades.
        if n > _SCRYPT_MAX_N:
            raise ConfigurationError(
                f"scrypt n must be <= {_SCRYPT_MAX_N} so issued keys stay verifiable (got {n})"
            )
        if r > _SCRYPT_MAX_R:
            raise ConfigurationError(
                f"scrypt r must be <= {_SCRYPT_MAX_R} so issued keys stay verifiable (got {r})"
            )
        if p > _SCRYPT_MAX_P:
            raise ConfigurationError(
                f"scrypt p must be <= {_SCRYPT_MAX_P} so issued keys stay verifiable (got {p})"
            )
        if salt_length < 8:
            raise ConfigurationError("salt_length must be >= 8 bytes")
        if salt_length > _MAX_SALT_LENGTH:
            raise ConfigurationError(
                f"salt_length must be <= {_MAX_SALT_LENGTH} bytes (got {salt_length})"
            )
        if dklen < _MIN_DIGEST_LENGTH:
            raise ConfigurationError(f"dklen must be >= {_MIN_DIGEST_LENGTH} bytes")
        if dklen > _MAX_DIGEST_LENGTH:
            raise ConfigurationError(f"dklen must be <= {_MAX_DIGEST_LENGTH} bytes (got {dklen})")
        required = _scrypt_memory(n, r, p)
        if maxmem is None:
            if required > SCRYPT_MAXMEM_CEILING:
                raise ConfigurationError(
                    f"scrypt parameters need {required / 1024**2:.0f} MiB, above the "
                    f"{SCRYPT_MAXMEM_CEILING / 1024**2:.0f} MiB ceiling; lower n/r or "
                    "pass maxmem explicitly"
                )
            maxmem = required + 32 * 1024 * 1024  # slack for runtime overhead
        elif maxmem < required:
            raise ConfigurationError(
                f"maxmem ({maxmem / 1024**2:.0f} MiB) is below what n={n}, r={r}, "
                f"p={p} requires ({required / 1024**2:.0f} MiB)"
            )
        if maxmem >= 2**31 - 1:
            # OpenSSL rejects maxmem >= 2**31-1 at hash time with a raw
            # ValueError; fail at construction with a clear error instead.
            raise ConfigurationError("maxmem must be smaller than 2147483647 (OpenSSL limit)")
        self.n = n
        self.r = r
        self.p = p
        self.salt_length = salt_length
        self.dklen = dklen
        self._maxmem = maxmem

    @property
    def algorithm(self) -> str:
        return "scrypt"

    def _derive(self, raw: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            raw.encode("utf-8"),
            salt=salt,
            n=self.n,
            r=self.r,
            p=self.p,
            dklen=self.dklen,
            maxmem=self._maxmem,
        )

    def hash(self, raw: str) -> str:
        salt = os.urandom(self.salt_length)
        derived = self._derive(raw, salt)
        return f"$scrypt$n={self.n}$r={self.r}$p={self.p}${_b64encode(salt)}${_b64encode(derived)}"

    def verify(self, raw: str, encoded: str) -> bool:
        if not isinstance(encoded, str):
            # Fail safe on corrupt records instead of raising AttributeError.
            return False
        try:
            scheme, n_part, r_part, p_part, salt_b64, hash_b64 = encoded.split("$")[1:]
            if scheme != "scrypt":
                return False
            # Canonical parameter syntax only: the key name must match and
            # the value must be plain digits (no sign, whitespace, "_"
            # separators or a second "=").
            matches = [
                pattern.fullmatch(part)
                for pattern, part in zip(_SCRYPT_PARAM_RES, (n_part, r_part, p_part), strict=True)
            ]
            if any(m is None for m in matches):
                return False
            n, r, p = (int(m.group(1)) for m in matches if m is not None)
            # Parameters matching this hasher's own configuration are always
            # allowed (mirrors Argon2Hasher): a key issued by *this* hasher
            # must verify no matter what the generic bounds are. Parameters
            # from a *stored* (potentially crafted) hash are only trusted
            # within sane bounds — a crafted record must not force absurd
            # KDF memory (hard-capped by maxmem) or per-parameter work.
            own_config = n == self.n and r == self.r and p == self.p
            if not own_config and not (
                2 <= n <= _SCRYPT_MAX_N and 1 <= r <= _SCRYPT_MAX_R and 1 <= p <= _SCRYPT_MAX_P
            ):
                return False
            # Per-parameter bounds and maxmem bound *memory*, not *CPU*:
            # p multiplies CPU without multiplying memory. Bound the total
            # work relative to this deployment's own profile, mirroring the
            # Argon2id total-work cap. The hasher's exact own configuration
            # is always allowed so heavy deployments keep verifying, and the
            # default profile's work is the floor so keys issued at the
            # documented default keep verifying on cheaper deployments.
            work_budget = max(
                _SCRYPT_MAX_WORK_FACTOR * self.n * self.r * self.p, _SCRYPT_DEFAULT_WORK
            )
            if not own_config and n * r * p > work_budget:
                return False
            salt = _b64decode(salt_b64)
            expected = _b64decode(hash_b64)
            if not (
                _MIN_DIGEST_LENGTH <= len(expected) <= _MAX_DIGEST_LENGTH
                and 1 <= len(salt) <= _MAX_SALT_LENGTH
            ):
                return False
        except (ValueError, IndexError):
            return False
        try:
            derived = hashlib.scrypt(
                raw.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(expected),
                maxmem=self._maxmem,
            )
        except ValueError:
            return False
        return hmac.compare_digest(derived, expected)


class Argon2Hasher:
    """Argon2id hasher using ``argon2-cffi`` (optional dependency; install
    the ``argon2`` extra or ``pip install argon2-cffi`` directly).

    Parameters mirror the argon2 low-level API. Defaults follow the
    RFC 9106 recommended first-choice: Argon2id, 64 MiB, t=3, p=1.

    Raises:
        ConfigurationError: If ``argon2-cffi`` is not installed or
            parameters are invalid.
    """

    def __init__(
        self,
        *,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 1,
        salt_length: int = 16,
        hash_length: int = 32,
    ) -> None:
        try:
            from argon2 import Type
            from argon2.exceptions import HashingError
            from argon2.low_level import hash_secret_raw
        except ModuleNotFoundError as exc:  # pragma: no cover - exercised via importorskip
            raise ConfigurationError(
                "Argon2Hasher requires the optional dependency argon2-cffi; "
                "install it with: pip install argon2-cffi"
            ) from exc
        for name, value in (
            ("time_cost", time_cost),
            ("memory_cost", memory_cost),
            ("parallelism", parallelism),
            ("salt_length", salt_length),
            ("hash_length", hash_length),
        ):
            _require_int(name, value)
        if time_cost < 1 or parallelism < 1:
            raise ConfigurationError("argon2 time_cost and parallelism must be >= 1")
        if memory_cost < 8:
            raise ConfigurationError("argon2 memory_cost must be >= 8 KiB")
        if salt_length < 8:
            raise ConfigurationError("salt_length must be >= 8 bytes")
        if salt_length > _MAX_SALT_LENGTH:
            raise ConfigurationError(
                f"salt_length must be <= {_MAX_SALT_LENGTH} bytes (got {salt_length})"
            )
        if hash_length < _MIN_DIGEST_LENGTH:
            raise ConfigurationError(f"hash_length must be >= {_MIN_DIGEST_LENGTH} bytes")
        if hash_length > _MAX_DIGEST_LENGTH:
            raise ConfigurationError(
                f"hash_length must be <= {_MAX_DIGEST_LENGTH} bytes (got {hash_length})"
            )
        if memory_cost < 8 * parallelism:
            # argon2 rejects this combination only when hashing; fail at
            # construction instead so misconfiguration surfaces early.
            raise ConfigurationError(
                f"argon2 memory_cost must be >= 8 * parallelism "
                f"({8 * parallelism} KiB for parallelism={parallelism})"
            )
        # Construction bounds mirror the sanity bounds verify() enforces on
        # *stored* hashes (see _ARGON2_MAX_*). Without them a hasher can be
        # configured to issue keys whose stored parameters verification then
        # rejects outright — keys that hash fine but never verify (the same
        # fixed for scrypt). Parameters equal to this hasher's
        # own configuration are always accepted at verification time, so any
        # in-bounds configuration keeps working after upgrades/downgrades.
        if time_cost > _ARGON2_MAX_T:
            raise ConfigurationError(
                f"argon2 time_cost must be <= {_ARGON2_MAX_T} so issued keys "
                f"stay verifiable (got {time_cost})"
            )
        if memory_cost > _ARGON2_MAX_M:
            raise ConfigurationError(
                f"argon2 memory_cost must be <= {_ARGON2_MAX_M} KiB so issued "
                f"keys stay verifiable (got {memory_cost})"
            )
        if parallelism > _ARGON2_MAX_P:
            raise ConfigurationError(
                f"argon2 parallelism must be <= {_ARGON2_MAX_P} so issued keys "
                f"stay verifiable (got {parallelism})"
            )
        self.time_cost = time_cost
        self.memory_cost = memory_cost
        self.parallelism = parallelism
        self.salt_length = salt_length
        self.hash_length = hash_length
        self._type = Type
        self._hash_secret_raw = hash_secret_raw
        # argon2-cffi raises its own exception type (not ValueError) when
        # stored hash parameters are invalid; verify() must catch it too.
        self._hashing_error: type[Exception] = HashingError

    @property
    def algorithm(self) -> str:
        return "argon2id"

    def hash(self, raw: str) -> str:
        salt = os.urandom(self.salt_length)
        derived = self._hash_secret_raw(
            secret=raw.encode("utf-8"),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_length,
            type=self._type.ID,
        )
        return (
            f"$argon2id$v=19$m={self.memory_cost},t={self.time_cost},p={self.parallelism}"
            f"${_b64encode(salt)}${_b64encode(derived)}"
        )

    def verify(self, raw: str, encoded: str) -> bool:
        if not isinstance(encoded, str):
            # Fail safe on corrupt records instead of raising AttributeError.
            return False
        try:
            scheme, version, params_part, salt_b64, hash_b64 = encoded.split("$")[1:]
            if scheme != "argon2id" or version != "v=19":
                return False
            # Exactly the three canonical parameters, each appearing once,
            # digits-only. Duplicate keys previously let a later "m=8"
            # silently override an earlier "m=65536".
            items = params_part.split(",")
            parsed_params = [_ARGON2_PARAM_RE.fullmatch(item) for item in items]
            if len(items) != 3 or any(m is None for m in parsed_params):
                return False
            params = {m.group(1): int(m.group(2)) for m in parsed_params if m is not None}
            if len(params) != 3:
                return False
            # Parameters matching this hasher's own configuration are always
            # allowed: a key issued by *this* hasher must verify no matter
            # what the generic bounds are (mirrors ScryptHasher). Parameters
            # from a *stored* (potentially crafted) hash are only trusted
            # within the sanity bounds below, and — beyond them — within the
            # total-work envelope: a crafted record combining a large pass
            # count with a large memory cost must not force a multi-minute,
            # 1 GiB KDF run per verification.
            own_config = (
                params.get("t", 0) == self.time_cost
                and params.get("m", 0) == self.memory_cost
                and params.get("p", 0) == self.parallelism
            )
            if not own_config and not (
                1 <= params.get("t", 0) <= _ARGON2_MAX_T
                and 8 <= params.get("m", 0) <= _ARGON2_MAX_M
                and 1 <= params.get("p", 0) <= _ARGON2_MAX_P
            ):
                return False
            salt = _b64decode(salt_b64)
            expected = _b64decode(hash_b64)
            if not (
                _MIN_DIGEST_LENGTH <= len(expected) <= _MAX_DIGEST_LENGTH
                and 1 <= len(salt) <= _MAX_SALT_LENGTH
            ):
                return False
            if not own_config and (
                params["t"] > _ARGON2_MAX_T_STRICT
                or params["t"] * params["m"] > _ARGON2_MAX_WORK
                or params["m"] > _ARGON2_STORED_MAX_M
            ):
                return False
        except (ValueError, IndexError):
            return False
        try:
            derived = self._hash_secret_raw(
                secret=raw.encode("utf-8"),
                salt=salt,
                time_cost=params["t"],
                memory_cost=params["m"],
                parallelism=params["p"],
                hash_len=len(expected),
                type=self._type.ID,
            )
        except (KeyError, ValueError, self._hashing_error):
            return False
        return hmac.compare_digest(derived, expected)
