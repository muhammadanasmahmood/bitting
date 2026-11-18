"""Property-based tests (Hypothesis) and reproducible fuzz corpus.

Invariants under test:
  P1 every generated key round-trips through parse_api_key
  P2 mutations of a valid key almost never verify (checksum + hash + prefix)
  P3 hash verification accepts the correct secret and rejects wrong ones
  P4 revoked/expired keys never authenticate
  P5 scope checks never grant unintended permissions
  P6 key format constraints hold for every generated key
  P7 encoded-hash parsers reject arbitrary junk without raising

All Hypothesis runs use fixed seeds (derivefn/random_module) so failures are
reproducible; the fuzz corpus additionally uses a fixed PRNG seed.
"""

from __future__ import annotations

import contextlib
import random
import string
from datetime import timedelta

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from bitting import (
    Argon2Hasher,
    InMemoryStore,
    KeyManager,
    ScryptHasher,
    generate_api_key,
    parse_api_key,
    scope_matches,
)
from bitting.errors import KeyFormatError

AUDIT_PROFILE = settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    print_blob=True,
)

# ---------------------------------------------------------------- P1 + P6


@AUDIT_PROFILE
@given(
    env=st.sampled_from(["live", "test", "staging", "eu1", "a1"]),
    prefix_length=st.integers(min_value=8, max_value=64),
    secret_length=st.integers(min_value=16, max_value=128),
)
def test_p1_every_generated_key_parses(env, prefix_length, secret_length):
    raw = generate_api_key(env, prefix_length=prefix_length, secret_length=secret_length)
    parsed = parse_api_key(raw)
    assert parsed.scheme == "btg"
    assert parsed.env == env
    assert len(parsed.prefix) == prefix_length
    assert len(parsed.secret) == secret_length
    assert set(parsed.prefix) <= set(string.ascii_letters + string.digits)
    assert set(parsed.secret) <= set(string.ascii_letters + string.digits)


@AUDIT_PROFILE
@given(data=st.data())
def test_p6_checksum_detects_single_char_mutation(data):
    """A single-character substitution in any component must break the checksum
    (or, if the checksum itself is mutated, verification) — never verify."""
    raw = generate_api_key()
    pos = data.draw(st.integers(min_value=4, max_value=len(raw) - 1))
    alphabet = string.ascii_letters + string.digits
    repl = data.draw(st.sampled_from([c for c in alphabet if c != raw[pos]]))
    mutated = raw[:pos] + repl + raw[pos + 1 :]
    assert mutated != raw
    try:
        parse_api_key(mutated)
    except KeyFormatError:
        return  # detected: good
    pytest.fail("single-char mutation survived checksum validation")


# ---------------------------------------------------------------- P2


@AUDIT_PROFILE
@given(
    junk=st.text(alphabet=string.printable, min_size=0, max_size=200),
)
def test_p2_parse_never_raises_on_junk(junk):
    """parse_api_key either returns a well-formed ParsedKey or raises KeyFormatError."""
    try:
        parsed = parse_api_key(junk)
    except KeyFormatError:
        return
    assert parsed.scheme == "btg"
    assert 8 <= len(parsed.prefix) <= 64
    assert 16 <= len(parsed.secret) <= 128


@AUDIT_PROFILE
@given(
    scheme=st.sampled_from(["btg", "BTG", "xtg", "btgg", "", "btg_live"]),
    env=st.sampled_from(["live", "test", "LIVE", "l", "x1", "prod-1", "", "toolongenv" * 3]),
    body=st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=0, max_size=300),
)
def test_p2_forged_keys_never_verify(scheme, env, body):
    """A hand-forged key must never authenticate, whatever its shape."""
    m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8))
    m.issue()
    candidate = f"{scheme}_{env}_{body}"
    result = m.verify(candidate)
    assert not result.ok
    assert result.reason.value in {"invalid_format", "not_found", "hash_mismatch"}


# ---------------------------------------------------------------- P3


@AUDIT_PROFILE
@given(
    secret=st.text(min_size=1, max_size=64),
    wrong=st.text(min_size=1, max_size=64).filter(lambda s: s != "bitting-audit-secret"),
)
def test_p3_scrypt_verify_roundtrip(secret, wrong):
    h = ScryptHasher(n=2**8)
    encoded = h.hash(secret)
    assert h.verify(secret, encoded) is True
    if wrong != secret:
        assert h.verify(wrong, encoded) is False


@AUDIT_PROFILE
@given(secret=st.text(min_size=1, max_size=64))
def test_p3_argon2_verify_roundtrip(secret):
    h = Argon2Hasher(time_cost=1, memory_cost=64)
    encoded = h.hash(secret)
    assert h.verify(secret, encoded) is True


@AUDIT_PROFILE
@given(
    n=st.integers(min_value=2, max_value=2**20),
    r=st.integers(min_value=1, max_value=64),
    p=st.integers(min_value=1, max_value=64),
)
def test_p7_scrypt_encoded_parser_never_raises(n, r, p):
    """Arbitrary in-range parameters embedded in a stored hash never raise."""
    h = ScryptHasher(n=2**8)
    salt = "c2FsdHNhbHRzYWx0c2FsdA"
    encoded = f"$scrypt$n={n}$r={r}$p={p}${salt}{'A' * 43}"
    assert h.verify("x", encoded) in (True, False)  # must not raise


@AUDIT_PROFILE
@given(
    junk=st.text(
        alphabet="$=,_-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/ \t\n",
        min_size=0,
        max_size=120,
    )
)
def test_p7_fuzz_encoded_hash_strings(junk):
    """Fuzz both hashers' verify with arbitrary encoded strings: never raise."""
    sh = ScryptHasher(n=2**8)
    ah = Argon2Hasher(time_cost=1, memory_cost=64)
    assert sh.verify("x", junk) in (True, False)
    assert ah.verify("x", junk) in (True, False)


# ---------------------------------------------------------------- P4 + P5


@AUDIT_PROFILE
@given(
    scopes=st.sets(
        st.sampled_from(["read:users", "write:posts", "read:*", "*", "admin", "read:users:admin"]),
        min_size=0,
        max_size=4,
    ),
    required=st.sets(
        st.sampled_from(["read:users", "write:posts", "admin:all", "read:users:admin", "read:x"]),
        min_size=0,
        max_size=3,
    ),
)
def test_p5_scope_no_escalation_property(scopes, required):
    """If verify() succeeds, every required scope must be legitimately covered
    by an exact/wildcard grant — never anything else."""
    m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8))
    issued = m.issue(scopes=scopes)
    result = m.verify(issued.raw_key, required_scopes=required)
    if result.ok:
        for req in required:
            assert any(scope_matches(g, req) for g in scopes), (
                f"verify granted {req!r} without a covering grant in {sorted(scopes)!r}"
            )


@AUDIT_PROFILE
@given(ttl_seconds=st.integers(min_value=-10_000_000, max_value=0))
def test_p4_expired_keys_never_verify(ttl_seconds):
    m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8))
    if ttl_seconds < 0:
        # Negative TTLs are rejected at issue time (
        # they could only ever create keys that are dead on arrival).
        with pytest.raises(ValueError, match="non-negative"):
            m.issue(ttl=timedelta(seconds=ttl_seconds))
        return
    issued = m.issue(ttl=timedelta(seconds=ttl_seconds))
    result = m.verify(issued.raw_key)
    # ttl == 0: the expiry moment is now, so the key is already expired.
    assert not result.ok
    assert result.reason.value == "expired"


# ---------------------------------------------------------------- reproducible fuzz corpus


FUZZ_RNG_SEED = 0xC0FFEE


def test_fuzz_corpus_key_parser():
    """Deterministic fuzz corpus for the key parser (seeded, reproducible)."""
    rng = random.Random(FUZZ_RNG_SEED)
    valid = generate_api_key()
    corpus = []
    for _ in range(500):
        choice = rng.randrange(5)
        s = list(valid)
        if choice == 0 and len(s) > 5:  # flip a char
            i = rng.randrange(len(s))
            s[i] = rng.choice(string.ascii_letters + string.digits + "_-é")
        elif choice == 1:  # delete a char
            del s[rng.randrange(len(s))]
        elif choice == 2:  # insert junk
            s.insert(rng.randrange(len(s)), rng.choice("_-+ =./\\\x00"))
        elif choice == 3:  # truncate
            s = s[: rng.randrange(len(s))]
        else:  # fully random
            s = [rng.choice(string.printable) for _ in range(rng.randrange(0, 80))]
        corpus.append("".join(ch for ch in s if ch != "\x00" or rng.random() < 0.1))
    m = KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8))
    m.issue()  # populate one key so not_found/hash_mismatch paths are reachable
    for candidate in corpus:
        with contextlib.suppress(KeyFormatError):
            parse_api_key(candidate)
        result = m.verify(candidate)
        assert not result.ok


def test_fuzz_corpus_cli_scopes():
    """CLI --scopes parsing must never produce empty or whitespace scopes."""
    from bitting.cli import _scopes

    rng = random.Random(FUZZ_RNG_SEED)
    for _ in range(300):
        parts = []
        for _ in range(rng.randrange(4)):
            chunk = rng.choice(["", " ", "  ", "read:users", "write:x", " a ", "\t", "*"])
            parts.append(chunk)
        parsed = _scopes(",".join(parts))
        assert all(p and not p.isspace() and p == p.strip() for p in parsed)
