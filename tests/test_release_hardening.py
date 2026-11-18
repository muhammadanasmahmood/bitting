"""Regression tests for pre-release hardening.

Covers:
  - ParsedKey.__repr__ must never print the raw secret.
  - rotate() must reject an already-expired key instead of minting a
    successor with a grace window on a dead credential.
"""

from __future__ import annotations

import datetime as dt
from datetime import timedelta

import pytest

from bitting import InMemoryStore, KeyManager, ScryptHasher
from bitting.keys import parse_api_key

_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)


def _manager(now: dt.datetime = _NOW) -> KeyManager:
    hasher = ScryptHasher(n=2, r=8, p=1)  # cheap profile for tests
    return KeyManager(InMemoryStore(), hasher=hasher, now_fn=lambda: now)


def _at(offset: timedelta) -> KeyManager:
    """A manager over a shared store, with the clock advanced by ``offset``."""
    m = _manager()
    m.issue(ttl=timedelta(hours=1))
    return KeyManager(
        m.store,
        hasher=ScryptHasher(n=2, r=8, p=1),
        now_fn=lambda: _NOW + offset,
    )


class TestParsedKeyRedactedRepr:
    def test_repr_omits_secret(self) -> None:
        issued = _manager().issue()
        parsed = parse_api_key(issued.raw_key)
        r = repr(parsed)
        assert parsed.secret not in r
        assert "<redacted:" in r

    def test_repr_shows_safe_fields(self) -> None:
        issued = _manager().issue()
        parsed = parse_api_key(issued.raw_key)
        r = repr(parsed)
        assert parsed.prefix in r
        assert parsed.scheme in r
        assert str(len(parsed.secret)) in r


class TestRotateExpiredRejected:
    def test_rotate_expired_key_raises(self) -> None:
        m = _manager()
        issued = m.issue(ttl=timedelta(hours=1))
        m2 = KeyManager(
            m.store,
            hasher=ScryptHasher(n=2, r=8, p=1),
            now_fn=lambda: _NOW + timedelta(hours=2),
        )
        with pytest.raises(ValueError, match="expired"):
            m2.rotate(issued.prefix)

    def test_rotate_at_exact_expiry_boundary_raises(self) -> None:
        m = _manager()
        issued = m.issue(ttl=timedelta(hours=1))
        m2 = KeyManager(
            m.store,
            hasher=ScryptHasher(n=2, r=8, p=1),
            now_fn=lambda: _NOW + timedelta(hours=1),
        )
        with pytest.raises(ValueError, match="expired"):
            m2.rotate(issued.prefix)

    def test_rotate_unexpired_key_still_works(self) -> None:
        m = _manager()
        issued = m.issue(ttl=timedelta(days=30))
        successor = m.rotate(issued.prefix, grace=timedelta(hours=1))
        assert successor.raw_key
