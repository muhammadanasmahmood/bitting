"""Shared fixtures: a fast scrypt hasher and managers on in-memory stores."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone

import pytest

from bitting import InMemoryStore, KeyManager, ScryptHasher


class FrozenClock:
    """A clock the tests can advance deterministically."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs) -> None:
        from datetime import timedelta

        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def fast_hasher() -> ScryptHasher:
    # Cheap parameters keep the suite fast; parameter handling is covered
    # separately in test_hashing.py, including one default-cost test.
    return ScryptHasher(n=2**8, r=1, p=1, salt_length=8, dklen=16)


@pytest.fixture
def manager(fast_hasher: ScryptHasher, clock: FrozenClock) -> KeyManager:
    return KeyManager(InMemoryStore(), hasher=fast_hasher, now_fn=clock)


@pytest.fixture
def sqlite_manager(fast_hasher: ScryptHasher, clock: FrozenClock, tmp_path) -> Iterator[KeyManager]:
    from bitting import SQLiteStore

    store = SQLiteStore(tmp_path / "keys.db")
    yield KeyManager(store, hasher=fast_hasher, now_fn=clock)
    store.close()
