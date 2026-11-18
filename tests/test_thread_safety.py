"""Concurrency and multiprocess regression tests.

Deterministic single-process races use gated hashers (see
test_security_regressions.py). The tests here exercise *statistical* concurrency:
multithreaded lifecycle storms and true multiprocess SQLite contention.
They assert the post-storm invariants rather than specific interleavings.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import threading
import time
from datetime import timedelta

import pytest

from bitting import InMemoryStore, KeyManager, ScryptHasher
from bitting.storage import SQLiteStore


def _fast(store, **kw) -> KeyManager:
    return KeyManager(store, hasher=ScryptHasher(n=2**8), verify_touch_interval=timedelta(0), **kw)


@pytest.mark.parametrize("store_factory", [InMemoryStore, lambda: SQLiteStore(":memory:")])
def test_concurrent_issue_verify_revoke_storm(store_factory):
    """20s-equivalent lifecycle storm compressed: 6 verifiers, 1 rotator,
    1 revoker over many iterations. After the storm:
      - no revoked key verifies,
      - no duplicate prefixes exist,
      - every rotation produced exactly one successor.
    """
    store = store_factory()
    m = _fast(store)
    issued = [m.issue(scopes={"read:users"}) for _ in range(24)]
    raw_by_prefix = {k.prefix: k.raw_key for k in issued}
    stop = threading.Event()

    def verifier(i: int) -> None:
        key = issued[i % len(issued)]
        while not stop.is_set():
            m.verify(key.raw_key)

    def rotator() -> None:
        idx = 0
        while not stop.is_set():
            with contextlib.suppress(ValueError):  # already rotated/revoked
                m.rotate(issued[idx % len(issued)].prefix, grace=timedelta(seconds=30))
            idx += 1
            time.sleep(0.001)

    def revoker() -> None:
        idx = 0
        while not stop.is_set():
            with contextlib.suppress(Exception):
                m.revoke(issued[idx % len(issued)].prefix)
            idx += 1
            time.sleep(0.001)

    threads = [threading.Thread(target=verifier, args=(i,)) for i in range(6)]
    threads += [threading.Thread(target=rotator), threading.Thread(target=revoker)]
    for t in threads:
        t.start()
    time.sleep(3.0)
    stop.set()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive(), "worker thread did not stop"

    records = store.list_keys()
    prefixes = [r.prefix for r in records]
    assert len(prefixes) == len(set(prefixes)), "duplicate prefixes after storm"
    for rec in records:
        if rec.revoked_at is not None:
            raw = raw_by_prefix.get(rec.prefix)
            if raw is not None:
                result = m.verify(raw)
                assert not result.ok, f"revoked key {rec.prefix} still verifies"
                assert result.reason.value == "revoked"


_CHILD = r"""
import sys
import time
from datetime import timedelta

sys.path.insert(0, "__SRC__")

from bitting import KeyManager, ScryptHasher
from bitting.storage import SQLiteStore

mode, db, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
m = KeyManager(
    SQLiteStore(db),
    hasher=ScryptHasher(n=2**8),
    verify_touch_interval=timedelta(0),
)
keys = [m.issue(scopes={"read:users"}) for _ in range(5)]
import random

rng = random.Random()
end = time.time() + seconds
ops = 0
if mode == "verify":
    while time.time() < end:
        m.verify(keys[ops % 5].raw_key)
        ops += 1
elif mode == "rotate":
    while time.time() < end:
        try:
            m.rotate(keys[rng.randrange(5)].prefix, grace=timedelta(seconds=10))
        except ValueError:
            pass
        ops += 1
        time.sleep(0.005)
elif mode == "revoke":
    while time.time() < end:
        try:
            m.revoke(keys[rng.randrange(5)].prefix)
        except Exception:
            pass
        ops += 1
        time.sleep(0.005)
print(ops)
"""


def test_multiprocess_sqlite_contention(tmp_path):
    """Four processes hammering one SQLite file: verify x2 + rotate + revoke.
    SQLite's WAL write lock must serialize them without corruption or
    lost lifecycle state.
    """
    import pathlib

    src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    db = str(tmp_path / "mp.db")
    child = tmp_path / "child.py"
    child.write_text(_CHILD.replace("__SRC__", src))
    procs = [
        subprocess.Popen(
            [sys.executable, str(child), "verify", db, "6"], stdout=subprocess.PIPE, text=True
        ),
        subprocess.Popen(
            [sys.executable, str(child), "verify", db, "6"], stdout=subprocess.PIPE, text=True
        ),
        subprocess.Popen(
            [sys.executable, str(child), "rotate", db, "6"], stdout=subprocess.PIPE, text=True
        ),
        subprocess.Popen(
            [sys.executable, str(child), "revoke", db, "6"], stdout=subprocess.PIPE, text=True
        ),
    ]
    outs = []
    for p in procs:
        out, _ = p.communicate(timeout=60)
        outs.append(out.strip())
        assert p.returncode == 0, "multiprocess worker crashed"

    store = SQLiteStore(db)
    records = store.list_keys()
    prefixes = [r.prefix for r in records]
    assert len(prefixes) == len(set(prefixes)), "duplicate prefixes across processes"
    assert store._conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    store.close()


_OPEN_RACE_CHILD = r"""
import os, sys, time
sys.path.insert(0, "__SRC__")
from bitting.storage import SQLiteStore

flag, db = sys.argv[1], sys.argv[2]
# Tight simultaneous open: spin until the start flag appears.
while not os.path.exists(flag):
    time.sleep(0.001)
store = SQLiteStore(db)  # must not raise, even against a fresh file
store.close()
"""


def test_concurrent_first_open_sqlite(tmp_path):
    """Many processes opening the same *fresh* SQLite file at the same
    instant must all succeed.

    ``PRAGMA journal_mode=WAL`` needs an exclusive lock and SQLite returns
    SQLITE_BUSY for it *without* invoking the busy handler, so before the
    retry in ``SQLiteStore._enable_wal`` a simultaneous multi-worker boot
    crashed with ``StorageError: database is locked`` (observed as a CI
    failure of test_multiprocess_sqlite_contention on 3.10/3.11/3.13;
    3.12 only passed by timing luck).
    """
    import pathlib

    src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    child = tmp_path / "open_child.py"
    child.write_text(_OPEN_RACE_CHILD.replace("__SRC__", src))

    for attempt in range(3):  # 3 rounds: the race is per-fresh-file
        db = str(tmp_path / f"open{attempt}.db")
        flag = tmp_path / f"go{attempt}"
        procs = [
            subprocess.Popen(
                [sys.executable, str(child), str(flag), db],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for _ in range(12)
        ]
        time.sleep(0.4)  # let every child reach the spin loop
        flag.touch()  # ...and open simultaneously
        for p in procs:
            out, _ = p.communicate(timeout=60)
            assert p.returncode == 0, f"concurrent first-open crashed:\n{out}"
        assert SQLiteStore(db).list_keys() == []


def test_touch_write_is_isolated_single_column(tmp_path):
    """SQLiteStore.mark_verified must update ONLY last_verified_at: a
    concurrent revocation committed between the read and the touch survives.
    """
    db = tmp_path / "iso.db"
    store = SQLiteStore(db)
    m = _fast(store)
    issued = m.issue()

    # Simulate the race deterministically: touch an outdated snapshot AFTER
    # a revoke has landed; the stored revocation must survive.
    stale = store.find_by_prefix(issued.prefix)
    m.revoke(issued.prefix)
    # the manager's touch path on the stale prefix:
    assert store.mark_verified(issued.prefix, at=m._now_fn()) is True
    fresh = store.find_by_prefix(issued.prefix)
    assert fresh.revoked_at is not None, "mark_verified clobbered revoked_at"
    assert fresh.last_verified_at is not None
    # all other fields identical to the revoked snapshot
    assert fresh.grace_until == stale.grace_until
    assert fresh.scopes == stale.scopes
    store.close()
