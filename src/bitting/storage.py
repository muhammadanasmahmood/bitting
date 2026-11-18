"""Key storage: a protocol plus in-memory and SQLite (WAL) implementations.

The store contract is intentionally small so applications can adapt any
database to bitting: implement :class:`KeyStore` with five methods and
pass it to :class:`bitting.KeyManager`.

Concurrency: :class:`SQLiteStore` serializes writes with a process-wide
lock over a WAL-mode connection, which is safe for multi-threaded
servers within one process. For multi-process deployments, point every
process at the same database file; SQLite's file locking coordinates
them (see README, "Deploying with SQLite").
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import DuplicateKeyError, StorageError
from .models import AuditEvent, KeyRecord
from .timeutil import from_iso, to_iso

__all__ = ["InMemoryStore", "KeyStore", "SQLiteStore"]

#: ``PRAGMA journal_mode=WAL`` requires an exclusive lock, and SQLite
#: returns SQLITE_BUSY for that statement *without* invoking the busy
#: handler (the connection's ``timeout=`` does not apply). When several
#: processes open the same fresh database simultaneously (multi-worker
#: service boot), each retry cycle is ~50 ms and the whole switch is
#: retried for ~2 s before giving up with the documented StorageError.
_WAL_RETRY_ATTEMPTS = 40
_WAL_RETRY_DELAY = 0.05

#: SQLite integers are signed 64-bit; bind parameters outside that range
#: raise OverflowError from the driver. Used to validate ``limit`` before
#: it reaches SQL (a Python-only store has no such bound, but the store
#: contract keeps both implementations' validation identical).
_SQLITE_MAX_INT = 2**63 - 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    prefix            TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    hash              TEXT NOT NULL,
    algorithm         TEXT NOT NULL,
    scopes            TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    expires_at        TEXT,
    revoked_at        TEXT,
    rotated_at        TEXT,
    grace_until       TEXT,
    last_verified_at  TEXT,
    metadata          TEXT NOT NULL DEFAULT '{}',
    supersedes        TEXT
);
CREATE INDEX IF NOT EXISTS idx_keys_key_id ON keys (key_id);
CREATE TABLE IF NOT EXISTS audit_events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    kind     TEXT NOT NULL,
    prefix   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_prefix ON audit_events (prefix);
"""


class KeyStore:
    """The storage contract required by :class:`bitting.KeyManager`.

    Implementations must be safe for concurrent use from multiple
    threads within one process.
    """

    def save(self, record: KeyRecord) -> None:
        """Insert or update a key record keyed by its prefix."""
        raise NotImplementedError

    def find_by_prefix(self, prefix: str) -> KeyRecord | None:
        """Return the record with this prefix, or None."""
        raise NotImplementedError

    def delete(self, prefix: str) -> bool:
        """Delete the record with this prefix. Return True if it existed."""
        raise NotImplementedError

    def list_keys(self) -> list[KeyRecord]:
        """Return all key records (unspecified order)."""
        raise NotImplementedError

    def append_event(self, event: AuditEvent) -> None:
        """Persist an audit event (best-effort; stores may no-op)."""
        raise NotImplementedError

    def list_events(self, *, limit: int = 100) -> list[AuditEvent]:
        """Return the most recent audit events, newest first."""
        raise NotImplementedError

    def mark_rotated(self, prefix: str, *, rotated_at: datetime, grace_until: datetime) -> bool:
        """Claim the active→rotated transition for a key.

        Returns True only when this call performed the transition;
        False when the key is missing, already rotated, or revoked.
        Concurrent callers race on a single claim: exactly one wins.

        The default implementation is a non-atomic read-check-write.
        Stores that serve multiple threads or processes should override
        it with an atomic conditional update (both built-in stores do).
        """
        record = self.find_by_prefix(prefix)
        if record is None or record.rotated_at is not None or record.revoked_at is not None:
            return False
        record.rotated_at = rotated_at
        record.grace_until = grace_until
        self.save(record)
        return True

    def mark_revoked(self, prefix: str, *, at: datetime) -> bool:
        """Claim the active→revoked transition for a key.

        Returns True only when this call performed the transition; False
        when the key is missing or already revoked (revocation is
        idempotent: the first ``revoked_at`` timestamp is authoritative).
        Concurrent callers race on a single claim: exactly one wins.

        Implementations must alter **only** ``revoked_at`` — never other
        lifecycle fields. A full-record write here could erase a rotation
        claimed concurrently by :meth:`mark_rotated` (race:
        revoke-vs-rotate lost update).

        The default implementation is a non-atomic read-check-write.
        Stores that serve multiple threads or processes should override
        it with an atomic conditional update (both built-in stores do).
        """
        record = self.find_by_prefix(prefix)
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = at
        self.save(record)
        return True

    def mark_verified(self, prefix: str, *, at: datetime) -> bool:
        """Record the timestamp of a successful verification.

        Implementations must alter **only** ``last_verified_at`` — never
        lifecycle fields (``revoked_at``, ``rotated_at``, ``grace_until``,
        ...). Verification runs concurrently with revocation and
        rotation; a full-record write here could resurrect a key that an
        operator just revoked or rotated.

        Returns True when a record was found and updated. The default
        implementation is a non-atomic read-modify-write limited to
        ``last_verified_at``; stores that serve multiple threads or
        processes should override it with a targeted single-column
        update (both built-in stores do).
        """
        record = self.find_by_prefix(prefix)
        if record is None:
            return False
        record.last_verified_at = at
        self.save(record)
        return True

    def delete_events_before(self, cutoff: datetime) -> int:
        """Delete audit events strictly older than ``cutoff``.

        Returns the number of events removed. Used to bound audit-log
        growth (see :meth:`bitting.KeyManager.prune_events`).
        """
        raise NotImplementedError("this store does not support audit pruning")

    def close(self) -> None:
        """Release resources, if any."""


def _copy_record(record: KeyRecord) -> KeyRecord:
    """Return an isolated copy so stores never hand out live records.

    ``metadata`` is deep-copied: a shallow ``dict()`` would still alias
    nested containers, letting callers mutate stored state through a
    fetched record (or inject aliased state on save).
    """
    return replace(record, metadata=deepcopy(record.metadata))


class InMemoryStore(KeyStore):
    """A thread-safe, in-memory store. Keys vanish when the process exits.

    Records are copied on the way in and out, so mutating a fetched
    record never changes what the store holds (matching
    :class:`SQLiteStore`, which builds fresh objects per read).

    Useful for tests, prototypes, and short-lived services.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: dict[str, KeyRecord] = {}
        self._events: list[AuditEvent] = []

    def save(self, record: KeyRecord) -> None:
        with self._lock:
            self._keys[record.prefix] = _copy_record(record)

    def find_by_prefix(self, prefix: str) -> KeyRecord | None:
        with self._lock:
            record = self._keys.get(prefix)
            return _copy_record(record) if record is not None else None

    def delete(self, prefix: str) -> bool:
        with self._lock:
            return self._keys.pop(prefix, None) is not None

    def list_keys(self) -> list[KeyRecord]:
        with self._lock:
            return [_copy_record(record) for record in self._keys.values()]

    def append_event(self, event: AuditEvent) -> None:
        with self._lock:
            # Isolate the detail mapping: neither the emitter nor a later
            # list_events() caller may mutate stored audit history.
            self._events.append(replace(event, detail=deepcopy(event.detail)))

    def list_events(self, *, limit: int = 100) -> list[AuditEvent]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > _SQLITE_MAX_INT:
            # Keep validation identical across both stores (see the
            # SQLiteStore note): a nonsensical limit is a caller error.
            raise ValueError(f"limit must be <= {_SQLITE_MAX_INT}")
        with self._lock:
            return [
                replace(event, detail=deepcopy(event.detail))
                for event in reversed(self._events[-limit:])
            ]

    def mark_rotated(self, prefix: str, *, rotated_at: datetime, grace_until: datetime) -> bool:
        # Atomic under the store lock: exactly one concurrent caller
        # performs the active→rotated transition.
        with self._lock:
            record = self._keys.get(prefix)
            if record is None or record.rotated_at is not None or record.revoked_at is not None:
                return False
            self._keys[prefix] = replace(
                record,
                rotated_at=rotated_at,
                grace_until=grace_until,
                metadata=deepcopy(record.metadata),
            )
            return True

    def mark_verified(self, prefix: str, *, at: datetime) -> bool:
        # Atomic under the store lock: a targeted field replacement that
        # can never undo a concurrent revoke/rotate on the same key.
        with self._lock:
            record = self._keys.get(prefix)
            if record is None:
                return False
            self._keys[prefix] = replace(
                record,
                last_verified_at=at,
                # deepcopy, matching _copy_record/mark_rotated/mark_revoked:
                # dict() would keep nested containers aliased to the
                # previously stored record.
                metadata=deepcopy(record.metadata),
            )
            return True

    def mark_revoked(self, prefix: str, *, at: datetime) -> bool:
        # Atomic under the store lock: exactly one concurrent caller
        # performs the active→revoked transition, and no other lifecycle
        # field is touched (a concurrent rotation survives untouched).
        with self._lock:
            record = self._keys.get(prefix)
            if record is None or record.revoked_at is not None:
                return False
            self._keys[prefix] = replace(
                record,
                revoked_at=at,
                metadata=deepcopy(record.metadata),
            )
            return True

    def delete_events_before(self, cutoff: datetime) -> int:
        with self._lock:
            remaining = [event for event in self._events if event.at >= cutoff]
            removed = len(self._events) - len(remaining)
            self._events = remaining
            return removed


def _record_to_row(record: KeyRecord) -> tuple[Any, ...]:
    def _dt(value: datetime | None) -> str | None:
        from .timeutil import to_iso

        return to_iso(value) if value is not None else None

    return (
        record.prefix,
        record.key_id,
        record.hash,
        record.algorithm,
        json.dumps(sorted(record.scopes)),
        _dt(record.created_at),
        record.description,
        _dt(record.expires_at),
        _dt(record.revoked_at),
        _dt(record.rotated_at),
        _dt(record.grace_until),
        _dt(record.last_verified_at),
        json.dumps(record.metadata),
        record.supersedes,
    )


def _row_to_record(row: sqlite3.Row) -> KeyRecord:
    try:
        scopes = json.loads(row["scopes"])
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise ValueError("scopes column must be a JSON array of strings")
        metadata = json.loads(row["metadata"])
        if not isinstance(metadata, dict):
            raise ValueError("metadata column must be a JSON object")
        return KeyRecord(
            prefix=row["prefix"],
            key_id=row["key_id"],
            hash=row["hash"],
            algorithm=row["algorithm"],
            scopes=frozenset(scopes),
            created_at=from_iso(row["created_at"]),
            description=row["description"],
            expires_at=from_iso(row["expires_at"]) if row["expires_at"] else None,
            revoked_at=from_iso(row["revoked_at"]) if row["revoked_at"] else None,
            rotated_at=from_iso(row["rotated_at"]) if row["rotated_at"] else None,
            grace_until=from_iso(row["grace_until"]) if row["grace_until"] else None,
            last_verified_at=from_iso(row["last_verified_at"]) if row["last_verified_at"] else None,
            metadata=metadata,
            supersedes=row["supersedes"],
        )
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        # A corrupted or crafted row must surface as a predictable
        # StorageError, never a raw JSON/ISO parsing exception. IndexError
        # covers rows written by a legacy schema whose column set differs
        # (e.g. a missing ``last_verified_at``): ``sqlite3.Row`` raises
        # "No item with that key" when a mapped column is absent.
        # The prefix itself may be the missing column (or unreadable), so
        # it must not be used to build the error message.
        try:
            prefix_hint = f" for prefix {row['prefix']!r}"
        except (IndexError, KeyError):  # pragma: no cover - doubly-corrupt row
            prefix_hint = ""
        raise StorageError(f"corrupted key record{prefix_hint}: {exc}") from exc


class SQLiteStore(KeyStore):
    """A durable store in a single SQLite file with WAL mode.

    Args:
        path: File path for the database. Parent directories are created.
            The special value ``":memory:"`` creates a private in-memory
            database (use :class:`InMemoryStore` instead for tests).
        schema_check: When True (default) the store refuses to open a
            database whose ``user_version`` is newer than the one it
            supports, to avoid silently misreading future schemas.

    Raises:
        StorageError: On any failure to open or initialize the database.
    """

    _USER_VERSION = 1

    def _enable_wal(self) -> None:
        """Switch the database to WAL mode, tolerating concurrent first-open.

        The journal-mode change needs an exclusive lock; if another process
        is mid-open (or mid-schema-creation) on the same file, SQLite can
        raise ``SQLITE_BUSY`` for this pragma without honoring the busy
        timeout. Once *any* opener completes the switch, WAL is persistent
        in the database header and every other opener converges, so a
        short bounded retry resolves the contention instead of crashing
        the boot of N workers against one fresh file.
        """
        for attempt in range(_WAL_RETRY_ATTEMPTS):
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt + 1 >= _WAL_RETRY_ATTEMPTS:
                    raise
                time.sleep(_WAL_RETRY_DELAY)

    def __init__(self, path: str | Path, *, schema_check: bool = True) -> None:
        raw_path = str(path)
        # Expand "~" once, for the connection path *and* the parent-directory
        # creation below. Previously only the parent was expanded, so
        # SQLiteStore("~/keys.db") created directories under $HOME and then
        # failed to open the literal "~/keys.db" relative to the cwd.
        self._path = raw_path if raw_path == ":memory:" else os.path.expanduser(raw_path)
        self._lock = threading.RLock()
        try:
            file_backed = self._path != ":memory:"
            if file_backed:
                existed = Path(self._path).exists()
                parent = Path(self._path).expanduser().resolve().parent
                parent.mkdir(parents=True, exist_ok=True)
            else:
                existed = False
            self._conn = sqlite3.connect(
                self._path,
                check_same_thread=False,
                isolation_level=None,  # autocommit; we control transactions
                timeout=30.0,
            )
            if file_backed and not existed:
                # The file holds credential hashes, prefixes, and metadata:
                # create it owner-only (0600) instead of the umask default
                # (typically 0644, world-readable). Best-effort: exotic
                # filesystems may reject chmod, and existing files keep
                # their deliberate permissions untouched.
                with suppress(OSError):
                    os.chmod(self._path, 0o600)
            self._conn.row_factory = sqlite3.Row
            # PRAGMAs must run outside any transaction (SQLite refuses to
            # change the journal mode transactionally).
            self._enable_wal()
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            # executescript() manages its own transaction boundaries.
            self._conn.executescript(_SCHEMA)
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._conn.execute(f"PRAGMA user_version={self._USER_VERSION}")
            elif schema_check and version > self._USER_VERSION:
                raise StorageError(
                    f"database schema version {version} is newer than supported "
                    f"version {self._USER_VERSION}; upgrade the bitting package"
                )
        except StorageError:
            raise
        except sqlite3.Error as exc:
            raise StorageError(f"failed to open SQLite store at {self._path}: {exc}") from exc

    @property
    def path(self) -> str:
        return self._path

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def save(self, record: KeyRecord) -> None:
        try:
            with self._transaction():
                existing = self._conn.execute(
                    "SELECT 1 FROM keys WHERE prefix = ?", (record.prefix,)
                ).fetchone()
                if existing:
                    row = _record_to_row(record)
                    self._conn.execute(
                        """UPDATE keys SET key_id=?, hash=?, algorithm=?, scopes=?,
                           created_at=?, description=?, expires_at=?, revoked_at=?,
                           rotated_at=?, grace_until=?, last_verified_at=?, metadata=?,
                           supersedes=? WHERE prefix=?""",
                        (*row[1:], record.prefix),
                    )
                else:
                    self._conn.execute(
                        """INSERT INTO keys (prefix, key_id, hash, algorithm, scopes,
                           created_at, description, expires_at, revoked_at, rotated_at,
                           grace_until, last_verified_at, metadata, supersedes)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        _record_to_row(record),
                    )
        except sqlite3.IntegrityError as exc:
            raise DuplicateKeyError(f"prefix {record.prefix!r} already exists") from exc
        except sqlite3.Error as exc:
            raise StorageError(f"failed to save key {record.prefix!r}: {exc}") from exc

    def find_by_prefix(self, prefix: str) -> KeyRecord | None:
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT * FROM keys WHERE prefix = ?", (prefix,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to look up prefix {prefix!r}: {exc}") from exc
        return _row_to_record(row) if row else None

    def delete(self, prefix: str) -> bool:
        try:
            with self._transaction():
                cursor = self._conn.execute("DELETE FROM keys WHERE prefix = ?", (prefix,))
        except sqlite3.Error as exc:
            raise StorageError(f"failed to delete key {prefix!r}: {exc}") from exc
        return cursor.rowcount > 0

    def list_keys(self) -> list[KeyRecord]:
        try:
            with self._lock:
                rows = self._conn.execute("SELECT * FROM keys ORDER BY created_at").fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to list keys: {exc}") from exc
        return [_row_to_record(row) for row in rows]

    def append_event(self, event: AuditEvent) -> None:
        try:
            with self._transaction():
                self._conn.execute(
                    "INSERT INTO audit_events (at, kind, prefix, detail) VALUES (?,?,?,?)",
                    (
                        to_iso(event.at),
                        event.kind.value,
                        event.prefix,
                        json.dumps(event.detail, default=str),
                    ),
                )
        except sqlite3.Error as exc:  # pragma: no cover - audit is best-effort
            raise StorageError(f"failed to append audit event: {exc}") from exc

    def list_events(self, *, limit: int = 100) -> list[AuditEvent]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > _SQLITE_MAX_INT:
            # SQLite integers are signed 64-bit; an out-of-range Python
            # int previously leaked a raw OverflowError from the driver.
            raise ValueError(f"limit must be <= {_SQLITE_MAX_INT}")
        try:
            with self._lock:
                rows = self._conn.execute(
                    "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        except sqlite3.Error as exc:
            raise StorageError(f"failed to list audit events: {exc}") from exc
        from .models import AuditEventKind

        try:
            return [
                AuditEvent(
                    kind=AuditEventKind(row["kind"]),
                    prefix=row["prefix"],
                    at=from_iso(row["at"]),
                    detail=json.loads(row["detail"]),
                )
                for row in rows
            ]
        except (ValueError, TypeError, KeyError) as exc:
            raise StorageError(f"corrupted audit event record: {exc}") from exc

    def mark_rotated(self, prefix: str, *, rotated_at: datetime, grace_until: datetime) -> bool:
        # A single conditional UPDATE inside BEGIN IMMEDIATE: atomic
        # across threads in this process AND across processes sharing
        # the database file (SQLite's write lock serializes them).
        try:
            with self._transaction():
                cursor = self._conn.execute(
                    "UPDATE keys SET rotated_at=?, grace_until=? "
                    "WHERE prefix=? AND rotated_at IS NULL AND revoked_at IS NULL",
                    (to_iso(rotated_at), to_iso(grace_until), prefix),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to rotate key {prefix!r}: {exc}") from exc
        return cursor.rowcount > 0

    def mark_verified(self, prefix: str, *, at: datetime) -> bool:
        # A single-column UPDATE: concurrent lifecycle transitions
        # (revoke/rotate) write their own columns and can never be
        # clobbered by this touch, across threads and processes alike.
        try:
            with self._transaction():
                cursor = self._conn.execute(
                    "UPDATE keys SET last_verified_at=? WHERE prefix=?",
                    (to_iso(at), prefix),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to touch key {prefix!r}: {exc}") from exc
        return cursor.rowcount > 0

    def mark_revoked(self, prefix: str, *, at: datetime) -> bool:
        # A single conditional UPDATE inside BEGIN IMMEDIATE: atomic
        # across threads in this process AND across processes sharing
        # the database file. Only revoked_at is written, so a rotation
        # claimed concurrently keeps its rotated_at/grace_until, and a
        # repeated revocation keeps the first (authoritative) timestamp.
        try:
            with self._transaction():
                cursor = self._conn.execute(
                    "UPDATE keys SET revoked_at=? WHERE prefix=? AND revoked_at IS NULL",
                    (to_iso(at), prefix),
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to revoke key {prefix!r}: {exc}") from exc
        return cursor.rowcount > 0

    def delete_events_before(self, cutoff: datetime) -> int:
        try:
            with self._transaction():
                cursor = self._conn.execute(
                    "DELETE FROM audit_events WHERE at < ?", (to_iso(cutoff),)
                )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to prune audit events: {exc}") from exc
        return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def new_key_id() -> str:
    """Generate a fresh opaque key identifier (uuid4 hex)."""
    return uuid.uuid4().hex
