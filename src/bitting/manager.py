"""The KeyManager: issue, verify, rotate, and revoke API keys.

This module is the orchestrator that ties together key generation
(:mod:`bitting.keys`), hashing (:mod:`bitting.hashing`), and storage
(:mod:`bitting.storage`), and emits audit events for every lifecycle
action.

Scope model
===========
Scopes are strings like ``read:users`` or ``write:posts``. A granted
scope matches a required scope when:

* they are equal, or
* the granted scope ends with ``:*`` and shares the prefix
  (``read:*`` matches ``read:users``), or
* the granted scope is the global wildcard ``*``.
"""

from __future__ import annotations

import contextlib
import json
import warnings
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta
from typing import Any

from .errors import ConfigurationError, KeyNotFoundError, StorageError
from .hashing import Hasher, ScryptHasher
from .keys import DEFAULT_ENV, ParsedKey, generate_api_key, parse_api_key, validate_env_label
from .models import (
    AuditCallback,
    AuditEvent,
    AuditEventKind,
    IssuedKey,
    KeyRecord,
    VerifyReason,
    VerifyResult,
)
from .storage import KeyStore, new_key_id
from .timeutil import utcnow

__all__ = [
    "DEFAULT_ROTATION_GRACE",
    "LEGACY_STORE_WARNING",
    "KeyManager",
    "missing_scopes",
    "scope_matches",
    "validate_scopes",
]

#: Default grace period during which a rotated key keeps working.
DEFAULT_ROTATION_GRACE = timedelta(hours=24)

#: Attempts to draw an unused prefix before giving up on issue().
_ISSUE_COLLISION_RETRIES = 8

#: Set to ``False`` to silence the legacy-store warning emitted when a
#: ``KeyStore`` lacks ``mark_verified``/``mark_rotated``/``mark_revoked``.
#: Silencing it is an explicit acceptance of the documented race risk
#: (a revoked key can verify again after a concurrent touch on such a
#: store — see README, "Limitations"); the warning exists so nobody
#: ships that configuration by accident.
LEGACY_STORE_WARNING = True


def scope_matches(granted: str, required: str) -> bool:
    """Return True when a granted scope satisfies a required scope."""
    if granted == required or granted == "*":
        return True
    if granted.endswith(":*"):
        return required.startswith(granted[:-1])
    return False


def validate_scopes(scopes: Iterable[str], *, label: str = "scope") -> frozenset[str]:
    """Normalize and validate an iterable of scope strings.

    A bare ``str``/``bytes`` is rejected rather than silently iterated into
    single characters. Every element must be a non-empty string without
    whitespace.

    Raises:
        ValueError: If ``scopes`` is a bare string or contains an invalid
            scope. This is a caller/configuration error, not a bad key.
    """
    if isinstance(scopes, (str, bytes)):
        # A bare string would silently become a set of single
        # characters ("read:users" -> {'r','e','a',...}), granting
        # nothing and confusing everyone. Fail loudly instead.
        raise ValueError(
            f"{label}s must be an iterable of scope strings, not a single "
            f"string (got {scopes!r}); pass e.g. scopes={{'read:users'}}"
        )
    result = frozenset(scopes)
    for scope in result:
        if not isinstance(scope, str) or not scope or any(ch.isspace() for ch in scope):
            raise ValueError(
                f"{label}s must be non-empty strings without whitespace (got {scope!r})"
            )
    return result


def missing_scopes(granted: Iterable[str], required: Iterable[str]) -> frozenset[str]:
    """Return the subset of ``required`` scopes not covered by ``granted``."""
    granted_list = list(granted)
    return frozenset(
        req for req in required if not any(scope_matches(g, req) for g in granted_list)
    )


class KeyManager:
    """High-level API for the full key lifecycle.

    Args:
        store: Where key records live (SQLite, in-memory, or custom).
        hasher: How raw keys are hashed. Defaults to
            :class:`bitting.hashing.ScryptHasher` (~16 MiB per hash).
        env: Environment label embedded in generated keys (``live``,
            ``test`` ...). Verified keys from other labels are still
            accepted if they match a stored prefix — label switching is
            an operational concern, not a security boundary.
        now_fn: Injectable clock (defaults to :func:`bitting.timeutil.utcnow`).
        on_event: Optional synchronous audit callback invoked for every
            lifecycle action, after the store has been updated.
        hashers: Optional registry of extra hashers keyed by algorithm
            name, used to verify keys that were issued with a different
            algorithm (see "Switching hashers" in the README). New keys
            are always hashed with ``hasher``.
        verify_touch_interval: Minimum time between persisting
            ``last_verified_at`` updates (default 60s). ``timedelta(0)``
            restores the 1.0 behavior of writing on every verification.
        audit_verifications: When False, skip audit events for verify
            outcomes (both successes and failures); lifecycle events
            (issued/rotated/revoked) are always emitted.

    Example:
        >>> from bitting import KeyManager, SQLiteStore
        >>> manager = KeyManager(SQLiteStore("keys.db"))       # doctest: +SKIP
        >>> issued = manager.issue(scopes={"read:users"}, description="ci")
        >>> manager.verify(issued.raw_key, required_scopes={"read:users"}).ok
        True
    """

    def __init__(
        self,
        store: KeyStore,
        *,
        hasher: Hasher | None = None,
        env: str = DEFAULT_ENV,
        now_fn: Callable[[], datetime] = utcnow,
        on_event: AuditCallback | None = None,
        hashers: Mapping[str, Hasher] | None = None,
        verify_touch_interval: timedelta = timedelta(seconds=60),
        audit_verifications: bool = True,
    ) -> None:
        self._store = store
        self._hasher: Hasher = hasher if hasher is not None else ScryptHasher()
        # Verification dispatches on the algorithm stored with each key,
        # so keys issued under a previous hasher keep verifying after an
        # algorithm change (the primary hasher covers new keys).
        self._hashers: dict[str, Hasher] = {self._hasher.algorithm: self._hasher}
        for name, candidate in (hashers or {}).items():
            if candidate.algorithm != name:
                raise ConfigurationError(
                    f"hasher registry key {name!r} must match the hasher's "
                    f"algorithm {candidate.algorithm!r}"
                )
            if name == self._hasher.algorithm and candidate is not self._hasher:
                # Silently re-registering the primary algorithm would make
                # verification use a different hasher than issuance.
                raise ConfigurationError(
                    f"hashers registry must not re-register the primary "
                    f"algorithm {name!r} with a different hasher"
                )
            self._hashers[name] = candidate
        self._env = validate_env_label(env)
        self._now_fn = now_fn
        self._on_event = on_event
        self._verify_touch_interval = verify_touch_interval
        self._audit_verifications = audit_verifications
        if LEGACY_STORE_WARNING:
            missing = [
                name
                for name in ("mark_verified", "mark_rotated", "mark_revoked")
                if getattr(store, name, None) is None
            ]
            if missing:
                warnings.warn(
                    "the configured store does not implement "
                    f"{', '.join(missing)}: bitting falls back to non-atomic "
                    "read-modify-write lifecycle updates, so a concurrent "
                    "revocation/rotation can be lost (in the worst case a "
                    "revoked key verifies again). Implement the mark_* "
                    "methods as targeted atomic updates (both built-in "
                    "stores do), or set bitting.manager.LEGACY_STORE_WARNING "
                    "= False to accept the documented risk explicitly.",
                    stacklevel=2,
                )

    @property
    def store(self) -> KeyStore:
        """The underlying key store."""
        return self._store

    @property
    def hasher(self) -> Hasher:
        """The hasher used for new keys (verification dispatches per record)."""
        return self._hasher

    # ------------------------------------------------------------------
    # Issue
    # ------------------------------------------------------------------

    def issue(
        self,
        *,
        scopes: Iterable[str] = (),
        description: str = "",
        ttl: timedelta | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IssuedKey:
        """Generate and persist a new API key.

        Args:
            scopes: Scopes granted to this key.
            description: Free-form human description.
            ttl: Key lifetime from now (mutually exclusive with ``expires_at``).
            expires_at: Absolute expiry moment (timezone-aware).
            metadata: Arbitrary JSON-serializable metadata stored with the key.

        Returns:
            An :class:`IssuedKey`. The raw key is shown once and can
            never be recovered — store it securely at the client.

        Raises:
            ValueError: If both ``ttl`` and ``expires_at`` are given.
        """
        return self._issue(
            scopes=scopes,
            description=description,
            ttl=ttl,
            expires_at=expires_at,
            metadata=metadata,
            emit=True,
        )

    def _issue(
        self,
        *,
        scopes: Iterable[str] = (),
        description: str = "",
        ttl: timedelta | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        emit: bool = True,
        supersedes: str | None = None,
    ) -> IssuedKey:
        if ttl is not None and expires_at is not None:
            raise ValueError("specify either ttl or expires_at, not both")
        if ttl is not None and ttl < timedelta(0):
            raise ValueError("ttl must be non-negative")
        now = self._now_fn()
        if ttl is not None:
            expires_at = now + ttl
        if expires_at is not None and expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")
        stored_metadata = dict(metadata or {})
        try:
            json.dumps(stored_metadata)
        except (TypeError, ValueError) as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        # store.save() is an upsert by contract, so a prefix collision would
        # silently overwrite somebody else's key. 16 base62 characters make
        # that astronomically unlikely, but "unlikely" is not "impossible"
        # and the failure mode is credential replacement: check and retry.
        for _attempt in range(_ISSUE_COLLISION_RETRIES):
            raw_key = generate_api_key(self._env)
            parsed = parse_api_key(raw_key)
            if self._store.find_by_prefix(parsed.prefix) is None:
                break
        else:  # pragma: no cover - requires an astronomically unlikely collision
            raise StorageError(
                f"could not generate an unused key prefix after {_ISSUE_COLLISION_RETRIES} attempts"
            )
        record = KeyRecord(
            key_id=new_key_id(),
            prefix=parsed.prefix,
            hash=self._hasher.hash(raw_key),
            algorithm=self._hasher.algorithm,
            scopes=self._validated_scopes(scopes),
            created_at=now,
            description=description,
            expires_at=expires_at,
            metadata=stored_metadata,
            supersedes=supersedes,
        )
        self._store.save(record)
        if emit:
            self._emit(AuditEventKind.ISSUED, record.prefix, now, {"key_id": record.key_id})
        return IssuedKey(raw_key=raw_key, key_id=record.key_id, prefix=parsed.prefix, record=record)

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def verify(
        self,
        raw_key: str,
        *,
        required_scopes: Iterable[str] = (),
    ) -> VerifyResult:
        """Verify a raw key and check required scopes.

        The verdict is precise: ``result.reason`` distinguishes malformed
        keys, unknown prefixes, hash mismatches, expiry, revocation,
        rotation (inside and outside the grace window), and missing
        scopes — so callers can answer 401 vs 403 correctly.

        Verification never raises for a bad key; it returns a failed
        :class:`VerifyResult` instead. Leading/trailing whitespace is
        tolerated (stripped), matching the HTTP-header behavior of the
        FastAPI integration.

        Raises:
            ValueError: If ``required_scopes`` contains a non-string,
                empty, or whitespace-containing scope (caller error,
                distinct from a bad key).
        """
        now = self._now_fn()
        required = frozenset(self._validated_scopes(required_scopes, label="required scope"))

        try:
            candidate = raw_key.strip() if isinstance(raw_key, str) else raw_key
            parsed = parse_api_key(candidate)
        except Exception:
            return VerifyResult(ok=False, reason=VerifyReason.INVALID_FORMAT, checked_at=now)

        record = self._store.find_by_prefix(parsed.prefix)
        if record is None:
            return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND, checked_at=now)

        if record.revoked_at is not None:
            self._emit_verify(
                AuditEventKind.VERIFY_FAILED,
                record.prefix,
                now,
                {"reason": VerifyReason.REVOKED.value},
            )
            return VerifyResult(
                ok=False, reason=VerifyReason.REVOKED, record=record, checked_at=now
            )

        if record.rotated_at is not None:
            # Expiry is a hard cap on the grace window: a rotated key
            # past its TTL is expired, never "rotated_grace".
            expired = record.expires_at is not None and now >= record.expires_at
            in_grace = not expired and record.grace_until is not None and now <= record.grace_until
            if not in_grace:
                reason = VerifyReason.EXPIRED if expired else VerifyReason.ROTATED
                self._emit_verify(
                    AuditEventKind.VERIFY_FAILED,
                    record.prefix,
                    now,
                    {"reason": reason.value},
                )
                return VerifyResult(ok=False, reason=reason, record=record, checked_at=now)
            if not self._verify_hash(candidate, record, now, rotated_grace=True):
                return VerifyResult(
                    ok=False, reason=VerifyReason.HASH_MISMATCH, record=record, checked_at=now
                )
            return self._confirm_and_finish(parsed, required, VerifyReason.ROTATED_GRACE)

        if record.expires_at is not None and now >= record.expires_at:
            self._emit_verify(
                AuditEventKind.VERIFY_FAILED,
                record.prefix,
                now,
                {"reason": VerifyReason.EXPIRED.value},
            )
            return VerifyResult(
                ok=False, reason=VerifyReason.EXPIRED, record=record, checked_at=now
            )

        if not self._verify_hash(candidate, record, now):
            return VerifyResult(
                ok=False, reason=VerifyReason.HASH_MISMATCH, record=record, checked_at=now
            )

        return self._confirm_and_finish(parsed, required, VerifyReason.OK)

    @staticmethod
    def _lifecycle_denial(record: KeyRecord, now: datetime) -> VerifyReason | None:
        """The denial implied by a record's lifecycle state, or None.

        None means the key may authenticate: either active, or rotated but
        still inside its grace window (which the original expiry caps).
        """
        if record.revoked_at is not None:
            return VerifyReason.REVOKED
        expired = record.expires_at is not None and now >= record.expires_at
        if record.rotated_at is not None:
            in_grace = not expired and record.grace_until is not None and now <= record.grace_until
            if not in_grace:
                return VerifyReason.EXPIRED if expired else VerifyReason.ROTATED
            return None
        if expired:
            return VerifyReason.EXPIRED
        return None

    def _confirm_and_finish(
        self,
        parsed: ParsedKey,
        required: frozenset[str],
        success_reason: VerifyReason,
    ) -> VerifyResult:
        """Re-read lifecycle state *after* the KDF, then authorize.

        The KDF is deliberately expensive (tens of milliseconds at the
        default scrypt cost, longer under CPU contention). Deciding from
        the pre-hash snapshot alone lets a credential that was revoked,
        expired or rotated *while the hash was running* still authenticate:
        the revocation commits, but the in-flight request returns ok=True.

        Re-reading the record and the clock costs one indexed lookup
        (microseconds against even a million-key store) plus one clock
        read, and shrinks that window from the whole KDF duration to a
        single lookup. It also picks up scope narrowing committed during
        the hash.

        This is a mitigation, not an absolute guarantee: a lifecycle change
        committed between this lookup and the caller acting on the result
        is still possible. Applications needing a hard guarantee must
        serialize revocation against authorization at a higher layer.
        """
        now = self._now_fn()
        fresh = self._store.find_by_prefix(parsed.prefix)
        if fresh is None:
            self._emit_verify(
                AuditEventKind.VERIFY_FAILED,
                parsed.prefix,
                now,
                {"reason": VerifyReason.NOT_FOUND.value},
            )
            return VerifyResult(ok=False, reason=VerifyReason.NOT_FOUND, checked_at=now)
        denial = self._lifecycle_denial(fresh, now)
        if denial is not None:
            self._emit_verify(
                AuditEventKind.VERIFY_FAILED, fresh.prefix, now, {"reason": denial.value}
            )
            return VerifyResult(ok=False, reason=denial, record=fresh, checked_at=now)
        if fresh.rotated_at is not None:
            success_reason = VerifyReason.ROTATED_GRACE
        return self._check_scopes(parsed, fresh, required, now, success_reason)

    def _check_scopes(
        self,
        parsed: ParsedKey,
        record: KeyRecord,
        required: frozenset[str],
        now: datetime,
        success_reason: VerifyReason,
    ) -> VerifyResult:
        missing = missing_scopes(record.scopes, required) if required else frozenset()
        if missing:
            self._emit_verify(
                AuditEventKind.VERIFY_FAILED,
                record.prefix,
                now,
                {"reason": VerifyReason.SCOPE_MISSING.value, "missing": sorted(missing)},
            )
            return VerifyResult(
                ok=False,
                reason=VerifyReason.SCOPE_MISSING,
                record=record,
                missing_scopes=missing,
                checked_at=now,
            )
        previous_touch = record.last_verified_at
        record.last_verified_at = now
        # Persisting the touch is throttled: the hot verification path
        # stays read-only except once per interval (0 restores 1.0
        # write-on-every-verify behavior). The touch is a targeted
        # single-field update (mark_verified) so a concurrent revoke or
        # rotate can never be clobbered by a stale full-record save.
        if self._should_persist_touch(previous_touch, now):
            self._touch_verified(parsed.prefix, now)
        self._emit_verify(
            AuditEventKind.VERIFIED,
            record.prefix,
            now,
            {"reason": success_reason.value, "key_id": record.key_id},
        )
        return VerifyResult(ok=True, reason=success_reason, record=record, checked_at=now)

    def _verify_hash(
        self,
        raw_key: str,
        record: KeyRecord,
        now: datetime,
        *,
        rotated_grace: bool = False,
    ) -> bool:
        """Verify the hash with the hasher recorded for this key."""
        hasher = self._hashers.get(record.algorithm)
        verified = False
        detail_extra: dict[str, Any] = {}
        if hasher is not None:
            try:
                verified = hasher.verify(raw_key, record.hash)
            except Exception as exc:
                # A corrupted stored hash (or a broken custom hasher)
                # must fail closed, never crash the request path.
                verified = False
                detail_extra = {"hasher_error": type(exc).__name__}
        if not verified:
            detail: dict[str, Any] = {"reason": VerifyReason.HASH_MISMATCH.value}
            if rotated_grace:
                detail["rotated_grace"] = True
            if hasher is None:
                detail["unknown_algorithm"] = record.algorithm
            detail.update(detail_extra)
            self._emit_verify(AuditEventKind.VERIFY_FAILED, record.prefix, now, detail)
            return False
        return True

    def _should_persist_touch(self, previous: datetime | None, now: datetime) -> bool:
        if self._verify_touch_interval <= timedelta(0):
            return True
        if previous is None:
            return True
        return now - previous >= self._verify_touch_interval

    # ------------------------------------------------------------------
    # Rotate / revoke / inspect
    # ------------------------------------------------------------------

    def rotate(
        self,
        prefix: str,
        *,
        grace: timedelta = DEFAULT_ROTATION_GRACE,
        scopes: Iterable[str] | None = None,
        description: str | None = None,
        ttl: timedelta | None = None,
    ) -> IssuedKey:
        """Replace the key identified by ``prefix`` with a fresh key.

        The old key continues to verify (with reason
        ``ROTATED_GRACE``) until ``grace`` elapses or the old key's
        original expiry — whichever comes first — so clients can migrate
        without downtime. After that the old key is rejected with
        reason ``ROTATED`` (or ``EXPIRED`` if its TTL ended first).

        The successor does **not** inherit the old key's TTL; pass
        ``ttl`` to give the new key a lifetime.

        Args:
            prefix: Prefix of the key to rotate.
            grace: How long the old key keeps working (non-negative,
                capped by the old key's expiry).
            scopes: Replacement scopes (None keeps the existing ones).
            description: Replacement description (None keeps existing).
            ttl: Lifetime for the *new* key (None: no expiry).

        Raises:
            KeyNotFoundError: If no key has this prefix.
            ValueError: If the key was already rotated or revoked, is
                already expired, or ``grace`` is negative.
        """
        if grace < timedelta(0):
            raise ValueError("grace must be non-negative")
        now = self._now_fn()
        record = self._require(prefix)
        if record.revoked_at is not None:
            raise ValueError(f"key {prefix!r} is revoked; issue a new key instead")
        if record.rotated_at is not None:
            raise ValueError(f"key {prefix!r} was already rotated; rotate the successor instead")
        if record.expires_at is not None and now >= record.expires_at:
            raise ValueError(f"key {prefix!r} is expired; issue a new key instead")

        # Persist the successor FIRST, complete and undisclosed: its
        # supersedes link is already set, but the old key still verifies
        # normally and no ROTATED event has been emitted. If anything
        # fails from here on, the cleanup below removes the successor and
        # the old key is untouched — a failed rotation can never strand a
        # key in a rotated state without a working successor.
        issued = self._issue(
            scopes=record.scopes if scopes is None else scopes,
            description=record.description if description is None else description,
            ttl=ttl,
            metadata=record.metadata,
            emit=False,
            supersedes=record.prefix,
        )
        successor = issued.record
        grace_until = now + grace
        try:
            # Atomically claim the active→rotated transition. Concurrent
            # rotations race on this single conditional update: exactly
            # one caller wins; the losers clean up and raise below.
            claimed = self._mark_rotated(record.prefix, rotated_at=now, grace_until=grace_until)
        except BaseException:
            self._discard_successor(successor.prefix)
            raise
        if not claimed:
            self._discard_successor(successor.prefix)
            current = self._require(prefix)
            if current.revoked_at is not None:
                raise ValueError(f"key {prefix!r} is revoked; issue a new key instead")
            raise ValueError(f"key {prefix!r} was already rotated; rotate the successor instead")

        self._emit(
            AuditEventKind.ROTATED,
            record.prefix,
            now,
            {"successor_prefix": successor.prefix, "grace_until": grace_until.isoformat()},
        )
        return issued

    def _discard_successor(self, prefix: str) -> None:
        """Best-effort removal of an undisclosed rotate() successor.

        Cleanup must never mask the original failure, so storage errors
        are suppressed: an orphaned, never-disclosed successor record is
        inert (its raw key was never returned to anyone) and can be
        pruned by an operator.
        """
        with contextlib.suppress(Exception):
            self._store.delete(prefix)

    def revoke(self, prefix: str, *, now: datetime | None = None) -> KeyRecord:
        """Immediately revoke the key with this prefix.

        Revocation goes through :meth:`bitting.storage.KeyStore.mark_revoked`
        — a targeted conditional update that touches **only** ``revoked_at``
        — so a rotation claimed concurrently keeps its ``rotated_at`` and
        ``grace_until``, and the persisted touch of a concurrent
        verification keeps its ``last_verified_at``. Revocation is
        idempotent: revoking an already-revoked key keeps the first
        (authoritative) timestamp and records the repeated attempt in the
        audit trail with an ``already_revoked`` detail flag.

        Raises:
            KeyNotFoundError: If no key has this prefix.
            ValueError: If ``now`` is given but timezone-naive.
        """
        if now is not None and now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        moment = now or self._now_fn()
        marked = self._mark_revoked(prefix, at=moment)
        # Fresh post-transition state; also the KeyNotFoundError source for a
        # missing key (mark_revoked merely returns False for absent prefixes).
        record = self._require(prefix)
        detail: dict[str, Any] = {"key_id": record.key_id}
        if not marked:
            detail["already_revoked"] = True
        self._emit(AuditEventKind.REVOKED, record.prefix, moment, detail)
        return record

    def list_keys(self) -> list[KeyRecord]:
        """Return all key records (never raw keys)."""
        return self._store.list_keys()

    def list_events(self, *, limit: int = 100) -> list[AuditEvent]:
        """Return recent audit events, newest first."""
        return self._store.list_events(limit=limit)

    def prune_events(self, *, before: datetime) -> int:
        """Delete audit events strictly older than ``before``.

        Returns the number of events removed. Use this to bound audit
        growth; see ``delete_events_before`` on the stores.

        Raises:
            ValueError: If ``before`` is timezone-naive.
            NotImplementedError: If the store does not support pruning.
        """
        if before.tzinfo is None:
            raise ValueError("before must be timezone-aware")
        delete = getattr(self._store, "delete_events_before", None)
        if delete is None:
            raise NotImplementedError("the configured store does not support audit pruning")
        return int(delete(before))

    def close(self) -> None:
        """Close the underlying store, if it holds resources."""
        self._store.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _require(self, prefix: str) -> KeyRecord:
        record = self._store.find_by_prefix(prefix)
        if record is None:
            raise KeyNotFoundError(f"no key with prefix {prefix!r}")
        return record

    @staticmethod
    def _validated_scopes(scopes: Iterable[str], *, label: str = "scope") -> frozenset[str]:
        return validate_scopes(scopes, label=label)

    def _touch_verified(self, prefix: str, at: datetime) -> None:
        """Persist a ``last_verified_at`` touch without touching any other field.

        SECURITY: if the store does not implement ``mark_verified``, the
        fallback below re-reads a fresh record and saves only the timestamp
        on it. That re-read shrinks — but does not eliminate — the window in
        which a concurrent revocation (or rotation) can be overwritten by
        the stale save: for such stores a *revoked key can verify again*
        after this race. Stores used in production MUST implement
        ``mark_verified`` as a targeted single-field update (both built-in
        stores do; see README, "Limitations").
        """
        touch = getattr(self._store, "mark_verified", None)
        if touch is None:
            record = self._store.find_by_prefix(prefix)
            if record is None:
                return
            record.last_verified_at = at
            self._store.save(record)
            return
        touch(prefix, at=at)

    def _mark_rotated(self, prefix: str, *, rotated_at: datetime, grace_until: datetime) -> bool:
        """Claim the active→rotated transition through the store."""
        mark = getattr(self._store, "mark_rotated", None)
        if mark is None:
            # Duck-typed store predating mark_rotated: fall back to the
            # 1.0 non-atomic read-check-write behavior.
            record = self._store.find_by_prefix(prefix)
            if record is None or record.rotated_at is not None or record.revoked_at is not None:
                return False
            record.rotated_at = rotated_at
            record.grace_until = grace_until
            self._store.save(record)
            return True
        return bool(mark(prefix, rotated_at=rotated_at, grace_until=grace_until))

    def _mark_revoked(self, prefix: str, *, at: datetime) -> bool:
        """Claim the active→revoked transition through the store."""
        mark = getattr(self._store, "mark_revoked", None)
        if mark is None:
            # Duck-typed store predating mark_revoked: fall back to the
            # 1.0 non-atomic read-check-write behavior. Note this full-record
            # save can lose a concurrent lifecycle transition (see the
            # mark_rotated fallback above and README, "Limitations").
            record = self._store.find_by_prefix(prefix)
            if record is None or record.revoked_at is not None:
                return False
            record.revoked_at = at
            self._store.save(record)
            return True
        return bool(mark(prefix, at=at))

    def _emit(
        self,
        kind: AuditEventKind,
        prefix: str,
        at: datetime,
        detail: dict[str, Any],
    ) -> None:
        event = AuditEvent(kind=kind, prefix=prefix, at=at, detail=detail)
        # Audit persistence and observers are best-effort by design:
        # a broken observer or store must never break verification.
        with contextlib.suppress(Exception):
            self._store.append_event(event)
        if self._on_event is not None:
            with contextlib.suppress(Exception):
                self._on_event(event)

    def _emit_verify(
        self,
        kind: AuditEventKind,
        prefix: str,
        at: datetime,
        detail: dict[str, Any],
    ) -> None:
        """Emit a verify-path event, unless verify auditing is disabled."""
        if self._audit_verifications:
            self._emit(kind, prefix, at, detail)
