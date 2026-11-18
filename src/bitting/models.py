"""Domain models: key records, issued keys, and verification results.

Security note: :class:`IssuedKey` is the only object that ever holds a
raw key, and its ``__repr__`` is redacted so secrets cannot leak into
logs by accident.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .timeutil import to_iso

__all__ = [
    "AuditEvent",
    "AuditEventKind",
    "IssuedKey",
    "KeyRecord",
    "VerifyReason",
    "VerifyResult",
]


@dataclass(slots=True)
class KeyRecord:
    """Everything the store knows about one API key.

    The raw key is *never* part of a record; only its hash. The prefix
    is stored plaintext because it is the lookup index (Stripe-style).
    """

    key_id: str
    prefix: str
    hash: str
    algorithm: str
    scopes: frozenset[str]
    created_at: datetime
    description: str = ""
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    rotated_at: datetime | None = None
    grace_until: datetime | None = None
    last_verified_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    supersedes: str | None = None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def __repr__(self) -> str:
        # Mirrors IssuedKey: the stored hash must never leak into logs.
        return (
            f"KeyRecord(key_id={self.key_id!r}, prefix={self.prefix!r}, "
            f"hash=<redacted:{len(self.hash)} chars>, algorithm={self.algorithm!r}, "
            f"scopes={sorted(self.scopes)!r}, created_at={self.created_at!r}, "
            f"description={self.description!r}, expires_at={self.expires_at!r}, "
            f"revoked_at={self.revoked_at!r}, rotated_at={self.rotated_at!r}, "
            f"grace_until={self.grace_until!r}, last_verified_at={self.last_verified_at!r}, "
            f"metadata={self.metadata!r}, supersedes={self.supersedes!r})"
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True when the key's expiry moment has passed."""
        if self.expires_at is None:
            return False
        from .timeutil import utcnow

        return self.expires_at <= (now or utcnow())

    def to_json(self) -> dict[str, Any]:
        """A JSON-serializable view of the record (no secrets involved).

        The stored KDF hash is redacted: it is offline-attack material
        (a guessable key can be confirmed against it without any server
        round-trip), so it must not travel into CLI output, logs, or API
        responses. Storage adapters serialize records through their own
        row mapping, not through this view.
        """

        def _dt(value: datetime | None) -> str | None:
            return to_iso(value) if value is not None else None

        return {
            "key_id": self.key_id,
            "prefix": self.prefix,
            "hash": "<redacted>",
            "algorithm": self.algorithm,
            "scopes": sorted(self.scopes),
            "created_at": _dt(self.created_at),
            "description": self.description,
            "expires_at": _dt(self.expires_at),
            "revoked_at": _dt(self.revoked_at),
            "rotated_at": _dt(self.rotated_at),
            "grace_until": _dt(self.grace_until),
            "last_verified_at": _dt(self.last_verified_at),
            "metadata": self.metadata,
            "supersedes": self.supersedes,
        }


@dataclass(slots=True)
class IssuedKey:
    """The result of issuing (or rotating) a key: the raw key plus its record.

    The raw key must be shown to the user exactly once, at issue time.
    It cannot be recovered later — only verified.
    """

    raw_key: str
    key_id: str
    prefix: str
    record: KeyRecord

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"IssuedKey(prefix={self.prefix!r}, key_id={self.key_id!r}, "
            f"raw_key=<redacted:{len(self.raw_key)} chars>)"
        )

    __str__ = __repr__


class VerifyReason(Enum):
    """Why a verification succeeded or failed.

    Applications can map these to HTTP status codes precisely:
    ``*_MISMATCH``/``NOT_FOUND`` are authentication failures (401),
    ``SCOPE_MISSING`` is an authorization failure (403).
    """

    OK = "ok"
    ROTATED_GRACE = "rotated_grace"
    NOT_FOUND = "not_found"
    INVALID_FORMAT = "invalid_format"
    HASH_MISMATCH = "hash_mismatch"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ROTATED = "rotated"
    SCOPE_MISSING = "scope_missing"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of :meth:`bitting.KeyManager.verify`.

    ``ok`` is the verdict; ``reason`` explains it; ``record`` is the
    matched key record when a prefix matched (None otherwise).
    """

    ok: bool
    reason: VerifyReason
    record: KeyRecord | None = None
    missing_scopes: frozenset[str] = frozenset()
    checked_at: datetime | None = None

    def __bool__(self) -> bool:
        return self.ok


class AuditEventKind(Enum):
    """Kinds of audit events emitted by the manager."""

    ISSUED = "issued"
    VERIFIED = "verified"
    VERIFY_FAILED = "verify_failed"
    ROTATED = "rotated"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """An immutable audit event describing a lifecycle action."""

    kind: AuditEventKind
    prefix: str
    at: datetime
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "prefix": self.prefix,
            "at": to_iso(self.at),
            "detail": self.detail,
        }


#: Type of a user-supplied audit callback.
AuditCallback = Callable[[AuditEvent], None]
