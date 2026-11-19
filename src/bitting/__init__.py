"""bitting — API key lifecycle management for Python.

Generation, memory-hard hashing (scrypt / Argon2id), prefix-indexed
storage, rotation with grace periods, scopes with wildcards, TTL,
revocation, audit events, a CLI, and an optional FastAPI integration.

Quick start::

    from bitting import InMemoryStore, KeyManager

    manager = KeyManager(InMemoryStore())
    issued = manager.issue(scopes={"read:users"}, description="ci-runner")
    print(issued.raw_key)                  # shown exactly once

    result = manager.verify(issued.raw_key, required_scopes={"read:users"})
    assert result.ok
"""

from __future__ import annotations

from .errors import (
    BittingError,
    ConfigurationError,
    DuplicateKeyError,
    KeyFormatError,
    KeyNotFoundError,
    StorageError,
)
from .hashing import Argon2Hasher, Hasher, ScryptHasher
from .keys import generate_api_key, parse_api_key
from .manager import (
    DEFAULT_ROTATION_GRACE,
    KeyManager,
    missing_scopes,
    scope_matches,
    validate_scopes,
)
from .models import (
    AuditEvent,
    AuditEventKind,
    IssuedKey,
    KeyRecord,
    VerifyReason,
    VerifyResult,
)
from .storage import InMemoryStore, KeyStore, SQLiteStore
from .timeutil import parse_duration

__version__ = "1.2.2"

__all__ = [
    "DEFAULT_ROTATION_GRACE",
    "Argon2Hasher",
    "AuditEvent",
    "AuditEventKind",
    "BittingError",
    "ConfigurationError",
    "DuplicateKeyError",
    "Hasher",
    "InMemoryStore",
    "IssuedKey",
    "KeyFormatError",
    "KeyManager",
    "KeyNotFoundError",
    "KeyRecord",
    "KeyStore",
    "SQLiteStore",
    "ScryptHasher",
    "StorageError",
    "VerifyReason",
    "VerifyResult",
    "generate_api_key",
    "missing_scopes",
    "parse_api_key",
    "parse_duration",
    "scope_matches",
    "validate_scopes",
]
