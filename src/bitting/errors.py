"""Exception hierarchy for bitting.

All library errors derive from :class:`BittingError`, so applications can
catch a single base class while still distinguishing failure modes when
needed.
"""

from __future__ import annotations

__all__ = [
    "BittingError",
    "ConfigurationError",
    "DuplicateKeyError",
    "KeyFormatError",
    "KeyNotFoundError",
    "StorageError",
]


class BittingError(Exception):
    """Base class for all errors raised by bitting."""


class KeyFormatError(BittingError):
    """A raw API key string is malformed (wrong scheme, bad checksum, ...)."""


class KeyNotFoundError(BittingError):
    """No key record exists for the given prefix."""


class DuplicateKeyError(BittingError):
    """A key with the same prefix already exists in the store."""


class StorageError(BittingError):
    """The backing key store failed an operation."""


class ConfigurationError(BittingError):
    """The library was configured with invalid values."""
