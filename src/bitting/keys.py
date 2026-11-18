"""API key format: generation, parsing, and checksum validation.

Key anatomy
===========
A bitting key looks like::

    btg_live_9kQ2VxNmLpR7zT4w_8fJk2LmNpQrStUvWxYz3Aa5Bb7CcDdEe9fGh_5K3m

It has five parts, joined by underscores:

``btg``
    Scheme marker that identifies the key format.
``live``
    Environment label (``live``, ``test``, ... — configurable, validated).
``9kQ2VxNmLpR7zT4w``
    A 16-character base62 *prefix* (~95 bits; 8-64 configurable). It is
    stored in plaintext and used as the lookup index so verification
    never scans the table.
``8fJk...9fGh``
    A 40-character base62 *secret* (~238 bits; 16-128 configurable). It
    is never stored; only its memory-hard hash is persisted.
``5K3m``
    A 4-character base62 *checksum* over the preceding characters. It
    catches transcription errors (typos) before the store is touched.
    This is a data-integrity aid, **not** a security control.

Design notes
------------
* Prefix lookup is the same trade-off made by Stripe-style API keys:
  an attacker who steals the database learns which prefixes exist but
  cannot reconstruct any secret (they only ever see hashes).
* Malformed keys are rejected before a store lookup, so junk traffic
  cannot be used to force database work.
* ``secrets`` from the standard library provides the entropy; no
  dependency is required.
"""

from __future__ import annotations

import binascii
import re
import secrets
from dataclasses import dataclass

from .errors import ConfigurationError, KeyFormatError

__all__ = [
    "ALPHABET",
    "CHECKSUM_LENGTH",
    "DEFAULT_ENV",
    "PREFIX_LENGTH",
    "SCHEME",
    "SECRET_LENGTH",
    "ParsedKey",
    "compute_checksum",
    "generate_api_key",
    "parse_api_key",
    "validate_env_label",
]

#: Scheme marker that starts every bitting key.
SCHEME = "btg"

#: base62 alphabet used for all random components.
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

#: Length of the plaintext prefix (the lookup index).
PREFIX_LENGTH = 16

#: Length of the secret component.
SECRET_LENGTH = 40

#: Length of the trailing checksum.
CHECKSUM_LENGTH = 4

#: Default environment label embedded in generated keys.
DEFAULT_ENV = "live"

_ENV_RE = re.compile(r"^[a-z][a-z0-9]{1,15}$")

# btg_live_<8-64 chars>_<16-128 chars>_<4 chars>
# The component-length ranges mirror exactly what generate_api_key()
# validates, so every key the generator can produce is parseable.
_KEY_RE = re.compile(
    r"^(?P<scheme>btg)"
    r"_(?P<env>[a-z][a-z0-9]{1,15})"
    r"_(?P<prefix>[0-9A-Za-z]{8,64})"
    r"_(?P<secret>[0-9A-Za-z]{16,128})"
    r"_(?P<checksum>[0-9A-Za-z]{4})$"
)


@dataclass(frozen=True, slots=True)
class ParsedKey:
    """The decoded components of a raw API key string.

    The secret is redacted in ``repr()`` so a debugger or an unlucky
    ``%r`` log line can never print the live credential.
    """

    scheme: str
    env: str
    prefix: str
    secret: str

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(scheme={self.scheme!r}, env={self.env!r}, "
            f"prefix={self.prefix!r}, secret=<redacted:{len(self.secret)} chars>)"
        )

    @property
    def canonical(self) -> str:
        """The key string without the trailing checksum."""
        return f"{self.scheme}_{self.env}_{self.prefix}_{self.secret}"


def validate_env_label(env: str) -> str:
    """Validate an environment label such as ``live`` or ``test``.

    Labels must be 2-16 characters of lowercase letters and digits,
    starting with a letter. This keeps keys unambiguous when parsed.

    Raises:
        ConfigurationError: If the label is invalid.
    """
    if not isinstance(env, str) or not _ENV_RE.fullmatch(env):
        raise ConfigurationError(
            "environment label must be 2-16 chars of lowercase letters/digits, "
            f"starting with a letter (got {env!r})"
        )
    return env


def _random_token(length: int) -> str:
    # System randomness with rejection sampling to avoid modulo bias:
    # draw fresh indices until one is uniform over the 62-symbol alphabet.
    alphabet_length = len(ALPHABET)
    out: list[str] = []
    while len(out) < length:
        byte = secrets.token_bytes(1)[0]
        if byte < 248:  # 248 = 62 * 4, the largest exact multiple of 62 <= 256
            out.append(ALPHABET[byte % alphabet_length])
    return "".join(out)


def compute_checksum(canonical: str) -> str:
    """Compute the 4-char base62 checksum for a canonical key string.

    The checksum is ``CRC32(canonical) mod 62**4``, base62-encoded and
    zero-padded. It detects common transcription errors (single-character
    substitutions, most transpositions). It is *not* cryptographic and
    must never be treated as an integrity guarantee against an attacker.
    """
    value = binascii.crc32(canonical.encode("utf-8")) % (62**CHECKSUM_LENGTH)
    digits: list[str] = []
    for _ in range(CHECKSUM_LENGTH):
        value, remainder = divmod(value, 62)
        digits.append(ALPHABET[remainder])
    return "".join(reversed(digits))


def generate_api_key(
    env: str = DEFAULT_ENV,
    *,
    prefix_length: int = PREFIX_LENGTH,
    secret_length: int = SECRET_LENGTH,
) -> str:
    """Generate a new raw API key string.

    Args:
        env: Environment label embedded in the key (``live``, ``test``, ...).
        prefix_length: Length of the random prefix (default 16).
        secret_length: Length of the random secret (default 40).

    Returns:
        A key of the form ``btg_<env>_<prefix>_<secret>_<checksum>``.

    Raises:
        ConfigurationError: If ``env`` or the component lengths are invalid.
    """
    validate_env_label(env)
    if isinstance(prefix_length, bool) or not isinstance(prefix_length, int):
        raise ConfigurationError(
            f"prefix_length must be an int (got {type(prefix_length).__name__})"
        )
    if isinstance(secret_length, bool) or not isinstance(secret_length, int):
        raise ConfigurationError(
            f"secret_length must be an int (got {type(secret_length).__name__})"
        )
    if prefix_length < 8 or prefix_length > 64:
        raise ConfigurationError("prefix_length must be between 8 and 64")
    if secret_length < 16 or secret_length > 128:
        raise ConfigurationError("secret_length must be between 16 and 128")
    prefix = _random_token(prefix_length)
    secret = _random_token(secret_length)
    canonical = f"{SCHEME}_{env}_{prefix}_{secret}"
    return f"{canonical}_{compute_checksum(canonical)}"


def parse_api_key(raw: str) -> ParsedKey:
    """Parse and checksum-validate a raw API key string.

    Leading/trailing whitespace is tolerated and stripped.

    Returns:
        The decoded :class:`ParsedKey`.

    Raises:
        KeyFormatError: If the key does not match the format, the checksum
            is wrong, or the scheme is not ``btg``.
    """
    if not isinstance(raw, str):
        raise KeyFormatError(f"API key must be a string, got {type(raw).__name__}")
    candidate = raw.strip()
    match = _KEY_RE.fullmatch(candidate)
    if match is None:
        raise KeyFormatError("malformed API key: expected btg_<env>_<prefix>_<secret>_<checksum>")
    parts = match.groupdict()
    parsed = ParsedKey(
        scheme=parts["scheme"],
        env=parts["env"],
        prefix=parts["prefix"],
        secret=parts["secret"],
    )
    if compute_checksum(parsed.canonical) != parts["checksum"]:
        raise KeyFormatError("API key checksum mismatch (transcription error?)")
    return parsed
