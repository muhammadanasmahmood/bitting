"""Time helpers: aware-UTC clock access and human-friendly duration parsing.

The library never uses naive datetimes. All timestamps are timezone-aware
UTC values, serialized to ISO 8601 in storage.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

__all__ = ["from_iso", "parse_duration", "to_iso", "utcnow"]

_DURATION_RE = re.compile(
    r"^\s*(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>s|sec|secs|second|seconds|"
    r"m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)\s*$",
    re.IGNORECASE,
)

_UNIT_TO_SECONDS: dict[str, float] = {
    "s": 1,
    "sec": 1,
    "secs": 1,
    "second": 1,
    "seconds": 1,
    "m": 60,
    "min": 60,
    "mins": 60,
    "minute": 60,
    "minutes": 60,
    "h": 3600,
    "hr": 3600,
    "hrs": 3600,
    "hour": 3600,
    "hours": 3600,
    "d": 86400,
    "day": 86400,
    "days": 86400,
    "w": 604800,
    "week": 604800,
    "weeks": 604800,
}


def utcnow() -> datetime:
    """Return the current moment as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def parse_duration(text: str) -> timedelta:
    """Parse a human-friendly duration string into a :class:`timedelta`.

    Supported units (case-insensitive): ``s``, ``m``, ``h``, ``d``, ``w``
    and their long forms (``seconds``, ``minutes``, ``hours``, ``days``,
    ``weeks``). A bare number is interpreted as seconds.

    Examples:
        >>> parse_duration("30d")
        datetime.timedelta(days=30)
        >>> parse_duration("12h")
        datetime.timedelta(seconds=43200)
        >>> parse_duration("90")
        datetime.timedelta(seconds=90)

    Raises:
        ValueError: If the text is not a valid duration.
    """
    if not isinstance(text, str):
        raise ValueError(f"duration must be a string, got {type(text).__name__}")
    match = _DURATION_RE.match(text)
    if match is None:
        stripped = text.strip()
        if re.fullmatch(r"\d+(?:\.\d+)?", stripped):
            seconds = float(stripped)
        else:
            raise ValueError(f"invalid duration: {text!r}")
    else:
        value = float(match.group("value"))
        unit = match.group("unit").lower()
        seconds = value * _UNIT_TO_SECONDS[unit]
    if seconds < 0:
        raise ValueError(f"duration must be non-negative, got {text!r}")
    try:
        return timedelta(seconds=seconds)
    except OverflowError as exc:
        # Values like "999999999999999w" overflow timedelta; surface the
        # documented ValueError instead of leaking OverflowError.
        raise ValueError(f"duration out of range: {text!r}") from exc


def to_iso(moment: datetime) -> str:
    """Serialize a datetime to an ISO 8601 UTC string."""
    return moment.astimezone(timezone.utc).isoformat()


def from_iso(text: str) -> datetime:
    """Parse an ISO 8601 string into a timezone-aware UTC datetime.

    A trailing ``Z`` is normalized to ``+00:00`` explicitly: Python 3.11+
    accepts it natively but 3.10 does not, so a row written by an external
    tool would load on 3.11 and raise StorageError on 3.10. ``to_iso``
    always emits ``+00:00``, so library-written rows are unaffected.
    """
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
