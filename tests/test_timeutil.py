"""Tests for timeutil: duration parsing and ISO round-trips."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bitting import parse_duration
from bitting.timeutil import from_iso, to_iso


class TestParseDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30", timedelta(seconds=30)),
            ("90s", timedelta(seconds=90)),
            ("5m", timedelta(minutes=5)),
            ("2h", timedelta(hours=2)),
            ("30d", timedelta(days=30)),
            ("2w", timedelta(weeks=2)),
            ("1.5h", timedelta(minutes=90)),
            ("  12 H  ", timedelta(hours=12)),
            ("1hour", timedelta(hours=1)),
            ("3days", timedelta(days=3)),
            ("2weeks", timedelta(weeks=2)),
        ],
    )
    def test_valid(self, text: str, expected: timedelta) -> None:
        assert parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "abc", "1x", "h", "-5d", "1.2.3h", "5 s 3"])
    def test_invalid(self, text: str) -> None:
        with pytest.raises(ValueError):
            parse_duration(text)

    def test_huge_values_raise_value_error_not_overflow(self) -> None:
        # timedelta overflows around 999999999 days; the documented
        # ValueError must surface instead of OverflowError.
        with pytest.raises(ValueError, match="out of range"):
            parse_duration("999999999999999w")

    def test_non_string_rejected(self) -> None:
        with pytest.raises(ValueError):
            parse_duration(30)  # type: ignore[arg-type]


class TestIsoRoundtrip:
    def test_roundtrip(self) -> None:
        moment = datetime(2026, 5, 1, 10, 30, tzinfo=timezone.utc)
        assert from_iso(to_iso(moment)) == moment

    def test_naive_iso_interpreted_as_utc(self) -> None:
        parsed = from_iso("2026-05-01T10:30:00")
        assert parsed.tzinfo is not None

    def test_to_iso_normalizes_timezone(self) -> None:
        from datetime import timedelta

        aware = datetime(2026, 5, 1, 16, 30, tzinfo=timezone(timedelta(hours=5)))
        # 16:30 at UTC+05:00 is 11:30 UTC.
        assert to_iso(aware) == "2026-05-01T11:30:00+00:00"
