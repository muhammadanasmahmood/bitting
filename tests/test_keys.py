"""Tests for key generation, format parsing, and checksums."""

from __future__ import annotations

import re

import pytest

from bitting import ConfigurationError, KeyFormatError, generate_api_key, parse_api_key
from bitting.keys import ALPHABET, compute_checksum

KEY_RE = re.compile(r"^btg_[a-z][a-z0-9]{1,15}_[0-9A-Za-z]{16}_[0-9A-Za-z]{40}_[0-9A-Za-z]{4}$")


class TestGenerate:
    def test_format_shape(self) -> None:
        key = generate_api_key()
        assert KEY_RE.fullmatch(key), key

    def test_uniqueness(self) -> None:
        keys = {generate_api_key() for _ in range(200)}
        assert len(keys) == 200

    def test_env_label_embedded(self) -> None:
        assert generate_api_key(env="test").split("_")[1] == "test"

    def test_invalid_env_labels_rejected(self) -> None:
        for bad in ("", "l", "Live", "LIVE", "1live", "way_too_long_label", "with-dash", "a" * 20):
            with pytest.raises(ConfigurationError):
                generate_api_key(env=bad)

    def test_invalid_lengths_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            generate_api_key(prefix_length=4)
        with pytest.raises(ConfigurationError):
            generate_api_key(secret_length=8)

    def test_custom_lengths(self) -> None:
        key = generate_api_key(prefix_length=32, secret_length=64)
        parts = key.split("_")
        assert len(parts[2]) == 32  # prefix
        assert len(parts[3]) == 64  # secret

    def test_custom_lengths_roundtrip(self) -> None:
        # Regression: the parser must accept every component length the
        # generator can produce, or custom-length keys would be
        # unverifiable (found post-release).
        for prefix_length, secret_length in ((8, 16), (32, 64), (64, 128)):
            key = generate_api_key(prefix_length=prefix_length, secret_length=secret_length)
            parsed = parse_api_key(key)
            assert len(parsed.prefix) == prefix_length
            assert len(parsed.secret) == secret_length

    def test_parse_rejects_out_of_range_lengths(self) -> None:
        # Lengths outside the generator's validated range stay malformed.
        canonical = "btg_live_" + "a" * 7 + "_" + "b" * 40  # 7-char prefix < minimum 8
        key = f"{canonical}_{compute_checksum(canonical)}"
        with pytest.raises(KeyFormatError):
            parse_api_key(key)

    def test_only_alphabet_characters(self) -> None:
        key = generate_api_key()
        body = key.split("_", 2)[2]
        assert all(ch in ALPHABET or ch == "_" for ch in body)


class TestParse:
    def test_roundtrip(self) -> None:
        key = generate_api_key(env="stage")
        parsed = parse_api_key(key)
        assert parsed.scheme == "btg"
        assert parsed.env == "stage"
        assert key.startswith(f"btg_stage_{parsed.prefix}_")
        assert parsed.secret in key

    def test_whitespace_tolerated(self) -> None:
        key = generate_api_key()
        assert parse_api_key(f"  {key}\n").prefix == parse_api_key(key).prefix

    def test_rejects_wrong_scheme(self) -> None:
        key = generate_api_key().replace("btg_", "sk_", 1)
        with pytest.raises(KeyFormatError):
            parse_api_key(key)

    def test_rejects_checksum_tamper(self) -> None:
        key = generate_api_key()
        tampered = key[:-4] + ("0" if key[-4] != "0" else "1") + key[-3:]
        with pytest.raises(KeyFormatError):
            parse_api_key(tampered)

    def test_secret_tamper_with_recomputed_checksum_parses(self) -> None:
        # A different secret with a *valid* checksum is a well-formed key
        # (of a key that was never issued); only checksum tampering fails
        # parsing. Verification elsewhere rejects it via hash mismatch.
        key = generate_api_key()
        parts = key.split("_")
        tampered_secret = ("A" if parts[3][0] != "A" else "B") + parts[3][1:]
        canonical = f"{parts[0]}_{parts[1]}_{parts[2]}_{tampered_secret}"
        tampered = f"{canonical}_{compute_checksum(canonical)}"
        parsed = parse_api_key(tampered)
        assert parsed.secret == tampered_secret

    def test_rejects_truncated_key(self) -> None:
        with pytest.raises(KeyFormatError):
            parse_api_key("btg_live_short")

    def test_rejects_non_string(self) -> None:
        with pytest.raises(KeyFormatError):
            parse_api_key(12345)  # type: ignore[arg-type]


class TestChecksum:
    def test_deterministic(self) -> None:
        canonical = "btg_live_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        assert compute_checksum(canonical) == compute_checksum(canonical)

    def test_format(self) -> None:
        checksum = compute_checksum("btg_live_x_y")
        assert len(checksum) == 4
        assert all(ch in ALPHABET for ch in checksum)

    def test_detects_single_character_change(self) -> None:
        canonical = "btg_live_9kQ2VxNmLpR7zT4w_8fJk2LmNpQrStUvWxYz3Aa5Bb7CcDdEe9fGh"
        original = compute_checksum(canonical)
        for position in (0, 5, 20, 40, len(canonical) - 1):
            altered = (
                canonical[:position]
                + ("A" if canonical[position] != "A" else "B")
                + canonical[position + 1 :]
            )
            assert compute_checksum(altered) != original, f"missed change at {position}"
