"""Tests for the CLI: argument handling and end-to-end command flows."""

from __future__ import annotations

import json

import pytest

from bitting.cli import main


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "cli.db")


class TestIssueAndVerify:
    def test_issue_then_verify(self, db, capsys) -> None:
        assert main(["--db", db, "issue", "--scopes", "read:users", "--description", "ci"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        assert raw_key.startswith("btg_live_")

        assert main(["--db", db, "verify", raw_key]) == 0
        out = capsys.readouterr().out
        assert "VALID" in out

    def test_verify_rejects_bad_key(self, db, capsys) -> None:
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        assert main(["--db", db, "verify", "btg_live_garbage"]) == 1
        assert "INVALID" in capsys.readouterr().out

    def test_verify_with_required_scope(self, db, capsys) -> None:
        assert main(["--db", db, "issue", "--scopes", "read:users"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        assert main(["--db", db, "verify", raw_key, "--require-scope", "read:users"]) == 0
        capsys.readouterr()
        assert main(["--db", db, "verify", raw_key, "--require-scope", "admin"]) == 1

    def test_issue_json_output(self, db, capsys) -> None:
        assert main(["--db", db, "--json", "issue", "--ttl", "30d"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["raw_key"].startswith("btg_live_")
        assert payload["expires_at"]

    def test_issue_uses_default_scrypt_cost(self, db, capsys) -> None:
        # Consolidation decision : the CLI must not silently
        # weaken the hash cost. Keys issued via `bitting issue` are hashed
        # with the library's default scrypt parameters (n=2^14), verified
        # here against the parameters actually persisted in the store.
        from bitting.storage import SQLiteStore

        assert main(["--db", db, "issue"]) == 0
        out = capsys.readouterr().out
        raw_key = out.splitlines()[0].split(":", 1)[1].strip()
        prefix = raw_key.split("_")[2]
        assert "library default cost" in out
        assert "n=16384" in out

        store = SQLiteStore(db)
        try:
            record = store.find_by_prefix(prefix)
            assert record is not None
            assert record.hash.startswith("$scrypt$n=16384$r=8$p=1$")
        finally:
            store.close()


class TestRotateAndRevoke:
    def test_rotate_flow(self, db, capsys) -> None:
        assert main(["--db", db, "issue", "--scopes", "read:x"]) == 0
        out = capsys.readouterr().out
        old_key = out.splitlines()[0].split(":", 1)[1].strip()
        prefix = old_key.split("_")[2]

        assert main(["--db", db, "rotate", prefix, "--grace", "1h"]) == 0
        new_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()

        # Old key still valid during grace, new key valid too.
        assert main(["--db", db, "verify", old_key]) == 0
        capsys.readouterr()
        assert main(["--db", db, "verify", new_key]) == 0

    def test_revoke_flow(self, db, capsys) -> None:
        assert main(["--db", db, "issue"]) == 0
        old_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        prefix = old_key.split("_")[2]
        assert main(["--db", db, "revoke", prefix]) == 0
        capsys.readouterr()
        assert main(["--db", db, "verify", old_key]) == 1

    def test_rotate_unknown_prefix_fails(self, db, capsys) -> None:
        assert main(["--db", db, "rotate", "unknownprefix123"]) == 1
        assert "error" in capsys.readouterr().err


class TestListAndEvents:
    def test_list_shows_keys_without_secrets(self, db, capsys) -> None:
        assert main(["--db", db, "issue", "--description", "svc-a"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        assert main(["--db", db, "list"]) == 0
        out = capsys.readouterr().out
        assert "svc-a" in out
        assert "active" in out
        assert raw_key not in out

    def test_list_json(self, db, capsys) -> None:
        assert main(["--db", db, "--json", "list"]) == 0
        assert json.loads(capsys.readouterr().out) == []

    def test_events_flow(self, db, capsys) -> None:
        assert main(["--db", db, "issue"]) == 0
        capsys.readouterr()
        assert main(["--db", db, "events"]) == 0
        assert "issued" in capsys.readouterr().out


class TestDurations:
    def test_ttl_duration_parsing(self, db, capsys) -> None:
        assert main(["--db", db, "--json", "issue", "--ttl", "12h"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["expires_at"] is not None

    def test_invalid_duration_fails(self, db, capsys) -> None:
        assert main(["--db", db, "issue", "--ttl", "soon"]) == 1
        assert "error" in capsys.readouterr().err


class TestUsageErrors:
    def test_unknown_command_exits_2(self, db) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--db", db, "explode"])
        assert excinfo.value.code == 2


class TestVerifyStdin:
    """Keys can be piped in instead of landing in shell history."""

    def test_verify_from_stdin_flag(self, db, capsys, monkeypatch) -> None:
        import io

        assert main(["--db", db, "issue"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        monkeypatch.setattr("sys.stdin", io.StringIO(f"  {raw_key}\n"))
        assert main(["--db", db, "verify", "--stdin"]) == 0
        assert "VALID" in capsys.readouterr().out

    def test_verify_with_dash_reads_stdin(self, db, capsys, monkeypatch) -> None:
        import io

        assert main(["--db", db, "issue"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        monkeypatch.setattr("sys.stdin", io.StringIO(raw_key))
        assert main(["--db", db, "verify", "-"]) == 0
        assert "VALID" in capsys.readouterr().out

    def test_verify_without_key_or_stdin_is_a_usage_error(self, db, capsys) -> None:
        assert main(["--db", db, "verify"]) == 2
        assert "error" in capsys.readouterr().err

    def test_stdin_strips_whitespace_and_newlines(self, db, capsys, monkeypatch) -> None:
        import io

        assert main(["--db", db, "issue"]) == 0
        raw_key = capsys.readouterr().out.splitlines()[0].split(":", 1)[1].strip()
        monkeypatch.setattr("sys.stdin", io.StringIO(f"\n\n{raw_key}\n\n"))
        assert main(["--db", db, "verify", "--stdin", "--require-scope", "nothing"]) == 1
        out = capsys.readouterr().out
        assert "INVALID" in out and "scope_missing" in out
