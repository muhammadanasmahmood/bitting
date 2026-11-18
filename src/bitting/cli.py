"""Command-line interface: issue, verify, rotate, revoke, and list keys.

Every command accepts ``--db`` (a SQLite path, default ``bitting.db``)
and ``--json`` for machine-readable output. ``verify`` accepts the key
as an argument, as ``-``, or via ``--stdin`` (recommended, so the key
never lands in shell history or process listings). Exit codes: 0 on
success, 1 on operational failure (not found, bad key, ...), 2 on
usage errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from typing import Any

from .errors import BittingError
from .hashing import ScryptHasher
from .manager import KeyManager
from .models import KeyRecord
from .storage import _SQLITE_MAX_INT, SQLiteStore
from .timeutil import parse_duration

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bitting",
        description="API key lifecycle management: issue, verify, rotate, revoke, list.",
    )
    parser.add_argument(
        "--db", default="bitting.db", help="SQLite database path (default: bitting.db)"
    )
    parser.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit machine-readable JSON"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # README documents "--json on every command". argparse does not
    # inherit top-level optionals, so `bitting issue --json` used to exit 2.
    # Register it on each subparser too; SUPPRESS keeps an absent flag from
    # overwriting a --json given before the subcommand.
    def _add_json_flag(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            default=argparse.SUPPRESS,
            help="Emit machine-readable JSON (also accepted before the command)",
        )

    p_issue = sub.add_parser("issue", help="Issue a new API key")
    p_issue.add_argument(
        "--scopes", default="", help="Comma-separated scopes, e.g. read:users,write:posts"
    )
    p_issue.add_argument("--description", default="", help="Free-form description")
    p_issue.add_argument("--ttl", default=None, help="Lifetime, e.g. 30d, 12h, 90 (seconds)")
    p_issue.add_argument("--env", default="live", help="Environment label (default: live)")

    p_verify = sub.add_parser("verify", help="Verify a raw API key")
    p_verify.add_argument(
        "key",
        nargs="?",
        default=None,
        help="The raw API key string, or '-' to read it from stdin",
    )
    p_verify.add_argument(
        "--stdin",
        action="store_true",
        help="Read the raw key from stdin (avoids the key landing in shell "
        "history or process listings)",
    )
    p_verify.add_argument(
        "--require-scope",
        action="append",
        default=[],
        dest="required_scopes",
        help="Scope the key must have (repeatable)",
    )

    p_rotate = sub.add_parser(
        "rotate", help="Rotate a key by prefix (old key stays valid during grace)"
    )
    p_rotate.add_argument("prefix", help="Prefix of the key to rotate")
    p_rotate.add_argument(
        "--grace", default="24h", help="Grace period for the old key (default: 24h)"
    )

    p_revoke = sub.add_parser("revoke", help="Revoke a key by prefix (immediate)")
    p_revoke.add_argument("prefix", help="Prefix of the key to revoke")

    p_list = sub.add_parser("list", help="List stored keys (prefixes and metadata, never secrets)")
    p_events = sub.add_parser("events", help="Show recent audit events")
    p_events.add_argument("--limit", type=int, default=20)

    for subparser in (p_issue, p_verify, p_rotate, p_revoke, p_list, p_events):
        _add_json_flag(subparser)

    return parser


def _scopes(text: str) -> list[str]:
    return [s.strip() for s in text.split(",") if s.strip()]


def _print(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        for key, value in payload.items():
            print(f"{key:>15}: {value}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        store = SQLiteStore(args.db)
    except BittingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        # Filesystem problems (parent path is a file, permission denied,
        # unreadable directory, ...) must exit cleanly, not traceback.
        print(f"error: cannot open database {args.db!r}: {exc}", file=sys.stderr)
        return 1

    # The CLI hashes at the library's default scrypt cost (n=2^14, ~16 MiB).
    # Issuing a key performs a single hash, so interactive use stays
    # snappy, and CLI-issued keys get the same offline-guessing resistance
    # as library-issued ones. Verification cost is governed by the
    # parameters stored with each key, not by this profile.
    hasher = ScryptHasher()
    manager = KeyManager(store, hasher=hasher, env=getattr(args, "env", "live"))

    try:
        if args.command == "issue":
            ttl: timedelta | None = None
            if args.ttl is not None:
                ttl = parse_duration(args.ttl)
            issued = manager.issue(
                scopes=_scopes(args.scopes),
                description=args.description,
                ttl=ttl,
            )
            _print(
                {
                    "raw_key": issued.raw_key,
                    "key_id": issued.key_id,
                    "prefix": issued.prefix,
                    "scopes": ",".join(sorted(issued.record.scopes)) or "(none)",
                    "expires_at": issued.record.expires_at.isoformat()
                    if issued.record.expires_at
                    else "never",
                    "hash": (
                        f"scrypt n={hasher.n} r={hasher.r} p={hasher.p} "
                        "(library default cost; see 'Tuning hash cost' in the README)"
                    ),
                    "note": "Store the raw key now; it cannot be recovered later.",
                },
                args.as_json,
            )
            return 0

        if args.command == "verify":
            raw_key = args.key
            if args.stdin or raw_key == "-":
                raw_key = sys.stdin.read().strip()
            if not raw_key:
                print(
                    "error: no key provided (pass it as an argument or via --stdin)",
                    file=sys.stderr,
                )
                return 2
            result = manager.verify(raw_key, required_scopes=args.required_scopes)
            payload = {
                "ok": result.ok,
                "reason": result.reason.value,
                "key_id": result.record.key_id if result.record else None,
                "prefix": result.record.prefix if result.record else None,
            }
            if result.missing_scopes:
                payload["missing_scopes"] = ",".join(sorted(result.missing_scopes))
            if not args.as_json:
                status = "VALID" if result.ok else f"INVALID ({result.reason.value})"
                payload = {"status": status, **{k: v for k, v in payload.items() if k != "ok"}}
            _print(payload, args.as_json)
            return 0 if result.ok else 1

        if args.command == "rotate":
            issued = manager.rotate(args.prefix, grace=parse_duration(args.grace))
            _print(
                {
                    "raw_key": issued.raw_key,
                    "new_prefix": issued.prefix,
                    "rotated_prefix": args.prefix,
                    "key_id": issued.key_id,
                    "note": "The old key keeps working until the grace window closes.",
                },
                args.as_json,
            )
            return 0

        if args.command == "revoke":
            record = manager.revoke(args.prefix)
            _print(
                {
                    "revoked_prefix": record.prefix,
                    "key_id": record.key_id,
                    "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
                },
                args.as_json,
            )
            return 0

        if args.command == "list":
            keys = manager.list_keys()
            if args.as_json:
                print(json.dumps([record.to_json() for record in keys], indent=2))
            else:
                if not keys:
                    print("No keys stored.")
                for record in keys:
                    state = _describe_state(record)
                    scopes = ",".join(sorted(record.scopes)) or "-"
                    description = record.description or "-"
                    print(f"{record.prefix}  {state:<22}  scopes={scopes}  desc={description}")
            return 0

        if args.command == "events":
            # argparse's type=int accepts any Python int; guard the range
            # (shared bound with the stores) before it reaches SQL so the
            # user sees the clean "error:" line instead of a traceback.
            if args.limit < 1 or args.limit > _SQLITE_MAX_INT:
                print(f"error: --limit must be between 1 and {_SQLITE_MAX_INT}", file=sys.stderr)
                return 1
            events = manager.list_events(limit=args.limit)
            if args.as_json:
                print(json.dumps([event.to_json() for event in events], indent=2))
            else:
                if not events:
                    print("No events recorded.")
                for event in events:
                    at = event.at.isoformat()
                    print(f"{at}  {event.kind.value:<14}  {event.prefix}  {event.detail}")
            return 0

        raise BittingError(f"unknown command: {args.command}")  # pragma: no cover
    except BittingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        store.close()


def _describe_state(record: KeyRecord) -> str:
    if record.revoked_at is not None:
        return "revoked"
    if record.rotated_at is not None:
        return "rotated"
    if record.is_expired():
        return "expired"
    return "active"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
