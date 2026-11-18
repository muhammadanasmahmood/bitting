# bitting

**API key lifecycle management for Python — generation, memory-hard hashing, prefix-indexed storage, rotation with grace periods, scopes, TTL, revocation, audit events, a CLI, and an optional FastAPI integration. Zero required dependencies.**

> *Bitting* is the locksmithing term for the unique pattern of cuts that makes one key fit exactly one lock.

[![CI](https://github.com/muhammadanasmahmood/bitting/actions/workflows/ci.yml/badge.svg)](https://github.com/muhammadanasmahmood/bitting/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://github.com/muhammadanasmahmood/bitting)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230)](https://github.com/astral-sh/ruff)
[![PyPI](https://img.shields.io/pypi/v/bitting.svg)](https://pypi.org/project/bitting/)

---

## The problem

Almost every service with machine-to-machine access needs API keys, and almost every team hand-rolls the same system — usually badly:

- keys stored **in plaintext** in the database (a single SQL dump leaks every credential),
- verification by **full-table scans** (`SELECT * FROM keys` then compare in Python),
- fast hashes (SHA-256, or worse, none) that let an attacker with the database test **billions** of key guesses per second on a GPU,
- **no rotation story**, so keys live forever and get shared between services,
- no scopes, no expiry, no audit trail.

The existing options tend to be either trivial header-checkers that compare against keys sitting in environment variables, or heavyweight vendor platforms that require external services. The middle ground — a focused, self-contained, well-engineered library — is what bitting provides.

## What bitting does differently

| Concern | Common hand-rolled approach | bitting |
|---|---|---|
| Storage | Plaintext key in a column | Only a **memory-hard hash** is stored (scrypt default, Argon2id optional) |
| Lookup | Full table scan | **Prefix-indexed**: a 16-char public prefix is the lookup key |
| Format | `uuid4()` — no typo detection, no environment label | `btg_live_<prefix>_<secret>_<checksum>` with a transcription-error checksum |
| Rotation | None (or "delete and hope") | New key issued; old key keeps working through a **grace window** (capped by the key's original expiry), then is rejected |
| Scopes | Boolean "is admin" | String scopes with `read:*` wildcards and precise `missing_scopes` reporting |
| Expiry | Never | TTL or absolute expiry, verified per request |
| Revocation | DELETE the row (loses history) | `revoked_at` timestamp; history and audit trail retained |
| Observability | None | Every lifecycle action emits an **audit event** (stored + optional callback) |
| Failure detail | `401 unauthorized` | `VerifyReason` enum: `invalid_format`, `not_found`, `hash_mismatch`, `expired`, `revoked`, `rotated`, `rotated_grace`, `scope_missing` |

### Design decisions worth knowing

- **scrypt from the standard library is the default hasher.** No compiled dependencies, yet memory-hard (default cost: 16 MiB per hash). If the database leaks, offline guessing is expensive instead of trivial. Argon2id is available via the optional `argon2` extra (see below).
- **The prefix is public by design** (the same trade-off as Stripe-style keys): an attacker who steals the store learns *which prefixes exist* but cannot reconstruct any key. Verification cost is one indexed lookup plus one hash — constant as your key count grows. (`last_verified_at` persistence is throttled to once per interval; see Configuration.)
- **Malformed keys are rejected before touching the store**, so junk traffic cannot be turned into database load.
- **The checksum is not a security feature.** It catches typos when a human copies a key; it is documented as such and never trusted as an integrity control.
- **Raw keys exist exactly once** — at issue time. `IssuedKey.__repr__` is redacted so secrets cannot leak into logs by accident.

## Installation

Install from PyPI:

```bash
pip install bitting
```

Optional extras:

```bash
pip install 'bitting[fastapi]'    # FastAPI integration
pip install 'bitting[argon2]'     # Argon2id hasher
```

Or install the development version directly from GitHub:

```bash
pip install git+https://github.com/muhammadanasmahmood/bitting.git
```

Extras with direct-reference syntax (works with pip 21.3+):

```bash
pip install 'bitting[fastapi] @ git+https://github.com/muhammadanasmahmood/bitting.git'   # FastAPI integration
pip install 'bitting[argon2] @ git+https://github.com/muhammadanasmahmood/bitting.git'    # Argon2id hasher
```

Or from a local clone of this repository, where the short forms apply:

```bash
pip install '.[fastapi]'    # FastAPI integration
pip install '.[argon2]'     # Argon2id hasher
pip install '.[dev]'        # pytest, ruff, mypy (for contributors)
```

## Quick start

```python
from datetime import timedelta

from bitting import KeyManager, SQLiteStore

manager = KeyManager(SQLiteStore("api-keys.db"))

# Issue a key (the raw key is shown exactly once — ever)
issued = manager.issue(
    scopes={"read:users", "write:posts"},
    description="ci-runner",
    ttl=timedelta(days=30),
)
print(issued.raw_key)  # btg_live_9kQ2VxNmLpR7zT4w_...
print(issued.prefix)  # safe to display and store

# Verify on every request
result = manager.verify(raw_key, required_scopes={"read:users"})
if result.ok:
    ...
elif result.reason.value == "scope_missing":
    ...  # 403, with result.missing_scopes
else:
    ...  # 401

# Rotate without downtime: old key works for 24h, then dies
new = manager.rotate(issued.prefix, grace=timedelta(hours=24))

# Revoke immediately
manager.revoke(new.prefix)
```

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                          Your application                       │
│      (FastAPI dependency · CLI · plain library calls)          │
└───────────────┬────────────────────────────────────────────────┘
                │
        ┌───────▼────────┐   issue / verify / rotate / revoke
        │   KeyManager   │──────────────┐
        └───┬───────┬────┘              │  audit events
   keys.py  │       │ hashing.py        ▼
 (generate, │       │ (scrypt /    ┌─────────────┐
   parse,   │       │  Argon2id)   │ AuditEvent  │──▶ optional callback
 checksum)  │       └──────────────└─────────────┘
            ▼
     ┌──────────────┐  KeyStore protocol
     │  KeyStore    │◀──── InMemoryStore (tests, prototypes)
     │ (SQLite WAL) │◀──── SQLiteStore (durable, thread-safe)
     └──────────────┘◀──── your adapter (Postgres, Redis, ...)
```

Layers and responsibilities:

- **`keys.py`** — key format: generation with rejection-sampled base62 entropy, parsing, and the CRC32-based transcription checksum.
- **`hashing.py`** — the `Hasher` protocol, `ScryptHasher` (stdlib, default), `Argon2Hasher` (optional). Self-describing encoded hashes (`$scrypt$n=16384$r=8$p=1$…`) mean parameters can be tuned per deployment without invalidating existing keys: parameters matching the active configuration are always accepted, and stored work is bounded to 4× the active profile's work (with the documented default profile as the floor) — keys issued at the default cost keep verifying on any cheaper deployment, while a drastic downgrade beyond 4× of the active profile retires old heavier keys.
- **`storage.py`** — the `KeyStore` protocol plus `InMemoryStore` and `SQLiteStore` (WAL mode, `BEGIN IMMEDIATE` transactions, a process-wide lock for thread safety, and a schema-version guard).
- **`manager.py`** — the lifecycle orchestrator: issue, verify (with the full reason state machine), rotate with grace, revoke, and audit dispatch.
- **`models.py`** — `KeyRecord`, `IssuedKey` (redacted repr), `VerifyResult`/`VerifyReason`, `AuditEvent`.
- **`integrations/fastapi.py`** — optional dependency builder with precise 401/403 semantics.

## Technology stack

- **Python 3.10+**, standard library only for the core (`secrets`, `hashlib.scrypt`, `sqlite3`, `argparse`, `dataclasses`).
- **Optional**: `argon2-cffi` (Argon2id), `fastapi` (integration).
- **Toolchain**: pytest, ruff (lint + format), mypy `--strict`, pip-audit, GitHub Actions CI.

## Configuration

```python
KeyManager(
    store=SQLiteStore("api-keys.db"),  # or InMemoryStore(), or your own
    hasher=ScryptHasher(n=2**14),  # default; raise for more resistance
    env="live",  # label embedded in keys ("test", ...)
    now_fn=my_clock,  # injectable clock (testing)
    on_event=send_to_audit_log,  # synchronous callback per action
    hashers={"argon2id": Argon2Hasher()},  # verify keys hashed with other algorithms
    verify_touch_interval=timedelta(seconds=60),  # throttle last_verified_at writes
    audit_verifications=True,  # set False to skip verify-time audit events
)
```

**Switching hashers.** Verification dispatches on the algorithm stored with each key (scrypt/Argon2id hashes are self-describing), so tuning cost parameters never invalidates existing keys. When you switch *algorithms* — e.g. scrypt → Argon2id — pass the old hasher in `hashers={...}` and existing keys keep verifying while new keys are hashed with the primary hasher. Keys whose algorithm has no registered hasher fail closed with `hash_mismatch`.

**Verification write load.** Successful verifications update `last_verified_at` in the returned record, but persist it at most once per `verify_touch_interval` (default 60 s; `timedelta(0)` restores write-on-every-verify). The persisted touch is a single-field update (`KeyStore.mark_verified`) and never rewrites lifecycle columns, so it cannot race with a concurrent revoke or rotate. Verify-time audit events (`verified` / `verify_failed`) can be disabled with `audit_verifications=False`; lifecycle events (issued/rotated/revoked) are always recorded. Audit history can be bounded with `manager.prune_events(before=...)`.

Tuning hash cost: the default scrypt parameters (n=2^14, r=8, p=1 ≈ 16 MiB) verify in roughly 50–100 ms on typical server hardware. That is the right ballpark for human-issued keys; it makes online brute-force through your API impractical and offline attacks on a stolen database expensive. If you issue thousands of keys per second in batch tooling, lower the cost deliberately — and document that you did. The scrypt memory limit is derived from your parameters (any consistent configuration up to 1 GiB works — except `r=1` with `n ≥ 2^16`, which OpenSSL rejects at hash time regardless of `maxmem`, so construction fails fast with a clear error; beyond the ceiling, construction is likewise refused).

## CLI

```console
$ bitting --db api-keys.db issue --scopes "read:users,write:posts" --ttl 30d
       raw_key: btg_live_9kQ2VxNmLpR7zT4w_8fJk2LmNpQrStUvWxYz3Aa5Bb7CcDdEe9fGh_5K3m
        key_id: 6a1f...
        prefix: 9kQ2VxNmLpR7zT4w
        scopes: read:users,write:posts
    expires_at: 2026-12-16T17:49:27+00:00
           note: Store the raw key now; it cannot be recovered later.

$ echo "$KEY" | bitting --db api-keys.db verify --stdin --require-scope read:users
        status: VALID

$ bitting --db api-keys.db rotate 9kQ2VxNmLpR7zT4w --grace 24h
$ bitting --db api-keys.db revoke 9kQ2VxNmLpR7zT4w
$ bitting --db api-keys.db list
$ bitting --db api-keys.db events
```

All commands support `--json` for scripting. Exit codes: `0` success, `1` operational failure, `2` usage error. `verify` accepts the key as an argument, as `-`, or via `--stdin` (recommended — it keeps the key out of shell history and process listings). The CLI hashes at the library's default scrypt cost (`n=2^14`), so CLI-issued keys have the same offline-guessing resistance as library-issued ones; the cost profile is printed at issue time, and verification cost is always governed by the parameters stored with each key.

## FastAPI integration

```python
from fastapi import Depends, FastAPI

from bitting import KeyManager, SQLiteStore
from bitting.integrations.fastapi import APIKeyAuth
from bitting.models import KeyRecord

app = FastAPI()
auth = APIKeyAuth(KeyManager(SQLiteStore("api-keys.db")))


@app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
async def list_users():
    return {"users": ["alice", "bob"]}


@app.get("/me")
async def me(record: KeyRecord = Depends(auth.require())):
    return {"prefix": record.prefix, "scopes": sorted(record.scopes)}
```

Authentication failures return `401` (with `WWW-Authenticate: ApiKey`); missing scopes return `403` naming the missing scopes. Both `X-API-Key: <key>` and `Authorization: Bearer <key>` styles are supported. Key issuance is deliberately **not** exposed as an HTTP route — minting keys belongs to trusted operator tooling, not to request handlers.

## Testing

```bash
pip install -e '.[dev,fastapi,argon2]'
pytest                 # 396 tests
ruff check src tests examples
ruff format --check src tests examples
mypy                   # strict mode
```

The suite covers: key format and checksum properties (including single-character tamper detection), both hashers (including one test at full production scrypt cost and one above the old 256 MiB memory cap), parameter-bound hardening against crafted stored hashes, both stores (including persistence, WAL mode, 40 concurrent saves across 8 threads, record isolation, and atomic rotation claims), the full manager lifecycle state machine (including the expiry-capped grace window and deterministic concurrent-rotation races), the audit trail (including throttling controls and pruning), the CLI (issue → verify → rotate → revoke → list → events, JSON output, and stdin key input), and the FastAPI integration (401/403 semantics in both auto_error modes, bearer mode, record injection).

## Deployment

- **Single process**: `SQLiteStore` is the intended default — WAL mode, thread-safe, zero infrastructure.
- **Multiple processes on one host**: point every process at the same SQLite file; SQLite's file locking coordinates writers. Put the database on local disk (not NFS), and expect write serialization — fine for key operations, which are rare compared to verifications. Cache verification results if request volume is high.
- **Distributed**: implement the five-method `KeyStore` protocol against your database of choice (Postgres is a natural fit — a prefix-indexed table with the same columns). The protocol is deliberately small so adapters stay thin.
- **Key rotation drill**: rotate on a schedule, keep the grace window shorter than your monitoring window for "old key still in use" alerts, and treat `rotated_grace` verifications as a signal to chase lingering clients.

## Security considerations

- **Threat model**: bitting protects keys *at rest* (memory-hard hashes, no plaintext anywhere after issue) and *in verification* (constant-time digest comparison, prefix-indexed lookups, parse-before-lookup). It does not protect a compromised application process — an attacker inside your process can hijack verification regardless of storage format.
- **Stored-hash parameters are bounds-checked and work-budgeted.** A crafted store record (requires write access to the database, which is outside bitting's threat model) can only select in-bounds parameters: memory is hard-capped by the hasher's configured `maxmem`, scrypt *CPU* per verification is bounded by a total-work budget (`n×r×p` ≤ 4× the active profile, default profile as the floor), and Argon2id carries a total-work cap (`t×m ≤ 2²³`, ~60× — a tighter argon2 budget is a deployment decision). Parameters matching the hasher's own configuration are always accepted.
- **Store the raw key where you store passwords**: a secrets manager at issue time. It cannot be recovered from bitting.
- **Transit is your responsibility**: keys must only travel over TLS.
- **The checksum catches typos, not attackers.** A tampered secret with a recomputed checksum parses fine — and is then rejected by hash verification.
- **Environment labels (`live`, `test`) are not a security boundary** — they are an operational aid. A `btg_test_...` key verifies if its prefix is in the store; use separate stores for separate environments.
- See [SECURITY.md](SECURITY.md) for how to report vulnerabilities.

## Roadmap

- [ ] Async store variants (`AsyncKeyStore`) for fully-async verification paths
- [ ] Optional pepper support in both hashers
- [ ] SQLAlchemy/PostgreSQL adapter in a companion package
- [ ] Verification-result caching helper (TTL-bounded, with revocation hooks)
- [x] PyPI publication — bitting is [on PyPI](https://pypi.org/project/bitting/) since 1.2.0

## Limitations

- The core API is synchronous. (FastAPI runs sync dependencies in a thread pool, so the integration works fine; a native async path is on the roadmap.)
- `SQLiteStore` serializes writes in-process by design; very high write concurrency needs a database server behind a custom `KeyStore`.
- No built-in rate limiting of verification attempts — pair with your normal API rate limiting (the memory-hard default cost already makes online guessing expensive).
- Key records hold one hash; concurrent rotation of the same key from two threads or processes is safe with the built-in stores (the active→rotated transition is an atomic conditional update — `KeyStore.mark_rotated`). Custom stores should implement `mark_rotated` atomically to keep that guarantee; the base-class fallback is non-atomic.
- Revocation is equally atomic and idempotent (`KeyStore.mark_revoked`): concurrent revoke-vs-rotate cannot erase lifecycle state, and revoking twice keeps the first (authoritative) `revoked_at` while logging the repeat. Custom stores should implement `mark_revoked` the same targeted way.
- **Custom stores must implement `mark_verified` (and `mark_rotated` / `mark_revoked`) as targeted, atomic updates.** The built-in stores do; the *fallback* used when a store lacks them is a non-atomic read-modify-write, and under a concurrent lifecycle change it can lose a revocation — **a revoked key can then verify again** until the next lifecycle write. Stores that only implement the original five-method protocol are supported for compatibility, not for production use.
- `list_keys()` loads every record: ~0.09 ms per key (~11 s and ~0.4 GB of process memory at one million keys on the benchmark hardware). For large stores, prefer `find_by_prefix` lookups in tooling.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every PR must keep `pytest`, `ruff`, and `mypy --strict` green.

## Contributors

- **[Muhammad Anas Mahmood](https://github.com/muhammadanasmahmood)** — Project Owner & Maintainer · architecture, releases, and repository stewardship
  · <anasmahmood2917@gmail.com> · Karachi, Pakistan

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for roles and how contributions are credited.

## License

[MIT](LICENSE) © Muhammad Anas Mahmood

- **Bound what you store in metadata and how many scopes you grant.** `issue()` accepts any JSON-serializable metadata and any number of valid scopes; a 10 MB metadata blob or a 100k-scope key is accepted today and stored whole, and `verify()` cost grows with the product of granted×required scopes (`missing_scopes` is O(granted × required) — 100k×100 ≈ 1 s). Cap sizes and counts at the application layer before they reach the library.
