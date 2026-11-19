# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.2] - 2026-11-19

### Fixed

- **Robustness and input-validation hardening** — six defects, each with
  a regression test in `tests/test_regressions.py` that fails on the
  pre-fix code:
  - **Legacy-schema rows raise `StorageError`** (was a raw `IndexError`):
    a database whose `keys` table was written by an older schema (e.g.
    missing `last_verified_at`, or even `prefix`) now fails with the
    documented `StorageError("corrupted key record ...")` on
    `find_by_prefix`/`list_keys` instead of leaking `sqlite3.Row`'s
    "No item with that key".
  - **`list_events(limit=...)` validates its range**: limits above
    SQLite's signed-64-bit maximum previously leaked a raw
    `OverflowError` from the driver; both stores now raise
    `ValueError` (consistent with the existing `limit < 1` guard), and
    the CLI `events --limit` prints its clean `error:` line (exit 1)
    instead of a traceback.
  - **`KeyManager` validates its clock at construction**: a `now_fn`
    that is not callable, returns a non-datetime, or returns *naive*
    datetimes is now rejected with `ConfigurationError`. Previously a
    naive clock was accepted and later exploded inside `verify()` as a
    `TypeError` — violating the documented "verify never raises for a
    bad key" contract.
  - **`verify_touch_interval` type validated at construction**
    (`timedelta` expected; `None`/`int` now fail fast instead of
    raising `TypeError` at the first verification).
  - **`issue()` rejects non-string metadata keys anywhere in the
    (nested) mapping**: JSON object keys are strings, and non-string
    keys round-tripped differently across stores (`{1: 'a'}` in memory
    vs `{'1': 'a'}` in SQLite). Now a `ValueError` naming the offending
    path.
  - **Stored (non-own-config) Argon2id hashes are memory-capped**:
    crafted records could previously demand up to ~1 GiB per
    verification (the total-work cap alone admitted `m=1 GiB, t=7`).
    Stored-parameter memory is now capped at 256 MiB — mirroring
    scrypt's `maxmem` — while a hasher's *own* configuration is exempt
    at any memory cost, and the RFC 9106 second-recommended profile
    (`m=256 MiB, t=3`) keeps verifying. Measured: the crafted
    1 GiB record went from a 5.4 s KDF run to a pre-KDF rejection.
  - Regression tests also pin that revoked, expired and
    rotated-out-of-grace keys are denied **before** the KDF runs (a
    previously untested cost property).
- **`ScryptHasher` rejects `r=1` with `n >= 2^16` at construction**: these
  in-bounds, under-ceiling configurations were accepted but every `hash()`
  call raised a raw OpenSSL `ValueError` ("memory limit exceeded")
  regardless of `maxmem` (reproduced for `n = 2^16 .. 2^22`; `r >= 2` works
  throughout the documented range). Construction now fails fast with a
  `ConfigurationError` naming the remedy; `r=1` below `2^16` and `r >= 2`
  everywhere are unaffected, and the default profile is untouched. Regression
  tests in `tests/test_hardening_regressions.py` (fail on the unfixed
  behavior, pass on the fix). README and SECURITY.md now state the exception
  precisely.
- **Constructing a `KeyManager` over a legacy (duck-typed) store now warns
  loudly**: a store without `mark_verified`/`mark_rotated`/`mark_revoked`
  used to accept the non-atomic read-modify-write fallback silently, and a
  concurrent revocation could be lost (a revoked key verifying again). The
  fallback itself is kept for backwards compatibility, but a one-time
  `UserWarning` is emitted at construction, and accepting the documented
  risk now requires explicitly setting
  `bitting.manager.LEGACY_STORE_WARNING = False`. New module-level export
  `LEGACY_STORE_WARNING`. SECURITY.md documents the behavior.
- **README limitations state metadata-size and scope-count caller
  responsibilities**: `issue()` accepts any JSON-serializable metadata
  and any number of valid scopes (a 10 MB metadata blob or a 100k-scope key is
  stored whole), and `missing_scopes` is O(granted x required) — cap sizes and
  counts at the application layer.
- **`rotate()` rejects already-expired keys** instead of minting a successor
  with a grace window on a dead credential: rotation now raises `ValueError`
  ("key is expired; issue a new key instead") when the key's TTL has passed.
- **`ParsedKey.__repr__` redacts the secret** (only `prefix`/`env`/`scheme`
  and the secret's length appear), so a debugger or an unlucky `%r` log line
  can never print the live credential. Regression tests in
  `tests/test_release_hardening.py`.
- CHANGELOG date for 1.2.0 corrected to 2026-11-17.

## [1.2.0] - 2026-11-17

Security-focused release. Every confirmed hardening item below is fixed with
a deterministic regression test; the suite grew from 180 to 396 tests, and
ruff, mypy --strict, and the sdist/wheel builds stay clean. New API is
additive only: `KeyStore.mark_revoked`, the public
`bitting.validate_scopes` helper, and `pytest-cov` in the `dev` extra.

### Lifecycle, hashing, and packaging hardening

#### Fixed

- **`ScryptHasher` no longer issues permanently-unverifiable keys**:
  construction accepted parameters (`r > 64`, `p > 64`, `n > 2^22`) that the
  stored-hash sanity bounds in `verify()` reject outright, so keys hashed
  with such a hasher failed every verification with `hash_mismatch` forever
  ("bricked keys" — reproduced with `ScryptHasher(r=128)` and
  `ScryptHasher(p=65)`, which constructed and hashed fine but never
  self-verified). Construction now rejects parameters outside the
  verification bounds with a clear error, and `verify()` accepts parameters
  equal to the hasher's own configuration unconditionally (mirroring
  `Argon2Hasher`), so every legitimately constructible hasher keeps verifying
  its own keys — including in-bounds heavy configurations — and cost
  upgrades/downgrades keep old keys working.
- **`revoke()` can no longer erase a concurrently claimed rotation**:
  revocation performed a non-atomic read-modify-write full-record `save()`;
  a revoke racing a rotate wrote a stale snapshot back and erased
  `rotated_at`/`grace_until` (deterministically reproduced with a gated
  store). Revocation now goes through the new
  `KeyStore.mark_revoked(prefix, at=...)` — a targeted conditional
  `UPDATE keys SET revoked_at=? WHERE prefix=? AND revoked_at IS NULL`
  inside `BEGIN IMMEDIATE` for SQLite (atomic across threads and processes)
  and a lock-guarded replacement for the in-memory store. As a consequence,
  revocation is now **idempotent**: revoking an already-revoked key keeps the
  first (authoritative) `revoked_at` timestamp and records the repeated
  attempt in the audit trail with an `already_revoked` detail flag
  (previously the timestamp was silently overwritten). Duck-typed stores
  without `mark_revoked` fall back to the previous behavior, documented as
  non-atomic.
- **`Argon2Hasher` no longer issues permanently-unverifiable keys** (the
  same defect class as the scrypt one above): construction accepted
  parameters whose stored form `verify()` rejects unconditionally
  (`parallelism > 64`, `memory_cost > 2^20 KiB`, `time_cost > 2^16` — e.g.
  `Argon2Hasher(parallelism=65)` hashed fine and never verified).
  Construction now enforces the same sanity bounds, and the
  own-configuration exemption in `verify()` covers all bounds (previously it
  exempted only the strict total-work caps), mirroring `ScryptHasher`.
- **FastAPI `require()` rejects bare-string scopes**: a bare string silently
  became a set of single characters (`"read:users"` -> `{'r','e','a',...}`),
  matching nothing sensible while appearing configured. It now raises
  `ValueError` at setup, consistent with `KeyManager`'s scope validation.
- **`revoke()` drops a redundant store read**: the `KeyNotFoundError`
  contract is preserved by the post-transition re-read.
- **FastAPI `require()` validates scopes at setup time**: malformed scope
  strings (empty, whitespace-containing, non-string) in a route's
  `require(scopes=...)` raised `ValueError` inside the request handler — a
  500 on every request. They now raise at dependency-construction time, so
  the application fails fast at startup instead.
- **sdist ships a runnable test suite**: `tests/conftest.py` was missing from
  the source distribution (setuptools' default sdist list includes only
  `tests/test*.py`), so `pytest` on an unpacked sdist failed at collection.
  A `MANIFEST.in` now includes `conftest.py` plus the operator-facing docs
  (CHANGELOG, SECURITY, CONTRIBUTING, CONTRIBUTORS) and the examples.
- **README corrections**: the documented test count was stale; the
  limitations section now states the custom-store fallback consequence
  explicitly (a store without `mark_verified` can lose a concurrent
  revocation — a revoked key may verify again) and records the `list_keys()`
  scaling characteristics.

#### Added

- `KeyStore.mark_revoked(prefix, at=...)` protocol method (see above); both
  built-in stores implement it atomically.
- `tests/test_hardening_regressions.py` — regression tests for every item
  above, plus two suite-gap tests from mutation testing: a chi-square
  statistical-uniformity test for the base62 generator (a modulo-bias
  mutation previously survived the entire suite) and
  constant-time-comparison wiring tests for both hashers (replacing
  `hmac.compare_digest` with `==` previously survived).
- A test pinning the documented residual risk of the legacy five-method
  store fallback: a verification touch racing a revocation on such a store
  can resurrect the revoked key. This cannot be fixed generically without
  store cooperation; the limitation is now stated explicitly in README and
  SECURITY.md instead of being implied.

#### Security notes (no behavior change)

- Measured crafted-stored-hash envelope, now documented precisely in
  SECURITY.md and README: with store-write access (outside the documented
  threat model) an attacker can select in-bounds KDF parameters per record —
  memory stays hard-capped by the configured `maxmem`, but scrypt CPU per
  verification could reach ~100-150x the configured cost (via `p <= 64`) and
  Argon2id ~60x (total-work cap). *(Superseded for scrypt by the total-work
  budget below: scrypt CPU is now bounded at 4x.)*

#### Further hardening (follow-up fixes)

##### Fixed

- **A credential revoked, expired, rotated out of grace, deleted or
  scope-narrowed while its verification's KDF was running no longer
  authorizes**: the verdict previously came from the pre-hash snapshot, so
  the in-flight request returned `ok` even though the revocation had already
  committed. Verification now re-reads the record and the clock *after* the
  KDF and re-checks lifecycle state before authorizing; the extra cost is
  one indexed lookup on the success path only. This shrinks — but cannot
  eliminate — the check-then-act window; applications needing a hard
  guarantee must serialize revocation against authorization at a higher
  layer.
- **Crafted scrypt stored hashes are now bounded by a total-work budget**:
  `n x r x p` of a stored record may not exceed 4x the active profile's work
  (with the documented default profile's work as the floor), so a record
  like `n=131072,r=2,p=64` (~67x default, ~4 s per verify, measured) is
  rejected before the KDF instead of burning CPU on every verification.
  Parameters matching the hasher's own configuration are always accepted,
  and the default-work floor keeps keys issued at the documented default
  verifiable on cheaper deployments. Keys issued under a profile more than
  4x heavier than the active one stop verifying after a drastic config
  downgrade — the deliberate trade that closes the crafted-CPU envelope
  noted above.
- **`SQLiteStore("~/keys.db")` works**: `~` was expanded for the parent
  directory but not the connection path, so the store created directories
  under `$HOME` and then failed to open the literal `~/keys.db`.
- **`bitting <command> --json` works**: `--json` was only accepted before
  the subcommand; after it, argparse exited 2, contradicting the README.
  The flag is now registered on every subparser too.
- **`InMemoryStore.mark_verified` deep-copies metadata**: nested containers
  were previously re-aliased to the stored record (`dict()` copy).
- **`from_iso` accepts a trailing `Z`/`z` on every supported Python**:
  `datetime.fromisoformat` only accepts `Z` from Python 3.11, so a row
  written by an external tool with a `Z` suffix loaded on 3.11+ and raised
  on 3.10.
- **Encoded-hash parameter parsing is canonical-only**: scrypt parameters
  must be plain digits with the exact `n=`/`r=`/`p=` names (previously
  `n=+256`, `n=1_024`, `n=256=999`, `n= 256` and renamed keys were all
  parsed and honored), and Argon2id accepts exactly the three canonical
  `m`/`t`/`p` parameters, each once (previously a later duplicate key
  silently overrode an earlier value).
- **Duplicate credential headers fail closed**: the header lookup returned
  the first occurrence, so a request carrying both a valid and an invalid
  key authenticated when the valid one happened to be listed first. An
  ambiguous credential is now refused outright (401).
- **`issue()` retries on a prefix collision instead of silently
  overwriting**: `store.save()` is an upsert, so a colliding prefix would
  have replaced an existing credential. The prefix is now checked before
  saving and redrawn (astronomically unlikely, but the failure mode is
  credential replacement).
- **Hasher constructors require integral parameter types**: a float `n`
  previously raised a raw `TypeError` from the power-of-two check, a float
  `dklen` or Argon2id `time_cost` constructed fine and failed at hash time,
  and a bool was silently accepted (`True == 1`). All parameters now fail
  fast with `ConfigurationError` at construction.
- **Metadata must be JSON-serializable, and SQLite no longer stringifies
  what is not**: `issue()` previously accepted any metadata; the SQLite
  layer serialized it with `json.dumps(default=str)`, silently turning
  non-JSON values into strings while `InMemoryStore` kept the live object —
  the same key round-tripped differently per store. `issue()` now rejects
  non-JSON metadata with a clear `ValueError`, and the SQLite serialization
  no longer coerces.

##### Added

- **`bitting.validate_scopes`** — the scope normalization/validation helper
  used by `KeyManager` and the FastAPI integration is now public, so
  applications can validate configured scopes the same way the library
  does.
- **`pytest-cov` is declared in the `dev` extra**, so the documented
  coverage workflow works for contributors out of the box.

##### Tests

- `tests/test_concurrency_regressions.py` — 64 concurrency tests
  (including a real two-OS-process revoke/rotate interleaving against a
  WAL-mode SQLite file), adapted to the idempotent `mark_revoked(at=)`
  semantics.
- `tests/test_storage_regressions.py` — 20 storage tests plus a
  both-stores metadata round-trip equivalence test.

### Security hardening

#### Fixed

- **Concurrent first-open of a fresh SQLite store no longer crashes** (found
  by the CI matrix on 3.10/3.11/3.13): `PRAGMA journal_mode=WAL` requires an
  exclusive lock and SQLite returns `SQLITE_BUSY` for that statement
  *without* invoking the busy handler — so several processes opening the
  same fresh database file simultaneously (multi-worker service boot, the
  multiprocess contention test) crashed with `StorageError: database is
  locked`. The open path now retries the journal-mode switch for a bounded
  ~2 s before failing; once any opener completes the switch, WAL is
  persistent and every other opener converges. Regression:
  `test_concurrent_first_open_sqlite` (12 barrier-synchronized processes x 3
  fresh files).
- **Concurrent verification can no longer resurrect revoked or rotated
  keys**: the throttled `last_verified_at` touch was persisted with a
  full-record `save()` of a snapshot read *before* the expensive hash
  check. A verification in flight while an operator revoked (or rotated) the
  same key wrote the stale snapshot back, permanently erasing
  `revoked_at`/`rotated_at`/`grace_until` — the "revoked" key kept
  authenticating indefinitely, and a rotated key became permanently active
  alongside its successor. Touches now go through the new
  `KeyStore.mark_verified()` (a targeted single-`last_verified_at`-column
  update in SQLite, atomic under the store lock in memory; single-column
  `UPDATE ... WHERE prefix=?`). Duck-typed stores without `mark_verified`
  fall back to a re-read that alters only the timestamp (documented
  non-atomic, matching the `mark_rotated` precedent).
- **Hashers no longer raise on non-string stored hashes**:
  `ScryptHasher.verify(raw, None)` (or any non-string `encoded`) raised
  `AttributeError`/`TypeError` instead of returning `False`, crashing the
  request path when a store returned a corrupt record. Both hashers now fail
  closed. `KeyManager` additionally catches a raising hasher (corrupted
  record or broken custom hasher) and returns `hash_mismatch`, recording
  the exception class in the audit detail.
- **Crafted Argon2id stored hashes can no longer force multi-minute KDF
  runs**: the per-parameter sanity bounds (t <= 2^16, m <= 1 GiB) admitted
  combinations like t=1024 x m=256 MiB, measured at ~170 s CPU and 256 MiB
  per verification — a denial-of-service vector for anyone able to write a
  store record, contradicting the 1.1.0 hardening goal. Verification now
  also enforces a total-work bound (t x m <= 2^23 KiB-passes and t <= 4096)
  for stored parameters, while always accepting parameters equal to the
  hasher's own configuration so deliberately heavy deployments keep
  verifying their own keys.
- **Salt/digest lengths from stored hashes are capped**: both hashers now
  reject stored salts or digests longer than 512 bytes before any allocation
  or KDF work (construction validates the same range for
  `salt_length`/`dklen`/`hash_length`, so self-produced hashes always
  verify). Closes the oversized-base64 allocation vector.
- **`issue(scopes="read:users")` is rejected**: a bare string was silently
  exploded into single-character scopes (`{'r','e','a',...}`), producing a
  key that granted nothing and failed every scope check. Both
  `issue()`/`rotate()` (granted) and `verify()` (required) now reject
  strings/bytes and non-string, empty, or whitespace-containing scope
  entries with `ValueError`.

#### Changed

- **`verify()` strips surrounding whitespace before hashing**: the key
  parser already tolerated (and stripped) padding, but the hash was
  computed over the unstripped string, so a padded key failed with
  `hash_mismatch` through the library while the FastAPI integration (which
  strips header values) accepted it. Both layers now behave identically:
  whitespace-padded keys verify.
- **`verify()` validates `required_scopes`**: malformed required scopes
  (empty/whitespace/non-string) raise `ValueError` — caller error, distinct
  from a bad key — instead of silently 403-ing forever.
- **CLI `issue` uses the library's default scrypt cost**: the CLI previously
  hashed with a light scrypt profile (n=1024, 16x weaker than the library
  default n=16384), silently reducing the offline-cracking cost of every
  CLI-issued key. Issuing one key performs a single hash, so interactivity
  is unaffected; the cost profile is still printed at issue time. README and
  SECURITY.md updated to match.

#### Added

- `KeyStore.mark_verified(prefix, at=...)` protocol method (see above);
  both built-in stores implement it atomically.
- Deterministic regression tests for the verify-vs-revoke/rotate race
  (gated hasher parks a verification between the store read and the touch
  write), multithreaded and true multiprocess SQLite contention storms,
  Hypothesis property tests (round-trip, no-escalation, fail-closed
  fuzzing), and a fixed-seed fuzz corpus.
- `hypothesis` is now a declared `dev` extra so a fresh CI install works.
- `tests/test_cli.py::test_issue_uses_default_scrypt_cost` — end-to-end
  regression asserting that CLI-issued keys are persisted with the
  library-default scrypt parameters.
## [1.1.0] - 2026-11-17

Follow-up security and correctness release. Two high-severity logic bugs were
confirmed by reproduction and fixed with deterministic regression tests,
alongside hasher-dispatch support, verification write throttling, and a broad
hardening pass.

### Fixed

- **Rotation grace no longer bypasses key expiry** (HIGH): the rotated-key
  branch of `verify()` never checked `expires_at`, so a rotated key kept
  authenticating through its grace window even after its TTL had passed.
  Expiry is now a hard cap on grace; a rotated, expired key is rejected with
  reason `expired`.
- **Concurrent double-rotation is now atomic** (HIGH): `rotate()` performed a
  non-atomic read-check-write, so two concurrent rotations of the same key
  could both succeed and mint two valid successors. Rotation now claims the
  active→rotated transition through the new `KeyStore.mark_rotated()` — a
  single conditional `UPDATE ... WHERE rotated_at IS NULL AND revoked_at IS
  NULL` inside `BEGIN IMMEDIATE` for SQLite (atomic across threads and
  processes) and a lock-guarded check-and-set for the in-memory store. Losers
  of the race get the normal "already rotated" error. This also closes a
  rotate-vs-revoke race. The base `KeyStore` ships a non-atomic default and
  `rotate()` falls back to the 1.0 behavior for duck-typed stores.
- **scrypt `maxmem` is derived from parameters** instead of being hard-coded
  to 256 MiB: `ScryptHasher(n=2**18, r=8)` (≈268 MiB) previously passed
  construction but failed on every `hash()`. Consistent configurations up to
  a 1 GiB ceiling now work; anything larger is rejected at construction with
  a clear error. An explicit `maxmem=` argument is still honored (and
  validated).
- **FastAPI `auto_error=False` no longer collapses 403 into 401**: scope
  failures now raise the new `ScopeDeniedError` (a `PermissionError`
  subclass carrying `missing_scopes`), and `register_error_handlers` maps it
  to `403` with the missing scopes listed while authentication failures stay
  `401`. `register_error_handlers` is now exported.
- `InMemoryStore` returns copies on read and copies on write, so mutating a
  fetched record (or an object after `save()`) can no longer change stored
  state — matching `SQLiteStore` semantics.
- `list_events(limit=...)` rejects limits < 1 in both stores (previously
  `limit=-1` returned everything on SQLite and a wrong slice in memory).
- `rotate()` rejects negative grace periods (previously they silently killed
  the old key immediately).
- `revoke()` rejects timezone-naive `now` values, consistent with `issue()`.
- `parse_duration()` raises `ValueError` (as documented) instead of
  `OverflowError` for out-of-range values like `"999999999999999w"`.
- `KeyRecord.__repr__` redacts the stored hash, mirroring `IssuedKey` —
  hashes can no longer leak into logs via repr.
- `Argon2Hasher` rejects `memory_cost < 8 * parallelism` at construction
  instead of failing on the first `hash()`.
- Verification rejects stored hashes whose parameters fall outside sane
  bounds (scrypt `n/r/p`, Argon2id `t/m/p`) or whose digest is shorter than
  16 bytes — before running the KDF — so a crafted store record cannot
  force absurd verification cost or exploit truncated digests. `ScryptHasher`
  likewise requires `dklen >= 16` at construction.

### Added

- **Hasher dispatch by stored algorithm**: `KeyManager(..., hashers={...})`
  registers additional hashers keyed by algorithm name; verification picks
  the hasher recorded with each key, so switching algorithms (e.g. scrypt →
  Argon2id) no longer invalidates existing keys. Keys with an unregistered
  algorithm fail closed with `hash_mismatch`.
- **Verification write throttling**: `last_verified_at` persistence is
  throttled to once per `verify_touch_interval` (default 60 s; `timedelta(0)`
  restores write-on-every-verify).
- **Optional verify-time audit**: `audit_verifications=False` skips
  `verified`/`verify_failed` events while lifecycle events (issued/rotated/
  revoked) are always kept.
- **Audit pruning**: `KeyManager.prune_events(before=...)` plus
  `KeyStore.delete_events_before(cutoff)` in both built-in stores bound
  audit-log growth.
- **CLI**: `bitting verify` accepts the key via `--stdin` or `-` so it never
  lands in shell history or process listings.

### Docs & hygiene

- Scope strings are validated at issue/rotate time (non-empty, no
  whitespace); the successor-TTL behavior of `rotate()` is now documented in
  its docstring.
- README: contributor team named directly (was only linked); rotation table
  and limitations updated for the capped grace window and atomic rotation;
  CLI section documents `--stdin` and the CLI's lighter scrypt cost; test
  count corrected (now 180).
- CHANGELOG: corrected the 1.0.1 release date (its commits and tag are from
  2026-11-16).
- `.gitignore` now excludes SQLite databases (`*.db`, `*.sqlite`,
  `*.sqlite3`) so key stores cannot be committed accidentally.
- The FastAPI example's install hint now includes the `argon2` extra it
  actually uses.
- CI: workflow runs with `permissions: contents: read` and actions are
  pinned to commit SHAs (supply-chain hardening).

## [1.0.1] - 2026-11-16

### Fixed

- **CI**: the test suite failed under a bare `pytest` invocation (`ModuleNotFoundError: No module named 'tests'`) because the repo root was only importable when running `python -m pytest`. Added `pythonpath = ["."]` to the pytest configuration, so the suite now passes however pytest is invoked. This is what caused the first CI run to fail.
- **CI**: `pip-audit` and `build` are now installed before the steps that use them.
- **Key format**: `parse_api_key` now accepts the full range of prefix (8–64) and secret (16–128) component lengths that `generate_api_key` can produce; previously only the default lengths (16/40) parsed, making custom-length keys unverifiable. Regression tests added.
- **Argon2id**: `Argon2Hasher.verify` now also catches argon2-cffi's own `HashingError` (raised for invalid stored-hash parameters), so verification returns `False` instead of raising.
- **Docs**: installation instructions for optional extras now use working direct-reference syntax (`pip install 'bitting[fastapi] @ git+...'`) since the package is not yet on PyPI; removed a duplicated example block from the FastAPI integration docstring.

## [1.0.0] - 2026-11-16

### Added

- **Key format**: `btg_<env>_<prefix>_<secret>_<checksum>` keys with rejection-sampled base62 entropy (~95-bit public prefix, ~238-bit secret), environment labels, and a CRC32-based transcription-error checksum.
- **Hashing**: `Hasher` protocol; `ScryptHasher` (standard library, memory-hard, default ~16 MiB cost) and `Argon2Hasher` (optional `bitting[argon2]` extra). Self-describing encoded hashes with per-hash salts; constant-time verification.
- **Storage**: `KeyStore` protocol; `InMemoryStore` and `SQLiteStore` (WAL mode, `BEGIN IMMEDIATE` transactions, thread-safe writes, schema-version guard, parent-directory creation).
- **Lifecycle**: `KeyManager` with `issue`, `verify`, `rotate` (grace windows for zero-downtime rotation), `revoke`, `list_keys`, and injectable clock.
- **Verification semantics**: `VerifyResult`/`VerifyReason` distinguishing `invalid_format`, `not_found`, `hash_mismatch`, `expired`, `revoked`, `rotated`, `rotated_grace`, and `scope_missing` — enabling correct 401 vs 403 responses.
- **Scopes**: exact matching plus `read:*` prefix wildcards and the global `*`; precise `missing_scopes` reporting.
- **Audit**: every lifecycle action emits an `AuditEvent` (persisted by stores, plus an optional synchronous callback); audit persistence and observer failures never break verification.
- **CLI**: `bitting issue|verify|rotate|revoke|list|events` with `--db`, `--json`, duration TTLs, and meaningful exit codes.
- **FastAPI integration** (optional `bitting[fastapi]` extra): `APIKeyAuth` dependency builder with `X-API-Key` and `Authorization: Bearer` styles and precise 401/403 semantics.
- **Documentation**: README with architecture diagram, security model, and deployment notes; SECURITY.md; CONTRIBUTING.md; runnable examples.
- **Quality**: 117 automated tests (unit + integration), ruff lint/format clean, mypy `--strict` clean, pip-audit clean, wheel/sdist build verified.

[1.2.0]: https://github.com/muhammadanasmahmood/bitting/releases/tag/v1.2.0
[1.1.0]: https://github.com/muhammadanasmahmood/bitting/releases/tag/v1.1.0
[1.0.1]: https://github.com/muhammadanasmahmood/bitting/releases/tag/v1.0.1
[1.0.0]: https://github.com/muhammadanasmahmood/bitting/releases/tag/v1.0.0
