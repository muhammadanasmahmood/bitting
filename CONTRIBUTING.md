# Contributing to bitting

Thanks for considering a contribution. This document explains the expectations for changes so the library stays small, correct, and trustworthy.

## Ground rules

- **Security first.** Anything touching key generation, hashing, verification, or storage must include tests that demonstrate the security property you rely on (tamper detection, constant-time behavior, thread safety, ...).
- **No new required dependencies.** The zero-dependency core is a feature. Optional functionality belongs behind an extra (`bitting[...]`).
- **Keep the surface small.** Prefer saying no to features that belong in applications or companion packages. A focused library is more auditable than a framework.
- **Documentation is part of the feature.** Public APIs need docstrings, and user-visible changes need README updates.

## Development setup

```bash
git clone https://github.com/muhammadanasmahmood/bitting.git
cd bitting
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,fastapi,argon2]'
```

## Workflow

1. **Discuss first** (for anything beyond a bugfix): open an issue describing the problem and your proposed approach.
2. **Fork & branch**: `git switch -c my-change`.
3. **Make the change** with tests. Bug fixes need a regression test that fails without the fix.
4. **Run the full quality gate locally**:

   ```bash
   pytest                     # full suite must pass
   ruff check src tests examples
   ruff format --check src tests examples
   mypy                       # strict; must report no issues
   ```

   CI runs exactly these on every push and pull request for Python 3.10–3.13. A PR that fails any of them will not be merged.

5. **Commit** with an imperative subject line (`Add grace-period overflow guard to rotate()`), and a body explaining *why* when the change is not obvious.
6. **Open a pull request** referencing the issue it resolves.

## Commit style

- Imperative, capitalized, ≤ 72 characters in the subject: `Add`, `Fix`, `Refactor`, `Document`.
- One logical change per commit.
- No secrets, tokens, or credentials in any commit — the repository has push protection enabled and a pre-push scan habit is a good one to keep.

## Testing guidelines

- Unit tests for pure logic (`keys`, `hashing`, `timeutil`).
- Integration tests for stateful paths (`storage`, `manager` lifecycle).
- Use the shared fixtures in `tests/conftest.py` (`fast_hasher`, `clock`, `manager`) — tests must not depend on wall-clock time or run at production hashing cost (one deliberate default-cost test exists in `test_hashing.py`; keep it that way).
- New stores must cover: save/find round-trip, update, delete, list, concurrency (see `test_storage_sqlite.py` for the checklist).

## Reporting security issues

Do **not** open a public issue for security problems — see [SECURITY.md](SECURITY.md).

## Code of conduct

Be precise, be kind, assume competence and good intent. Tough technical critique is welcome; personal remarks are not.
