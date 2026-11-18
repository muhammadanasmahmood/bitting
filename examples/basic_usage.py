"""Basic usage: issue a key, verify it, rotate it, revoke it.

Run with the dev environment active:
    python examples/basic_usage.py
"""

from __future__ import annotations

from datetime import timedelta

from bitting import InMemoryStore, KeyManager, ScryptHasher, VerifyReason

# A lighter scrypt cost keeps the example fast; production code can
# simply omit `hasher=` to use the default (~16 MiB per hash).
manager = KeyManager(
    InMemoryStore(),
    hasher=ScryptHasher(n=2**12, r=8, p=1),
    on_event=lambda event: print(f"  [audit] {event.kind.value:<13} {event.prefix}"),
)

# 1. Issue a key with scopes and a 30-day lifetime.
issued = manager.issue(
    scopes={"read:users", "write:posts"},
    description="ci-runner",
    ttl=timedelta(days=30),
)
print(f"issued key (show once!): {issued.raw_key}")
print(f"prefix (safe to display): {issued.prefix}")

# 2. Verify it — with a required scope.
result = manager.verify(issued.raw_key, required_scopes={"read:users"})
print(f"verify: ok={result.ok} reason={result.reason.value}")

# 3. The same key lacks the admin scope.
result = manager.verify(issued.raw_key, required_scopes={"admin"})
print(
    f"admin check: ok={result.ok} reason={result.reason.value} missing={sorted(result.missing_scopes)}"
)

# 4. Rotate the key: clients keep working during the grace window.
new = manager.rotate(issued.prefix, grace=timedelta(hours=24))
print(f"rotated: new prefix {new.prefix}; old key still valid during grace")
print(f"old key verify: {manager.verify(issued.raw_key).reason.value}")

# 5. Revoke the new key: immediate denial.
manager.revoke(new.prefix)
print(f"revoked verify: {manager.verify(new.raw_key).reason.value}")

# 6. Audit trail (newest first).
print("audit trail:")
for event in manager.list_events():
    print(f"  {event.at.isoformat()}  {event.kind.value:<13} {event.prefix}")

assert manager.verify(new.raw_key).reason is VerifyReason.REVOKED
print("\nBasic usage example completed.")
