# Security Policy

## Supported versions

Only the latest release line on `main` receives security fixes.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Email the maintainer via GitHub security advisory instead:

1. Open <https://github.com/muhammadanasmahmood/bitting/security/advisories/new>, or
2. Use GitHub's *Report a vulnerability* action on the Security tab.

Include what you can of: the affected component (`keys`, `hashing`, `storage`, `manager`, CLI, FastAPI integration), a minimal reproduction, and the impact you assess. You will receive an acknowledgment; fixes ship as promptly as practical, with credit in the release notes if you wish.

## Scope

In scope:

- Anything under `src/bitting/` and the CLI.
- Weaknesses in key generation, hashing, verification, storage, or the audit path.
- The FastAPI integration's authentication/authorization semantics.

Out of scope:

- Vulnerabilities in dependencies (report upstream; we will track and bump).
- Compromise of an application that *uses* bitting where bitting behaves as documented (e.g., an application that logs raw keys it was handed at issue time).
- Attacks requiring privileged access to the running process or the database file (documented non-goal: bitting protects keys at rest and in verification, not against a compromised host).
- Denial of service through sheer request volume (pair with API rate limiting).

## Hardening notes for operators

- If you implement a custom `KeyStore`, implement `mark_verified`, `mark_rotated`, and `mark_revoked` as targeted, atomic updates; never persist a full record from a verification or revocation path. The non-atomic fallbacks (used only when these methods are absent) can lose a concurrent lifecycle change — in the worst case a revoked key verifies again until the next lifecycle write.
- Verification rejects stored hashes whose parameters exceed sane work bounds (scrypt `n ≤ 2^22`, `r ≤ 64`, `p ≤ 64`; Argon2id `t`, `m`, `p` bounds plus a total-work cap `t×m ≤ 2^23`), and parameters equal to the hasher's own configuration are always accepted. Stored scrypt work is additionally budgeted: `n×r×p` may not exceed 4× the active profile's work (with the documented default profile's work as the floor), so a crafted record (which requires write access to the database — outside bitting's threat model) cannot force more than ~4× the configured CPU per scrypt verification; memory remains hard-capped by the configured `maxmem`, and Argon2id remains bounded by its total-work cap (~60×; a tighter argon2 budget is left as a deployment decision). Stored-hash parameter parsing is canonical-only (exact parameter names, digits-only values, no duplicates).
- `ScryptHasher` refuses construction parameters outside the stored-hash bounds (`n ≤ 2^22`, `r ≤ 64`, `p ≤ 64`): such a hasher would issue keys that can never verify. Heavy in-bounds configurations (up to the 1 GiB memory ceiling, or beyond with an explicit `maxmem`) keep working and keep verifying — with one documented exception: `r=1` combined with `n ≥ 2^16` is rejected at construction because OpenSSL refuses it at hash time regardless of `maxmem` (fail fast instead of a raw `ValueError` on every `hash()` call).
- Constructing a `KeyManager` over a store that lacks `mark_verified`/`mark_rotated`/`mark_revoked` emits a one-time `UserWarning`: bitting falls back to non-atomic read-modify-write lifecycle updates on such stores, and a concurrent revocation can be lost (in the worst case a revoked key verifies again until the next lifecycle write). Implement the `mark_*` methods as targeted atomic updates — both built-in stores do. Silencing the warning (`bitting.manager.LEGACY_STORE_WARNING = False`) is an explicit acceptance of that documented risk.
- Keys issued via the CLI are hashed at the library's default scrypt cost (n=16384); the CLI prints the profile at issue time. If you deliberately lower the cost for bulk issuing, document that you did.

- Keep `hasher` at the default cost unless you have a measured reason not to; document any deliberate downgrade.
- Store raw keys in a secrets manager at issue time — they are unrecoverable from the library.
- Serve traffic over TLS only.
- Monitor `rotated_grace` verifications and `verify_failed` events in your audit sink. Note that verification attempts with *malformed* or *unknown-prefix* keys (`invalid_format` / `not_found`) do not generate audit events by design — emitting one row per junk request would let unauthenticated traffic inflate the audit log; detect brute-force probing with edge metrics instead.
- Use separate stores for separate environments; environment labels are operational, not a security boundary.
