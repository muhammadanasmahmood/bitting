"""Protect a FastAPI service with bitting API keys.

Requires the optional extras (see README, Installation) — this example
uses the Argon2id hasher, so both extras are needed:
    pip install 'bitting[fastapi,argon2] @ git+https://github.com/muhammadanasmahmood/bitting.git'

Run:
    uvicorn examples.fastapi_service:app --reload

Exercise it:
    curl -H "X-API-Key: <key from the startup output>" http://127.0.0.1:8000/users
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from bitting import Argon2Hasher, KeyManager, SQLiteStore
from bitting.integrations.fastapi import APIKeyAuth
from bitting.models import KeyRecord

# One durable store for the service. SQLite in WAL mode is safe for a
# single-process deployment; see README for multi-process notes.
manager = KeyManager(
    SQLiteStore("api-keys.db"),
    hasher=Argon2Hasher(),  # or omit for the stdlib scrypt default
)

# Issue a first key at startup if the store is empty, so the example is
# immediately usable. Real services should issue keys via the CLI or an
# operator script instead.
if not manager.list_keys():
    bootstrap = manager.issue(scopes={"read:users"}, description="bootstrap key")
    print(f"bootstrap API key (show once): {bootstrap.raw_key}")

auth = APIKeyAuth(manager)

app = FastAPI(title="bitting example service")


@app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
async def list_users() -> dict:
    return {"users": ["alice", "bob"]}


@app.get("/me")
async def who_am_i(record: KeyRecord = Depends(auth.require())) -> dict:
    """The dependency can also inject the authenticated key record."""
    return {
        "key_id": record.key_id,
        "prefix": record.prefix,
        "scopes": sorted(record.scopes),
        "description": record.description,
    }
