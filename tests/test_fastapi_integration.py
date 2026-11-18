"""Tests for the optional FastAPI integration."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from bitting import InMemoryStore, KeyManager, ScryptHasher
from bitting.integrations.fastapi import APIKeyAuth
from bitting.models import KeyRecord


def _manager() -> KeyManager:
    return KeyManager(InMemoryStore(), hasher=ScryptHasher(n=2**8, r=1, p=1))


@pytest.fixture
def app_and_key():
    manager = _manager()
    issued = manager.issue(scopes={"read:users", "write:posts"}, description="test")
    auth = APIKeyAuth(manager)
    app = FastAPI()

    @app.get("/public")
    async def public() -> dict:
        return {"ok": True}

    @app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
    async def users() -> dict:
        return {"users": ["alice", "bob"]}

    @app.post("/posts", dependencies=[Depends(auth.require(scopes={"write:posts"}))])
    async def posts() -> dict:
        return {"created": True}

    @app.get("/me")
    async def me(record: KeyRecord = Depends(auth.require())) -> dict:
        return {"prefix": record.prefix, "scopes": sorted(record.scopes)}

    return app, issued.raw_key, manager, auth


class TestAPIKeyAuth:
    def test_missing_header_401(self, app_and_key) -> None:
        app, _, _, _ = app_and_key
        response = TestClient(app).get("/users")
        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "ApiKey"

    def test_valid_key_200(self, app_and_key) -> None:
        app, key, _, _ = app_and_key
        response = TestClient(app).get("/users", headers={"X-API-Key": key})
        assert response.status_code == 200
        assert response.json() == {"users": ["alice", "bob"]}

    def test_key_with_scope_200_on_matching_route(self, app_and_key) -> None:
        app, key, _, _ = app_and_key
        response = TestClient(app).post("/posts", headers={"X-API-Key": key})
        assert response.status_code == 200

    def test_missing_scope_403(self, app_and_key) -> None:
        app, _, manager, _ = app_and_key
        read_only = manager.issue(scopes={"read:users"})
        response = TestClient(app).post("/posts", headers={"X-API-Key": read_only.raw_key})
        assert response.status_code == 403
        assert "write:posts" in response.json()["detail"]

    def test_garbage_key_401(self, app_and_key) -> None:
        app, _, _, _ = app_and_key
        response = TestClient(app).get("/users", headers={"X-API-Key": "garbage"})
        assert response.status_code == 401

    def test_dependency_injects_record(self, app_and_key) -> None:
        app, key, _, _ = app_and_key
        response = TestClient(app).get("/me", headers={"X-API-Key": key})
        assert response.status_code == 200
        body = response.json()
        assert body["prefix"]
        assert "write:posts" in body["scopes"]

    def test_revoked_key_401(self, app_and_key) -> None:
        app, key, manager, _ = app_and_key
        manager.revoke(key.split("_")[2])
        response = TestClient(app).get("/users", headers={"X-API-Key": key})
        assert response.status_code == 401

    def test_public_route_unaffected(self, app_and_key) -> None:
        app, _, _, _ = app_and_key
        assert TestClient(app).get("/public").status_code == 200


class TestBearerMode:
    def test_bearer_authorization_header(self) -> None:
        manager = _manager()
        issued = manager.issue(scopes={"read:users"})
        auth = APIKeyAuth(manager, header="Authorization")
        app = FastAPI()

        @app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
        async def users() -> dict:
            return {"users": []}

        client = TestClient(app)
        ok = client.get("/users", headers={"Authorization": f"Bearer {issued.raw_key}"})
        assert ok.status_code == 200
        assert client.get("/users", headers={"X-API-Key": issued.raw_key}).status_code == 401
        # Bearer scheme is required; a bare token is rejected.
        assert client.get("/users", headers={"Authorization": issued.raw_key}).status_code == 401


class TestValidation:
    def test_invalid_header_rejected(self) -> None:
        with pytest.raises(ValueError):
            APIKeyAuth(_manager(), header="X-Custom-Header")


class TestAutoErrorFalse:
    """auto_error=False must keep 401 vs 403 semantics ."""

    @pytest.fixture
    def error_app_and_key(self):
        from bitting.integrations.fastapi import register_error_handlers

        manager = _manager()
        issued = manager.issue(scopes={"read:users"})
        auth = APIKeyAuth(manager, auto_error=False)
        app = FastAPI()
        register_error_handlers(app, auth)

        @app.get("/admin", dependencies=[Depends(auth.require(scopes={"admin"}))])
        async def admin() -> dict:
            return {"ok": True}

        @app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
        async def users() -> dict:
            return {"ok": True}

        return app, issued.raw_key

    def test_scope_failure_is_403_with_missing_scopes(self, error_app_and_key) -> None:
        app, key = error_app_and_key
        response = TestClient(app).get("/admin", headers={"X-API-Key": key})
        assert response.status_code == 403
        body = response.json()
        assert body["missing_scopes"] == ["admin"]
        assert "admin" in body["detail"]

    def test_authentication_failure_is_401(self, error_app_and_key) -> None:
        app, _ = error_app_and_key
        response = TestClient(app).get("/users", headers={"X-API-Key": "garbage"})
        assert response.status_code == 401
        assert response.headers.get("www-authenticate") == "ApiKey"

    def test_missing_header_is_401(self, error_app_and_key) -> None:
        app, _ = error_app_and_key
        assert TestClient(app).get("/users").status_code == 401

    def test_valid_key_passes(self, error_app_and_key) -> None:
        app, key = error_app_and_key
        assert TestClient(app).get("/users", headers={"X-API-Key": key}).status_code == 200

    def test_scope_denied_error_is_exported_and_subclasses_permission_error(self) -> None:
        from bitting.integrations.fastapi import ScopeDeniedError

        exc = ScopeDeniedError(["b:z", "a:x"])
        assert isinstance(exc, PermissionError)
        assert exc.missing_scopes == frozenset({"a:x", "b:z"})
        assert "a:x" in str(exc) and "b:z" in str(exc)
