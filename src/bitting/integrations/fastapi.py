"""FastAPI integration: a ready-made API key dependency.

Requires the optional ``fastapi`` extra (see README, Installation).

The dependency returns the authenticated :class:`bitting.KeyRecord` and
raises precise HTTP errors:

* 401 for authentication failures (bad format, unknown key, wrong hash,
  expired, revoked, fully rotated),
* 403 for authorization failures (missing scopes), with the missing
  scopes listed in the response detail.

Both header styles are supported: ``X-API-Key: <key>`` (default) or
``Authorization: Bearer <key>``.

Example::

    from fastapi import Depends, FastAPI

    from bitting import KeyManager, SQLiteStore
    from bitting.integrations.fastapi import APIKeyAuth

    app = FastAPI()
    auth = APIKeyAuth(KeyManager(SQLiteStore("keys.db")))

    @app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
    async def list_users():
        return [...]
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from ..manager import KeyManager
from ..models import KeyRecord, VerifyReason, VerifyResult

__all__ = [
    "WWW_AUTHENTICATE",
    "APIKeyAuth",
    "AuthenticationError",
    "ScopeDeniedError",
    "register_error_handlers",
]

WWW_AUTHENTICATE = "ApiKey"

# Every verify reason except SCOPE_MISSING is an authentication failure (401);
# SCOPE_MISSING is authorization (403). ROTATED_GRACE never reaches _deny()
# because it means the key verified successfully during its grace window.
_AUTHN_FAILURE_REASONS = frozenset(
    {
        VerifyReason.INVALID_FORMAT,
        VerifyReason.NOT_FOUND,
        VerifyReason.HASH_MISMATCH,
        VerifyReason.EXPIRED,
        VerifyReason.REVOKED,
        VerifyReason.ROTATED,
    }
)


class AuthenticationError(PermissionError):
    r"""A key failed authentication (bad format, unknown, expired, ...).

    Subclasses :class:`PermissionError` for backwards compatibility with
    code that caught the pre-1.2 exception type, but is raised *only* by
    the API-key dependency — so :func:`register_error_handlers` can map
    exactly these failures to 401 without relabelling unrelated
    application ``PermissionError``\ s (filesystem errors, third-party
    libraries, ...) as API-key problems.
    """


class ScopeDeniedError(PermissionError):
    """A valid key lacked the required scopes (an authorization failure).

    Raised instead of :class:`PermissionError` when ``auto_error=False``
    so applications (and :func:`register_error_handlers`) can map it to
    ``403`` while authentication failures stay ``401``.
    """

    def __init__(self, missing_scopes: Iterable[str]) -> None:
        self.missing_scopes = frozenset(missing_scopes)
        super().__init__("missing required scopes: " + ", ".join(sorted(self.missing_scopes)))


class APIKeyAuth:
    """Build FastAPI dependencies backed by a :class:`KeyManager`.

    Args:
        manager: The key manager to verify against.
        header: Where the client sends the key — ``"X-API-Key"`` (default)
            or ``"Authorization"`` (then ``Bearer <key>`` is expected).
        auto_error: Return 401/403 responses (True, default) or raise
            without a response (:class:`AuthenticationError` for
            authentication failures, :class:`ScopeDeniedError` for missing
            scopes) so custom handlers can take over.
    """

    def __init__(
        self,
        manager: KeyManager,
        *,
        header: str = "X-API-Key",
        auto_error: bool = True,
    ) -> None:
        if header.lower() not in {"x-api-key", "authorization"}:
            raise ValueError("header must be 'X-API-Key' or 'Authorization'")
        self._manager = manager
        self._header = header
        self._auto_error = auto_error

    def _www_authenticate(self) -> str:
        """The RFC 7235 challenge scheme matching the configured header.

        ``Bearer`` when keys arrive as ``Authorization: Bearer <key>``;
        ``ApiKey`` for the ``X-API-Key`` header.
        """
        return "Bearer" if self._header.lower() == "authorization" else WWW_AUTHENTICATE

    def _extract(self, request: Request) -> str | None:
        # An ambiguous credential is not a credential. Starlette's
        # headers.get() returns the *first* occurrence, so a request
        # carrying both a valid and an invalid key would authenticate on
        # whichever the client happened to list first. Refuse duplicates
        # outright instead of guessing.
        values = request.headers.getlist(self._header)
        if len(values) > 1:
            return None
        value = values[0] if values else None
        if value is None:
            return None
        if self._header.lower() == "authorization":
            scheme, _, token = value.partition(" ")
            if scheme.lower() != "bearer" or not token:
                return None
            return token.strip()
        return value.strip()

    def _deny(self, result: VerifyResult) -> HTTPException:
        if result.reason is VerifyReason.SCOPE_MISSING:
            missing = ", ".join(sorted(result.missing_scopes))
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing required scopes: {missing}",
            )
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid API key: {result.reason.value}",
            headers={"WWW-Authenticate": self._www_authenticate()},
        )

    def _authenticate(self, request: Request, required_scopes: Iterable[str]) -> KeyRecord:
        raw = self._extract(request)
        if raw is None:
            result = VerifyResult(ok=False, reason=VerifyReason.INVALID_FORMAT)
        else:
            result = self._manager.verify(raw, required_scopes=required_scopes)
        if not result.ok:
            if self._auto_error:
                raise self._deny(result)
            if result.reason is VerifyReason.SCOPE_MISSING:
                raise ScopeDeniedError(result.missing_scopes)
            raise AuthenticationError(result.reason.value)
        if result.record is None:  # pragma: no cover - invariant
            # Fail closed: an ``ok`` result always carries its record, but
            # an ``assert`` here would be stripped under ``python -O``.
            raise AuthenticationError(VerifyReason.INVALID_FORMAT.value)
        return result.record

    def require(self, *, scopes: Iterable[str] = ()) -> Callable[[Request], KeyRecord]:
        """Return a FastAPI dependency that enforces these scopes.

        Always use it through :func:`fastapi.Depends`, both in route
        ``dependencies=[...]`` lists and for parameter injection::

            @app.get("/users", dependencies=[Depends(auth.require(scopes={"read:users"}))])
            ...

            @app.get("/users")
            async def list_users(
                record: KeyRecord = Depends(auth.require(scopes={"read:users"})),
            ):
                ...

        Scopes are validated eagerly, at dependency-construction time
        (route setup / application startup): a malformed scope — a bare
        string, empty, whitespace-containing, or not a string — raises
        ``ValueError`` immediately instead of failing every request with
        a 500.
        """
        if isinstance(scopes, (str, bytes)):
            # A bare string would silently become a set of single characters
            # ("read:users" -> {'r','e','a',...}), matching nothing sensible.
            raise ValueError(
                f"require(scopes=...) needs an iterable of scope strings, not a "
                f"single string (got {scopes!r}); pass e.g. scopes={{'read:users'}}"
            )
        scope_set = frozenset(scopes)
        for scope in scope_set:
            if not isinstance(scope, str) or not scope or any(ch.isspace() for ch in scope):
                raise ValueError(
                    f"require(scopes=...) needs non-empty scope strings without "
                    f"whitespace (got {scope!r}); this is a route-configuration error"
                )

        def dependency(request: Request) -> KeyRecord:
            return self._authenticate(request, scope_set)

        return dependency

    def login_route(self, *, prefix: str = "/api-keys") -> None:
        """No-op: issuing keys over HTTP is intentionally unsupported.

        Key issuance is an operator action; exposing it via a public
        route would let any authenticated client mint keys. Use the CLI
        or library from trusted code paths instead.
        """
        raise NotImplementedError(
            "issuing API keys over HTTP is intentionally unsupported; "
            "use the bitting CLI or library from trusted code"
        )


def register_error_handlers(app: FastAPI, auth: APIKeyAuth | None = None) -> None:
    r"""Attach uniform 401/403 JSON responses for the auto_error=False flow.

    :class:`ScopeDeniedError` maps to 403 with the missing scopes listed;
    :class:`AuthenticationError` maps to 401 with a ``WWW-Authenticate``
    header matching ``auth``'s header mode (``Bearer`` for Authorization
    mode, ``ApiKey`` otherwise; ``ApiKey`` when ``auth`` is omitted).
    Only the dedicated exception classes are registered: unrelated
    application ``PermissionError``\ s keep their own meaning instead of
    being relabelled as API-key failures. Pass ``auth`` so the challenge
    scheme matches your deployment.
    """
    challenge = auth._www_authenticate() if auth is not None else WWW_AUTHENTICATE

    @app.exception_handler(ScopeDeniedError)
    async def _scope_denied(_: Request, exc: ScopeDeniedError) -> Response:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": str(exc), "missing_scopes": sorted(exc.missing_scopes)},
        )

    @app.exception_handler(AuthenticationError)
    async def _authentication_error(_: Request, exc: AuthenticationError) -> Response:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": f"invalid API key: {exc}"},
            headers={"WWW-Authenticate": challenge},
        )
