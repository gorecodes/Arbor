"""Session-based auth (local username/password only)."""

from collections.abc import Mapping
from types import SimpleNamespace

from fastapi import HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .authorization import set_current_principal
from .csrf import csrf_cookie_from_header, verify_csrf_tokens
from .session import get_session, session_cookie_name, session_from_cookie_header

_bearer = HTTPBearer(auto_error=False)


def auth_backend() -> str:
    # Single supported mode: local username/password + session cookie.
    return "local"


def _session_auth_or_401(request: Request) -> dict:
    session_id = request.cookies.get(session_cookie_name(), "")
    session = get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session


def _local_principal(session: Mapping[str, object]) -> dict:
    return {
        "backend": "local",
        "role": str(session.get("role", "owner")),
        "subject": str(session.get("user_id", "")),
        "username": str(session.get("username", "")),
    }


def resolve_ws_principal(payload: Mapping[str, object] | None, headers: Mapping[str, str]) -> dict | None:
    data = payload or {}
    session_id = session_from_cookie_header(headers.get("cookie"))
    session = get_session(session_id, touch=False)
    if session is None:
        return None
    csrf_cookie = csrf_cookie_from_header(headers.get("cookie"))
    csrf_payload = str(data.get("csrf", "") or "")
    if not verify_csrf_tokens(csrf_cookie, csrf_payload):
        return None
    return _local_principal(session)


def verify_ws_auth(payload: Mapping[str, object] | None, headers: Mapping[str, str]) -> bool:
    return resolve_ws_principal(payload, headers) is not None


def _store_request_principal(request: Request, principal: Mapping[str, object]) -> None:
    state = getattr(request, "state", None)
    if state is None:
        state = SimpleNamespace()
        setattr(request, "state", state)
    state.arbor_principal = dict(principal)


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
):
    _ = credentials
    session = _session_auth_or_401(request)
    principal = _local_principal(session)
    _store_request_principal(request, principal)
    set_current_principal(principal)
    return session["user_id"]
