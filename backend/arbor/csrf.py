"""CSRF protection (double-submit cookie pattern).

A random token is stored in a non-HttpOnly cookie and is required as an
``X-CSRF-Token`` header on every state-changing HTTP request. The values
are compared with ``hmac.compare_digest``. For WebSocket connections the
same token must be echoed in the first ``auth`` frame.

The cookie is *not* HttpOnly so the frontend can read it; that is the
defining trade-off of double-submit. Combined with ``SameSite=strict`` on
both cookies (session + csrf), a cross-site attacker cannot read the
cookie value and so cannot forge a request.
"""

from __future__ import annotations

import hmac
import secrets
from http.cookies import SimpleCookie

from fastapi import Request, Response

from .session import session_ttl_seconds

CSRF_COOKIE_NAME = "arbor_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
_TOKEN_BYTES = 32


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def set_csrf_cookie(response: Response, token: str, *, secure: bool = True) -> None:
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        httponly=False,
        secure=secure,
        samesite="strict",
        max_age=session_ttl_seconds(),
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/")


def csrf_cookie_from_request(request: Request) -> str:
    return str(request.cookies.get(CSRF_COOKIE_NAME, "") or "")


def csrf_cookie_from_header(cookie_header: str | None) -> str:
    if not cookie_header:
        return ""
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return ""
    morsel = jar.get(CSRF_COOKIE_NAME)
    return morsel.value if morsel is not None else ""


def verify_csrf_tokens(cookie_value: str, header_value: str) -> bool:
    if not cookie_value or not header_value:
        return False
    return hmac.compare_digest(cookie_value, header_value)
