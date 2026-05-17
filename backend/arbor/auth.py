"""
Simple token-based auth. Token is read from config at startup.
"""

import secrets
from pathlib import Path

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

_ephemeral_token: str | None = None


def get_token() -> str:
    global _ephemeral_token
    token_file = Path("/etc/arbor/token")
    if token_file.exists():
        return token_file.read_text().strip()
    if _ephemeral_token is None:
        _ephemeral_token = secrets.token_urlsafe(32)
        print(f"\n[arbor] No token file found. Ephemeral token: {_ephemeral_token}\n", flush=True)
    return _ephemeral_token


def verify_token(candidate: str | None) -> bool:
    """Constant-time token comparison. Returns False for None/empty input."""
    if not candidate:
        return False
    return secrets.compare_digest(candidate, get_token())


def require_auth(credentials: HTTPAuthorizationCredentials = Security(_bearer)):
    if credentials is None or not verify_token(credentials.credentials):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return credentials.credentials
