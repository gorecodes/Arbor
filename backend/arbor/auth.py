"""
Simple token-based auth. Token is read from config at startup.
"""

import logging
import secrets
from pathlib import Path

from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)
log = logging.getLogger(__name__)
TOKEN_FILE = Path("/etc/arbor/token")

_ephemeral_token: str | None = None
_cached_file_token: str | None = None
_cached_file_token_mtime_ns: int | None = None
_warned_missing_token_file = False
_printed_ephemeral_token = False


def get_token() -> str:
    global _ephemeral_token, _cached_file_token, _cached_file_token_mtime_ns
    global _warned_missing_token_file, _printed_ephemeral_token
    try:
        stat_result = TOKEN_FILE.stat()
    except FileNotFoundError:
        had_file_token = _cached_file_token is not None or _cached_file_token_mtime_ns is not None
        if had_file_token and not _warned_missing_token_file:
            log.warning("token file %s disappeared; falling back to in-memory token until it returns", TOKEN_FILE)
            _warned_missing_token_file = True
        _cached_file_token = None
        _cached_file_token_mtime_ns = None
        if _ephemeral_token is None:
            _ephemeral_token = secrets.token_urlsafe(32)
            if not had_file_token and not _printed_ephemeral_token:
                print(f"\n[arbor] No token file found. Ephemeral token: {_ephemeral_token}\n", flush=True)
                _printed_ephemeral_token = True
        return _ephemeral_token
    if _cached_file_token is not None and _cached_file_token_mtime_ns == stat_result.st_mtime_ns:
        return _cached_file_token
    token = TOKEN_FILE.read_text().strip()
    _cached_file_token = token
    _cached_file_token_mtime_ns = stat_result.st_mtime_ns
    _warned_missing_token_file = False
    _printed_ephemeral_token = False
    if not token:
        raise RuntimeError(f"token file {TOKEN_FILE} is empty")
    return token


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
