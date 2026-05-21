from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie

from fastapi import Response

from .config_env import env_int, env_value
from .local_auth import auth_db_path, ensure_auth_db

_SESSION_COOKIE_NAME_ENV = "ARBOR_SESSION_COOKIE_NAME"
_SESSION_COOKIE_NAME_DEFAULT = "arbor_session"
_SESSION_TTL_ENV = "ARBOR_SESSION_TTL_SECONDS"
_SESSION_TTL_DEFAULT = 43200
_SESSION_IDLE_ENV = "ARBOR_SESSION_IDLE_TIMEOUT_SECONDS"
_SESSION_IDLE_DEFAULT = 1800
_SESSION_REVOKED_RETENTION_ENV = "ARBOR_SESSION_REVOKED_RETENTION_SECONDS"
_SESSION_REVOKED_RETENTION_DEFAULT = 86400
_LAST_SEEN_UPDATE_INTERVAL_SECONDS = 30


def session_cookie_name() -> str:
    value = env_value(_SESSION_COOKIE_NAME_ENV, _SESSION_COOKIE_NAME_DEFAULT).strip()
    return value or _SESSION_COOKIE_NAME_DEFAULT


def session_ttl_seconds() -> int:
    return max(env_int(_SESSION_TTL_ENV, _SESSION_TTL_DEFAULT), 60)


def session_idle_timeout_seconds() -> int:
    return max(env_int(_SESSION_IDLE_ENV, _SESSION_IDLE_DEFAULT), 60)


def session_revoked_retention_seconds() -> int:
    return max(env_int(_SESSION_REVOKED_RETENTION_ENV, _SESSION_REVOKED_RETENTION_DEFAULT), 60)


@contextmanager
def _db_conn():
    path = auth_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15.0)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_session_db() -> None:
    ensure_auth_db()
    with _db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                session_version INTEGER NOT NULL,
                created_at REAL NOT NULL,
                last_seen_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                auth_time REAL,
                step_up_at REAL,
                step_up_method TEXT,
                remote_addr TEXT,
                user_agent TEXT,
                revoked_at REAL,
                revoke_reason TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions(revoked_at)")


def _now() -> float:
    return time.time()


def _cleanup_sessions(conn: sqlite3.Connection, now: float) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    conn.execute(
        "DELETE FROM sessions WHERE revoked_at IS NOT NULL AND revoked_at < ?",
        (now - session_revoked_retention_seconds(),),
    )


def create_session(user_id: str, *, remote_addr: str = "", user_agent: str = "", step_up_method: str = "") -> dict:
    ensure_session_db()
    now = _now()
    session_id = secrets.token_urlsafe(32)
    expires_at = now + session_ttl_seconds()
    normalized_step_up = str(step_up_method or "").strip()
    step_up_at = now if normalized_step_up else None
    with _db_conn() as conn:
        _cleanup_sessions(conn, now)
        conn.execute(
            """
            INSERT INTO sessions (
                session_id, user_id, session_version, created_at, last_seen_at,
                expires_at, auth_time, step_up_at, step_up_method, remote_addr, user_agent
            ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                user_id,
                now,
                now,
                expires_at,
                now,
                step_up_at,
                normalized_step_up or None,
                remote_addr,
                user_agent,
            ),
        )
        conn.execute(
            """
            INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
            VALUES (?, ?, ?, 'session_created', 'ok', '{}')
            """,
            (now, user_id, session_id),
        )
    return {"session_id": session_id, "expires_at": expires_at, "step_up_method": normalized_step_up}


def revoke_sessions_for_user(user_id: str, *, reason: str) -> None:
    if not user_id:
        return
    ensure_session_db()
    now = _now()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT session_id FROM sessions WHERE user_id=? AND revoked_at IS NULL",
            (user_id,),
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE session_id=?",
                (now, reason, row["session_id"]),
            )
            conn.execute(
                """
                INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
                VALUES (?, ?, ?, 'session_revoked', 'ok', ?)
                """,
                (now, user_id, row["session_id"], json.dumps({"reason": reason}, separators=(",", ":"))),
            )


def revoke_all_sessions(*, reason: str) -> None:
    ensure_session_db()
    now = _now()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT session_id, user_id FROM sessions WHERE revoked_at IS NULL"
        ).fetchall()
        for row in rows:
            conn.execute(
                "UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE session_id=?",
                (now, reason, row["session_id"]),
            )
            conn.execute(
                """
                INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
                VALUES (?, ?, ?, 'session_revoked', 'ok', ?)
                """,
                (now, row["user_id"], row["session_id"], json.dumps({"reason": reason}, separators=(",", ":"))),
            )


def revoke_session(session_id: str, *, reason: str = "logout") -> None:
    if not session_id:
        return
    ensure_session_db()
    now = _now()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, revoked_at FROM sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None or row["revoked_at"] is not None:
            return
        conn.execute(
            "UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE session_id=?",
            (now, reason, session_id),
        )
        conn.execute(
            """
            INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
            VALUES (?, ?, ?, 'session_revoked', 'ok', ?)
            """,
            (now, row["user_id"], session_id, json.dumps({"reason": reason}, separators=(",", ":"))),
        )


def get_session(session_id: str, *, touch: bool = True) -> dict | None:
    if not session_id:
        return None
    ensure_session_db()
    now = _now()
    idle_cutoff = now - session_idle_timeout_seconds()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        _cleanup_sessions(conn, now)
        row = conn.execute(
            """
            SELECT s.session_id, s.user_id, s.created_at, s.last_seen_at, s.expires_at, s.auth_time,
                   s.step_up_at, s.step_up_method, s.revoked_at, u.username, u.role, u.disabled_at,
                   u.password_changed_at
            FROM sessions s
            JOIN local_user u ON u.user_id = s.user_id
            WHERE s.session_id=?
            """,
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        if data["revoked_at"] is not None:
            return None
        if data["disabled_at"] is not None:
            return None
        if data["password_changed_at"] is not None and float(data["auth_time"] or 0.0) < float(data["password_changed_at"]):
            conn.execute(
                "UPDATE sessions SET revoked_at=?, revoke_reason=? WHERE session_id=?",
                (now, "password_changed", session_id),
            )
            return None
        if float(data["expires_at"]) < now:
            return None
        if float(data["last_seen_at"]) < idle_cutoff:
            return None
        if touch and now - float(data["last_seen_at"]) >= _LAST_SEEN_UPDATE_INTERVAL_SECONDS:
            conn.execute("UPDATE sessions SET last_seen_at=? WHERE session_id=?", (now, session_id))
            data["last_seen_at"] = now
        return data


def session_from_cookie_header(cookie_header: str | None) -> str:
    if not cookie_header:
        return ""
    jar = SimpleCookie()
    try:
        jar.load(cookie_header)
    except Exception:
        return ""
    morsel = jar.get(session_cookie_name())
    return morsel.value if morsel is not None else ""


def set_session_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(
        key=session_cookie_name(),
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=session_ttl_seconds(),
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(key=session_cookie_name(), path="/")
