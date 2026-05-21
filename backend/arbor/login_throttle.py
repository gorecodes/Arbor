from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager

from .config_env import env_int
from .local_auth import auth_db_path, ensure_auth_db

_FAILURE_WINDOW_ENV = "ARBOR_LOGIN_THROTTLE_WINDOW_SECONDS"
_FAILURE_WINDOW_DEFAULT = 300
_IP_THRESHOLD_ENV = "ARBOR_LOGIN_IP_FAILURE_THRESHOLD"
_IP_THRESHOLD_DEFAULT = 20
_USER_THRESHOLD_ENV = "ARBOR_LOGIN_USER_FAILURE_THRESHOLD"
_USER_THRESHOLD_DEFAULT = 10
_PAIR_THRESHOLD_ENV = "ARBOR_LOGIN_PAIR_FAILURE_THRESHOLD"
_PAIR_THRESHOLD_DEFAULT = 5
_BLOCK_SECONDS_ENV = "ARBOR_LOGIN_LOCKOUT_SECONDS"
_BLOCK_SECONDS_DEFAULT = 300
_BACKOFF_BASE_ENV = "ARBOR_LOGIN_BACKOFF_BASE_SECONDS"
_BACKOFF_BASE_DEFAULT = 1
_BACKOFF_MAX_ENV = "ARBOR_LOGIN_BACKOFF_MAX_SECONDS"
_BACKOFF_MAX_DEFAULT = 60


def _failure_window_seconds() -> int:
    return max(env_int(_FAILURE_WINDOW_ENV, _FAILURE_WINDOW_DEFAULT), 60)


def _ip_threshold() -> int:
    return max(env_int(_IP_THRESHOLD_ENV, _IP_THRESHOLD_DEFAULT), 1)


def _user_threshold() -> int:
    return max(env_int(_USER_THRESHOLD_ENV, _USER_THRESHOLD_DEFAULT), 1)


def _pair_threshold() -> int:
    return max(env_int(_PAIR_THRESHOLD_ENV, _PAIR_THRESHOLD_DEFAULT), 1)


def _block_seconds() -> int:
    return max(env_int(_BLOCK_SECONDS_ENV, _BLOCK_SECONDS_DEFAULT), 1)


def _backoff_base_seconds() -> int:
    return max(env_int(_BACKOFF_BASE_ENV, _BACKOFF_BASE_DEFAULT), 0)


def _backoff_max_seconds() -> int:
    return max(env_int(_BACKOFF_MAX_ENV, _BACKOFF_MAX_DEFAULT), 0)


def _scope_rows(username: str, remote_addr: str) -> list[tuple[str, str, int]]:
    normalized_user = str(username or "").strip().lower()
    normalized_ip = str(remote_addr or "").strip() or "unknown"
    return [
        ("ip", normalized_ip, _ip_threshold()),
        ("username", normalized_user, _user_threshold()),
        ("pair", f"{normalized_user}|{normalized_ip}", _pair_threshold()),
    ]


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


def ensure_login_throttle_db() -> None:
    ensure_auth_db()
    with _db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_throttle (
                scope_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                failure_count INTEGER NOT NULL DEFAULT 0,
                first_failed_at REAL NOT NULL,
                last_failed_at REAL NOT NULL,
                blocked_until REAL,
                PRIMARY KEY (scope_type, subject)
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_login_throttle_blocked_until ON login_throttle(blocked_until)"
        )


def _delete_stale_rows(conn: sqlite3.Connection, now: float) -> None:
    window_cutoff = now - _failure_window_seconds()
    conn.execute(
        """
        DELETE FROM login_throttle
        WHERE (blocked_until IS NULL OR blocked_until < ?)
          AND last_failed_at < ?
        """,
        (now, window_cutoff),
    )


def login_retry_after(username: str, remote_addr: str) -> int:
    ensure_login_throttle_db()
    now = time.time()
    retry_after = 0
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        _delete_stale_rows(conn, now)
        for scope_type, subject, _threshold in _scope_rows(username, remote_addr):
            row = conn.execute(
                """
                SELECT blocked_until
                FROM login_throttle
                WHERE scope_type=? AND subject=?
                """,
                (scope_type, subject),
            ).fetchone()
            if row is None or row["blocked_until"] is None:
                continue
            remaining = int(float(row["blocked_until"]) - now + 0.999)
            if remaining > retry_after:
                retry_after = remaining
    return max(retry_after, 0)


def register_login_failure(username: str, remote_addr: str) -> int:
    ensure_login_throttle_db()
    now = time.time()
    retry_after = 0
    window_cutoff = now - _failure_window_seconds()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        _delete_stale_rows(conn, now)
        for scope_type, subject, threshold in _scope_rows(username, remote_addr):
            row = conn.execute(
                """
                SELECT failure_count, first_failed_at, last_failed_at, blocked_until
                FROM login_throttle
                WHERE scope_type=? AND subject=?
                """,
                (scope_type, subject),
            ).fetchone()
            if row is None or float(row["last_failed_at"]) < window_cutoff:
                failure_count = 1
                first_failed_at = now
            else:
                failure_count = int(row["failure_count"]) + 1
                first_failed_at = float(row["first_failed_at"])
            blocked_until = None
            if failure_count >= threshold:
                blocked_until = now + _block_seconds()
                retry_after = max(retry_after, _block_seconds())
            elif failure_count > 1:
                backoff = min(
                    _backoff_base_seconds() * (2 ** (failure_count - 2)),
                    _backoff_max_seconds(),
                )
                if backoff > 0:
                    blocked_until = now + backoff
                    retry_after = max(retry_after, backoff)
            conn.execute(
                """
                INSERT INTO login_throttle (
                    scope_type, subject, failure_count, first_failed_at, last_failed_at, blocked_until
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_type, subject) DO UPDATE SET
                    failure_count=excluded.failure_count,
                    first_failed_at=excluded.first_failed_at,
                    last_failed_at=excluded.last_failed_at,
                    blocked_until=excluded.blocked_until
                """,
                (scope_type, subject, failure_count, first_failed_at, now, blocked_until),
            )
    return max(int(retry_after), 0)


def register_login_success(username: str, remote_addr: str) -> None:
    ensure_login_throttle_db()
    with _db_conn() as conn:
        for scope_type, subject, _threshold in _scope_rows(username, remote_addr):
            conn.execute(
                "DELETE FROM login_throttle WHERE scope_type=? AND subject=?",
                (scope_type, subject),
            )
