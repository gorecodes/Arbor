from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import pwd
import grp
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .config_env import env_value

_AUTH_DB_PATH_ENV = "ARBOR_AUTH_DB"
_AUTOHEAL_PERMS_ENV = "ARBOR_AUTH_AUTOHEAL_PERMS"
_DEFAULT_AUTH_DB_PATH = "/var/lib/arbor/auth.db"
_HASH_SCHEME = "scrypt"
# Keep default profile strong but compatible with constrained OpenSSL builds.
# Parameters are encoded in stored hash, so future tuning remains migration-safe.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_SALT_BYTES = 16
_SYSTEM_OWNER = "arbor"
_SYSTEM_GROUP = "arbor"
_ALLOWED_ROLES = {"owner", "operator", "viewer"}
log = logging.getLogger(__name__)


def auth_db_path() -> Path:
    return Path(env_value(_AUTH_DB_PATH_ENV, _DEFAULT_AUTH_DB_PATH))


def _is_system_auth_db(path: Path) -> bool:
    if os.environ.get(_AUTH_DB_PATH_ENV):
        return False
    return str(path) == _DEFAULT_AUTH_DB_PATH


def _autoheal_permissions_enabled() -> bool:
    raw = env_value(_AUTOHEAL_PERMS_ENV, "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _fix_system_auth_db_permissions(path: Path) -> None:
    if os.geteuid() != 0:
        return
    if not _autoheal_permissions_enabled():
        return
    if not _is_system_auth_db(path):
        return
    try:
        uid = pwd.getpwnam(_SYSTEM_OWNER).pw_uid
        gid = grp.getgrnam(_SYSTEM_GROUP).gr_gid
    except KeyError:
        return
    parent = path.parent
    try:
        if parent.exists() and parent.is_symlink():
            log.warning(
                "local_auth auto-heal skipped: symlinked parent path path=%s parent=%s",
                path,
                parent,
            )
            return
        if path.exists() and path.is_symlink():
            log.warning(
                "local_auth auto-heal skipped: symlinked db path path=%s",
                path,
            )
            return
    except OSError:
        log.warning(
            "local_auth auto-heal skipped: failed symlink safety check path=%s",
            path,
            exc_info=True,
        )
        return
    parent.mkdir(parents=True, exist_ok=True)
    try:
        parent_stat = parent.stat()
        if parent_stat.st_uid != uid or parent_stat.st_gid != gid:
            log.warning(
                "local_auth auto-heal ownership transition target=dir path=%s from_uid=%s from_gid=%s to_uid=%s to_gid=%s",
                parent,
                parent_stat.st_uid,
                parent_stat.st_gid,
                uid,
                gid,
            )
    except OSError:
        pass
    os.chown(parent, uid, gid)
    os.chmod(parent, 0o750)
    if path.exists():
        try:
            file_stat = path.stat()
            if file_stat.st_uid != uid or file_stat.st_gid != gid:
                log.warning(
                    "local_auth auto-heal ownership transition target=file path=%s from_uid=%s from_gid=%s to_uid=%s to_gid=%s",
                    path,
                    file_stat.st_uid,
                    file_stat.st_gid,
                    uid,
                    gid,
                )
        except OSError:
            pass
        os.chown(path, uid, gid)
        os.chmod(path, 0o640)


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


def ensure_auth_db() -> None:
    path = auth_db_path()
    with _db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS local_user (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                last_login_at REAL,
                password_changed_at REAL,
                disabled_at REAL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                user_id TEXT,
                session_id TEXT,
                event_type TEXT NOT NULL,
                result TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_local_user_username ON local_user(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_created_at ON auth_events(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_events_user_id ON auth_events(user_id)")
    _fix_system_auth_db_permissions(path)


def has_local_users() -> bool:
    ensure_auth_db()
    with _db_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM local_user").fetchone()
        return bool(row and int(row[0]) > 0)


def _scrypt_digest(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    salt = os.urandom(_SALT_BYTES)
    digest = _scrypt_digest(password, salt)
    return "$".join(
        (
            _HASH_SCHEME,
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, stored_hash: str) -> bool:
    if not password or not stored_hash:
        return False
    try:
        scheme, n_raw, r_raw, p_raw, salt_raw, digest_raw = stored_hash.split("$", 5)
        if scheme != _HASH_SCHEME:
            return False
        n = int(n_raw)
        r = int(r_raw)
        p = int(p_raw)
        salt = base64.b64decode(salt_raw.encode("ascii"))
        expected = base64.b64decode(digest_raw.encode("ascii"))
    except Exception:
        return False

    try:
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
    except Exception:
        return False
    return hmac.compare_digest(candidate, expected)


def normalize_role(role: str) -> str:
    value = str(role or "").strip().lower()
    if value not in _ALLOWED_ROLES:
        raise ValueError(f"invalid role '{role}', expected one of: owner, operator, viewer")
    return value


def create_local_user(username: str, password: str, role: str = "owner") -> dict:
    uname = username.strip()
    if not uname:
        raise ValueError("username must not be empty")
    user_role = normalize_role(role)
    password_hash = hash_password(password)
    now = time.time()
    user_id = secrets.token_hex(16)
    ensure_auth_db()
    with _db_conn() as conn:
        conn.execute(
            """
            INSERT INTO local_user (
                user_id, username, password_hash, role, created_at, updated_at, password_changed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, uname, password_hash, user_role, now, now, now),
        )
    return {"user_id": user_id, "username": uname, "role": user_role}


def list_local_users() -> list[dict]:
    ensure_auth_db()
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT user_id, username, role, created_at, last_login_at, disabled_at
            FROM local_user
            ORDER BY username ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def set_local_user_role(username: str, role: str) -> dict | None:
    uname = str(username or "").strip()
    if not uname:
        raise ValueError("username must not be empty")
    user_role = normalize_role(role)
    now = time.time()
    ensure_auth_db()
    with _db_conn() as conn:
        conn.execute(
            "UPDATE local_user SET role=?, updated_at=? WHERE username=?",
            (user_role, now, uname),
        )
        if conn.total_changes <= 0:
            return None
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT user_id, username, role FROM local_user WHERE username=?",
            (uname,),
        ).fetchone()
    return dict(row) if row is not None else None


def find_user_by_username(username: str) -> dict | None:
    ensure_auth_db()
    uname = username.strip()
    if not uname:
        return None
    with _db_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT user_id, username, password_hash, role, created_at, updated_at, last_login_at, disabled_at
            FROM local_user WHERE username=?
            """,
            (uname,),
        ).fetchone()
    return dict(row) if row is not None else None


def mark_login_success(user_id: str) -> None:
    now = time.time()
    ensure_auth_db()
    with _db_conn() as conn:
        conn.execute(
            "UPDATE local_user SET last_login_at=?, updated_at=? WHERE user_id=?",
            (now, now, user_id),
        )
        conn.execute(
            """
            INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
            VALUES (?, ?, NULL, 'login_succeeded', 'ok', '{}')
            """,
            (now, user_id),
        )


def record_login_failure(username: str) -> None:
    now = time.time()
    ensure_auth_db()
    details = '{"username":"' + username.replace('"', '\\"') + '"}'
    with _db_conn() as conn:
        conn.execute(
            """
            INSERT INTO auth_events (created_at, user_id, session_id, event_type, result, details_json)
            VALUES (?, NULL, NULL, 'login_failed', 'denied', ?)
            """,
            (now, details),
        )
