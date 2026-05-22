from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import socket
import struct
import time
from urllib.parse import quote, urlencode
from enum import StrEnum
from pathlib import Path

from .config_env import env_value, env_value_file_first

LOGIN_AUTH_MODE_ENV = "ARBOR_AUTH_MODE"
APPROVAL_MODE_ENV = "ARBOR_APPROVAL_MODE"
APPROVAL_AUTO_OK_ENV = "ARBOR_ALLOW_AUTO_APPROVAL"
TOTP_SECRET_ENV = "ARBOR_TOTP_SECRET"
TOTP_SECRET_FILE_ENV = "ARBOR_TOTP_SECRET_FILE"
TOTP_ISSUER_ENV = "ARBOR_TOTP_ISSUER"
TOTP_ACCOUNT_NAME_ENV = "ARBOR_TOTP_ACCOUNT_NAME"
DEFAULT_TOTP_SECRET_FILE = "/etc/arbor/totp.secret"
_ACK_TRUE_VALUES = {"1", "true", "yes", "on"}


class ApprovalModeError(RuntimeError):
    pass


class ApprovalMode(StrEnum):
    CLI = "cli"
    TOTP = "totp"
    NONE = "none"


def _parse_mode(raw: str, env_name: str) -> ApprovalMode:
    try:
        return ApprovalMode(raw)
    except ValueError as exc:
        raise ApprovalModeError(
            f"invalid {env_name}={raw!r}; expected one of: cli, totp, none"
        ) from exc


def get_login_auth_mode() -> ApprovalMode:
    raw = env_value_file_first(LOGIN_AUTH_MODE_ENV, ApprovalMode.CLI.value).strip().lower() or ApprovalMode.CLI.value
    return _parse_mode(raw, LOGIN_AUTH_MODE_ENV)


def _default_approval_mode() -> ApprovalMode:
    if get_login_auth_mode() is ApprovalMode.TOTP:
        return ApprovalMode.NONE
    return ApprovalMode.CLI


def get_approval_mode() -> ApprovalMode:
    default_mode = _default_approval_mode().value
    raw = env_value_file_first(APPROVAL_MODE_ENV, default_mode).strip().lower() or default_mode
    return _parse_mode(raw, APPROVAL_MODE_ENV)


def _load_totp_secret_from_file(path: Path) -> str:
    try:
        secret = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise ApprovalModeError(
            f"missing TOTP secret: set {TOTP_SECRET_ENV} or create {path}"
        ) from exc
    except PermissionError as exc:
        raise ApprovalModeError(
            f"cannot read TOTP secret from {path}: set {TOTP_SECRET_ENV} or fix file permissions"
        ) from exc
    except OSError as exc:
        raise ApprovalModeError(f"cannot read TOTP secret from {path}: {exc}") from exc
    if not secret:
        raise ApprovalModeError(f"empty TOTP secret: {path}")
    return secret


def totp_secret_path() -> Path:
    return Path(env_value_file_first(TOTP_SECRET_FILE_ENV, DEFAULT_TOTP_SECRET_FILE).strip() or DEFAULT_TOTP_SECRET_FILE)


def get_totp_secret() -> str:
    # F-19: inline TOTP secrets in the process environment are refused —
    # /proc/<pid>/environ exposes them to any local UID that can read the
    # proc tree. Use the secret file (ARBOR_TOTP_SECRET_FILE, default
    # /etc/arbor/totp.secret, mode 0600).
    env_inline = os.environ.get(TOTP_SECRET_ENV, "").strip()
    if env_inline:
        raise ApprovalModeError(
            f"{TOTP_SECRET_ENV} is no longer accepted from the process environment; "
            f"place the secret in {TOTP_SECRET_FILE_ENV} (default "
            f"{DEFAULT_TOTP_SECRET_FILE}) with mode 0600"
        )
    # arbor.env (file-only) is still tolerated for back-compat with
    # totp_admin.sync_runtime_env writers, but takes second priority to
    # the dedicated secret file.
    file_inline = env_value_file_first(TOTP_SECRET_ENV, "").strip()
    secret = file_inline or _load_totp_secret_from_file(totp_secret_path())
    if not secret:
        raise ApprovalModeError(
            f"TOTP mode requires the secret file {totp_secret_path()}"
        )
    try:
        base64.b32decode(secret.upper(), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ApprovalModeError("TOTP secret must be valid base32") from exc
    return secret


def _auto_approval_acknowledged() -> bool:
    return env_value_file_first(APPROVAL_AUTO_OK_ENV, "").strip().lower() in _ACK_TRUE_VALUES


def validate_approval_mode_config() -> ApprovalMode:
    login_mode = get_login_auth_mode()
    mode = get_approval_mode()

    # Legacy ARBOR_APPROVAL_MODE=totp used to silently degrade to NONE,
    # bypassing per-action approval without any explicit acknowledgement.
    # That mode is removed: surface the misconfiguration loudly.
    if mode is ApprovalMode.TOTP:
        raise ApprovalModeError(
            f"{APPROVAL_MODE_ENV}=totp is no longer supported. Use 'cli' for "
            f"per-action approval, or set 'none' together with "
            f"{APPROVAL_AUTO_OK_ENV}=1 to accept the security trade-off."
        )

    # ARBOR_APPROVAL_MODE=none disables per-action approval; refuse to boot
    # unless the operator explicitly acknowledges the trade-off.
    if mode is ApprovalMode.NONE and not _auto_approval_acknowledged():
        raise ApprovalModeError(
            f"{APPROVAL_MODE_ENV}=none disables per-action approval and is "
            f"refused by default. Set {APPROVAL_AUTO_OK_ENV}=1 to acknowledge "
            f"that any authenticated session can launch privileged operations "
            f"without further confirmation."
        )

    if login_mode is ApprovalMode.TOTP or mode is ApprovalMode.TOTP:
        get_totp_secret()
    return mode


def login_totp_required() -> bool:
    return get_login_auth_mode() is ApprovalMode.TOTP


def effective_approval_mode() -> ApprovalMode:
    mode = get_approval_mode()
    if mode is ApprovalMode.TOTP:
        return ApprovalMode.NONE
    return mode


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def get_totp_issuer() -> str:
    return env_value_file_first(TOTP_ISSUER_ENV, "Arbor").strip() or "Arbor"


def get_totp_account_name() -> str:
    default = f"arbor@{socket.gethostname() or 'localhost'}"
    return env_value_file_first(TOTP_ACCOUNT_NAME_ENV, default).strip() or default


def build_totp_uri(
    secret: str,
    *,
    issuer: str | None = None,
    account_name: str | None = None,
) -> str:
    resolved_issuer = (issuer or get_totp_issuer()).strip() or "Arbor"
    resolved_account = (account_name or get_totp_account_name()).strip() or "arbor@localhost"
    label = quote(f"{resolved_issuer}:{resolved_account}", safe="")
    params = urlencode(
        {
            "secret": secret,
            "issuer": resolved_issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": "30",
        }
    )
    return f"otpauth://totp/{label}?{params}"


def totp_code(secret: str, for_time: float | None = None, *, period: int = 30, digits: int = 6) -> str:
    decoded = base64.b32decode(secret.upper(), casefold=True)
    counter = int((time.time() if for_time is None else for_time) // period)
    digest = hmac.new(decoded, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def verify_totp_code_for_secret(secret: str, code: str) -> bool:
    cleaned = "".join(ch for ch in str(code).strip() if ch.isdigit())
    if not cleaned:
        return False
    now = time.time()
    for offset in (-30, 0, 30):
        if hmac.compare_digest(cleaned, totp_code(secret, now + offset)):
            return True
    return False


def verify_totp_code(code: str) -> bool:
    return verify_totp_code_for_secret(get_totp_secret(), code)
