from __future__ import annotations

import base64
import grp
import os
import pwd
import tempfile
from io import BytesIO
from pathlib import Path

from .approval_mode import (
    LOGIN_AUTH_MODE_ENV,
    TOTP_ACCOUNT_NAME_ENV,
    TOTP_ISSUER_ENV,
    TOTP_SECRET_ENV,
    TOTP_SECRET_FILE_ENV,
    ApprovalMode,
    build_totp_uri,
    generate_totp_secret,
    get_totp_account_name,
    get_totp_issuer,
    totp_secret_path,
)
from .config_env import env_file_path

_ENV_FILE_MODE = 0o640
_SECRET_FILE_MODE = 0o600


def _strip_xml_declaration(svg: str) -> str:
    if svg.startswith("<?xml"):
        _decl, _sep, remainder = svg.partition("?>")
        return remainder.lstrip()
    return svg


def _lookup_user_group(user: str, group: str) -> tuple[int, int] | None:
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        return None


def _write_atomic_text(path: Path, text: str, *, mode: int, owner: str, group: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp_path, mode)
        owner_ids = _lookup_user_group(owner, group)
        if owner_ids is not None:
            try:
                os.chown(tmp_path, owner_ids[0], owner_ids[1])
            except PermissionError:
                pass
        os.replace(tmp_path, path)
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
    return path


def write_totp_secret_file(secret: str, path: Path | None = None) -> Path:
    target = path or totp_secret_path()
    return _write_atomic_text(target, f"{secret.strip()}\n", mode=_SECRET_FILE_MODE, owner="arbor", group="arbor")


def remove_totp_secret_file(path: Path | None = None) -> None:
    target = path or totp_secret_path()
    try:
        target.unlink()
    except FileNotFoundError:
        return


def update_env_file(assignments: dict[str, str] | None = None, *, unset_keys: set[str] | None = None) -> Path:
    path = env_file_path()
    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(assignments or {})
    removals = set(unset_keys or set())
    updated_lines: list[str] = []

    for raw_line in existing_lines:
        stripped = raw_line.strip()
        if stripped.startswith("export "):
            key, sep, _ = stripped[7:].partition("=")
            prefix = "export "
        else:
            key, sep, _ = stripped.partition("=")
            prefix = ""
        key = key.strip()
        if sep and key in removals:
            continue
        if sep and key in remaining:
            updated_lines.append(f"{prefix}{key}={remaining.pop(key)}")
            continue
        updated_lines.append(raw_line)

    for key, value in remaining.items():
        updated_lines.append(f"{key}={value}")

    return _write_atomic_text(
        path,
        "\n".join(updated_lines).rstrip() + "\n",
        mode=_ENV_FILE_MODE,
        owner="root",
        group="arbor",
    )


def sync_runtime_env(assignments: dict[str, str] | None = None, *, unset_keys: set[str] | None = None) -> None:
    for key in set(unset_keys or set()):
        os.environ.pop(key, None)
    for key, value in (assignments or {}).items():
        os.environ[key] = value


def begin_totp_enrollment() -> dict:
    secret_path = totp_secret_path()
    if secret_path.exists():
        secret = secret_path.read_text(encoding="utf-8").strip()
    else:
        secret = generate_totp_secret()
        write_totp_secret_file(secret, secret_path)
    update_env_file(
        {TOTP_SECRET_FILE_ENV: str(secret_path)},
        unset_keys={TOTP_SECRET_ENV},
    )
    sync_runtime_env(
        {TOTP_SECRET_FILE_ENV: str(secret_path)},
        unset_keys={TOTP_SECRET_ENV},
    )
    issuer = get_totp_issuer()
    account_name = get_totp_account_name()
    uri = build_totp_uri(secret, issuer=issuer, account_name=account_name)
    payload = {
        "enabled": False,
        "pending_enrollment": True,
        "issuer": issuer,
        "account_name": account_name,
        "secret_file": str(secret_path),
        "manual_secret": secret,
        "otpauth_uri": uri,
    }
    qr_data_url = render_totp_qr_data_url(uri)
    if qr_data_url:
        payload["qr_data_url"] = qr_data_url
    qr_svg = render_totp_qr_svg(uri)
    if qr_svg:
        payload["qr_svg"] = qr_svg
    return payload


def enable_totp_login(*, secret_path: Path | None = None) -> dict:
    resolved_path = secret_path or totp_secret_path()
    update_env_file(
        {
            LOGIN_AUTH_MODE_ENV: ApprovalMode.TOTP.value,
            TOTP_SECRET_FILE_ENV: str(resolved_path),
        },
        unset_keys={TOTP_SECRET_ENV},
    )
    sync_runtime_env(
        {
            LOGIN_AUTH_MODE_ENV: ApprovalMode.TOTP.value,
            TOTP_SECRET_FILE_ENV: str(resolved_path),
        },
        unset_keys={TOTP_SECRET_ENV},
    )
    return {
        "enabled": True,
        "pending_enrollment": False,
        "issuer": get_totp_issuer(),
        "account_name": get_totp_account_name(),
        "secret_file": str(resolved_path),
    }


def disable_totp_login(*, secret_path: Path | None = None) -> dict:
    resolved_path = secret_path or totp_secret_path()
    remove_totp_secret_file(resolved_path)
    update_env_file(
        {LOGIN_AUTH_MODE_ENV: ApprovalMode.CLI.value},
        unset_keys={TOTP_SECRET_ENV, TOTP_SECRET_FILE_ENV},
    )
    sync_runtime_env(
        {LOGIN_AUTH_MODE_ENV: ApprovalMode.CLI.value},
        unset_keys={TOTP_SECRET_ENV, TOTP_SECRET_FILE_ENV},
    )
    return {
        "enabled": False,
        "pending_enrollment": False,
        "issuer": get_totp_issuer(),
        "account_name": get_totp_account_name(),
    }


def totp_management_status(*, enabled: bool) -> dict:
    secret_path = totp_secret_path()
    pending = not enabled and secret_path.exists()
    payload = {
        "enabled": enabled,
        "pending_enrollment": pending,
        "issuer": get_totp_issuer(),
        "account_name": get_totp_account_name(),
        "secret_file": str(secret_path),
    }
    if pending:
        secret = secret_path.read_text(encoding="utf-8").strip()
        uri = build_totp_uri(secret, issuer=payload["issuer"], account_name=payload["account_name"])
        payload["manual_secret"] = secret
        payload["otpauth_uri"] = uri
        qr_data_url = render_totp_qr_data_url(uri)
        if qr_data_url:
            payload["qr_data_url"] = qr_data_url
        qr_svg = render_totp_qr_svg(uri)
        if qr_svg:
            payload["qr_svg"] = qr_svg
    return payload


def render_totp_qr_data_url(uri: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return ""
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage, border=1)
    buffer = BytesIO()
    image.save(buffer)
    svg = _strip_xml_declaration(buffer.getvalue().decode("utf-8"))
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


def render_totp_qr_svg(uri: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return ""
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgImage, border=1)
    buffer = BytesIO()
    image.save(buffer)
    return _strip_xml_declaration(buffer.getvalue().decode("utf-8"))
