from __future__ import annotations

import argparse
import grp
import io
import json
import os
import pwd
import sys
from datetime import datetime
from pathlib import Path

import daemon.main as daemon_main

from .approval_mode import (
    ApprovalMode,
    ApprovalModeError,
    build_totp_uri,
    generate_totp_secret,
    get_approval_mode,
    get_totp_account_name,
    get_totp_issuer,
    get_totp_secret,
    totp_secret_path,
)
from .config_env import env_file_path


def _require_root() -> None:
    if os.geteuid() != 0:
        print("[arbor-approve] ERROR: run as root", file=sys.stderr)
        raise SystemExit(2)


def _fmt_ts(value: object) -> str:
    try:
        return datetime.fromtimestamp(float(value)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    except (TypeError, ValueError, OSError):
        return str(value)


def _safe_terminal_text(value: object) -> str:
    text = str(value)
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch.isprintable() and ch not in {"\n", "\r", "\t"}:
            out.append(ch)
        elif code <= 0xFF:
            out.append(f"\\x{code:02x}")
        else:
            out.append(f"\\u{code:04x}")
    return "".join(out)


def _cancel_request(request: dict) -> int:
    cancelled = daemon_main._approval_cancel(request["request_id"])
    if "error" in cancelled:
        print(f"[arbor-approve] ERROR: {cancelled['error']}", file=sys.stderr)
        return 1
    print()
    target = _safe_terminal_text(str(request.get("action_target", "")).strip())
    if target:
        print(f"Cancelled request {_safe_terminal_text(request['request_id'])} for {target}.")
    else:
        print(f"Cancelled request {_safe_terminal_text(request['request_id'])}.")
    return 0


def _print_request(request: dict) -> None:
    print(f"request_id: {_safe_terminal_text(request['request_id'])}")
    print(f"status:     {_safe_terminal_text(request['status'])}")
    print(f"action:     {_safe_terminal_text(request['action_cmd'])}")
    print(f"class:      {_safe_terminal_text(request['action_class'])}")
    if request.get("action_target"):
        print(f"target:     {_safe_terminal_text(request['action_target'])}")
    print(f"created_at: {_fmt_ts(request['created_at'])}")
    print(f"expires_at: {_fmt_ts(request['expires_at'])}")
    print("plan:")
    print(json.dumps(request.get("args", {}), indent=2, sort_keys=True))


def _set_owner_if_present(path: Path, user: str = "arbor", group: str = "arbor") -> None:
    try:
        uid = pwd.getpwnam(user).pw_uid
        gid = grp.getgrnam(group).gr_gid
        os.chown(path, uid, gid)
    except (KeyError, PermissionError, OSError):
        return


def _write_secret_file(path: Path, secret: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{secret}\n", encoding="utf-8")
    os.chmod(path, 0o600)
    _set_owner_if_present(path)


def _upsert_env_file(assignments: dict[str, str]) -> Path:
    path = env_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(assignments)
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
        if sep and key in remaining:
            updated_lines.append(f"{prefix}{key}={remaining.pop(key)}")
            continue
        updated_lines.append(raw_line)

    for key, value in remaining.items():
        updated_lines.append(f"{key}={value}")

    path.write_text("\n".join(updated_lines).rstrip() + "\n", encoding="utf-8")
    os.chmod(path, 0o640)
    _set_owner_if_present(path, user="root", group="arbor")
    return path


def _render_terminal_qr(uri: str) -> str:
    try:
        import qrcode
    except ImportError as exc:
        raise RuntimeError(
            "terminal QR rendering requires the optional 'qrcode' Python package"
        ) from exc
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    qr.make(fit=True)
    out = io.StringIO()
    qr.print_ascii(out=out, tty=False, invert=True)
    return out.getvalue().rstrip()


def _cmd_totp_setup(args: argparse.Namespace) -> int:
    _require_root()
    try:
        mode = get_approval_mode()
    except ApprovalModeError as exc:
        print(f"[arbor-approve] ERROR: {exc}", file=sys.stderr)
        return 2

    env_secret = os.environ.get("ARBOR_TOTP_SECRET", "").strip()
    source = "environment"
    status = "existing"
    secret_path = totp_secret_path()
    if env_secret:
        if args.rotate:
            print(
                "[arbor-approve] ERROR: cannot rotate a TOTP secret provided through ARBOR_TOTP_SECRET; update the environment value or switch to ARBOR_TOTP_SECRET_FILE",
                file=sys.stderr,
            )
            return 2
        secret = get_totp_secret()
    else:
        source = str(secret_path)
        if args.rotate or not secret_path.exists():
            secret = generate_totp_secret()
            _write_secret_file(secret_path, secret)
            status = "generated"
        else:
            try:
                secret = get_totp_secret()
            except ApprovalModeError as exc:
                print(f"[arbor-approve] ERROR: {exc}", file=sys.stderr)
                return 2

    issuer = args.issuer.strip() if args.issuer else get_totp_issuer()
    account_name = args.account_name.strip() if args.account_name else get_totp_account_name()
    uri = build_totp_uri(secret, issuer=issuer, account_name=account_name)
    env_updates = {"ARBOR_AUTH_MODE": "totp"}
    if not env_secret:
        env_updates["ARBOR_TOTP_SECRET_FILE"] = str(secret_path)
    if args.issuer:
        env_updates["ARBOR_TOTP_ISSUER"] = issuer
    if args.account_name:
        env_updates["ARBOR_TOTP_ACCOUNT_NAME"] = account_name
    updated_env_path = _upsert_env_file(env_updates)

    print("Arbor TOTP provisioning")
    print(f"mode:          {mode.value}")
    print(f"secret source: {source} ({status})")
    print(f"env file:      {updated_env_path}")
    print(f"issuer:        {issuer}")
    print(f"account:       {account_name}")
    print()
    print("Manual entry secret:")
    print(secret)
    print()
    try:
        print("Scan this QR code with Google Authenticator, Aegis, or another TOTP app:")
        print(_render_terminal_qr(uri))
        print()
    except RuntimeError as exc:
        print(f"[arbor-approve] WARNING: {exc}", file=sys.stderr)
        print("QR rendering unavailable; use the secret or otpauth URI below for manual setup.")
        print()
    print("otpauth URI:")
    print(uri)
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    _require_root()
    daemon_main._db_init()
    items = daemon_main._approval_request_list("pending")
    if not items:
        print("No pending approval requests.")
        return 0
    for item in items:
        target = f" target={_safe_terminal_text(item['action_target'])}" if item.get("action_target") else ""
        print(
            f"{_safe_terminal_text(item['request_id'])}  "
            f"class={_safe_terminal_text(item['action_class'])} "
            f"action={_safe_terminal_text(item['action_cmd'])}{target}"
        )
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    _require_root()
    daemon_main._db_init()
    request = daemon_main._approval_request_get(args.request_id)
    if not request:
        print(f"[arbor-approve] ERROR: request {args.request_id} not found", file=sys.stderr)
        return 1
    _print_request(request)
    return 0


def _cmd_approve(args: argparse.Namespace) -> int:
    _require_root()
    try:
        if get_approval_mode() is not ApprovalMode.CLI:
            print(
                "[arbor-approve] ERROR: ARBOR_AUTH_MODE must be 'cli' to approve from the terminal",
                file=sys.stderr,
            )
            return 2
    except ApprovalModeError as exc:
        print(f"[arbor-approve] ERROR: {exc}", file=sys.stderr)
        return 2
    daemon_main._db_init()
    request = daemon_main._approval_request_get(args.request_id)
    if not request:
        print(f"[arbor-approve] ERROR: request {args.request_id} not found", file=sys.stderr)
        return 1
    _print_request(request)
    print()
    tier = str(request.get("confirmation_tier", "standard")).strip() or "standard"
    phrase = str(request.get("confirmation_phrase", "")).strip()
    try:
        if not args.yes:
            if tier == "strong" and phrase:
                print("This is a high-impact request.")
                print(f"Type exactly: {_safe_terminal_text(phrase)}")
                entered = input("> ").strip()
                if entered != phrase:
                    return _cancel_request(request)
            else:
                entered = input("Approve this request? [y/N] ").strip().lower()
                if entered not in {"y", "yes"}:
                    return _cancel_request(request)
    except KeyboardInterrupt:
        return _cancel_request(request)
    issued = daemon_main._approval_issue_token(args.request_id, {"method": "cli"})
    if "error" in issued:
        print(f"[arbor-approve] ERROR: {issued['error']}", file=sys.stderr)
        return 1
    print()
    target = _safe_terminal_text(str(request.get("action_target", "")).strip())
    if target:
        print(f"Approved request {_safe_terminal_text(issued['request_id'])} for {target}.")
    else:
        print(f"Approved request {_safe_terminal_text(issued['request_id'])}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arbor-approve")
    sub = parser.add_subparsers(dest="cmd", required=True)

    list_parser = sub.add_parser("list", help="List pending approval requests")
    list_parser.set_defaults(func=_cmd_list)

    show_parser = sub.add_parser("show", help="Show a pending approval request")
    show_parser.add_argument("request_id")
    show_parser.set_defaults(func=_cmd_show)

    approve_parser = sub.add_parser("approve", help="Approve a pending request")
    approve_parser.add_argument("request_id")
    approve_parser.add_argument("-y", "--yes", action="store_true", help="Approve without interactive confirmation")
    approve_parser.set_defaults(func=_cmd_approve)

    totp_parser = sub.add_parser("totp-setup", help="Show or generate the Arbor TOTP secret and QR code")
    totp_parser.add_argument("--rotate", action="store_true", help="Generate and persist a fresh file-backed TOTP secret")
    totp_parser.add_argument("--issuer", default="", help="Override the TOTP issuer label")
    totp_parser.add_argument("--account-name", default="", help="Override the TOTP account label")
    totp_parser.set_defaults(func=_cmd_totp_setup)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
