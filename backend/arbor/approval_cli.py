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
    _ = args
    print(
        "[arbor-approve] ERROR: TOTP enable/disable is managed from the Arbor web UI by an owner account",
        file=sys.stderr,
    )
    return 2


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
                "[arbor-approve] ERROR: ARBOR_APPROVAL_MODE must be 'cli' to approve from the terminal",
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

    totp_parser = sub.add_parser("totp-setup", help="Show migration guidance; TOTP setup now lives in the web UI")
    totp_parser.add_argument("--rotate", action="store_true", help=argparse.SUPPRESS)
    totp_parser.add_argument("--issuer", default="", help=argparse.SUPPRESS)
    totp_parser.add_argument("--account-name", default="", help=argparse.SUPPRESS)
    totp_parser.set_defaults(func=_cmd_totp_setup)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
