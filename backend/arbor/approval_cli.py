from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime

import daemon.main as daemon_main


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
    issued = daemon_main._approval_issue_token(args.request_id)
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
