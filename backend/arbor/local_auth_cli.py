from __future__ import annotations

import argparse
import getpass
import os
import sys

from .local_auth import (
    create_local_user,
    has_local_users,
    list_local_users,
    normalize_role,
    set_local_user_role,
)


def _require_privileges() -> None:
    if os.geteuid() == 0:
        return
    if os.environ.get("ARBOR_AUTH_DB"):
        return
    print("[arbor-auth] ERROR: run as root (or set ARBOR_AUTH_DB for non-system testing)", file=sys.stderr)
    raise SystemExit(2)


def _cmd_status(_args: argparse.Namespace) -> int:
    _require_privileges()
    print("initialized" if has_local_users() else "empty")
    return 0


def _cmd_create_owner(args: argparse.Namespace) -> int:
    _require_privileges()
    if has_local_users() and not args.force:
        print("[arbor-auth] ERROR: local user already exists; use --force to add another", file=sys.stderr)
        return 1

    username = (args.username or "").strip()
    if not username:
        print("[arbor-auth] ERROR: --username is required", file=sys.stderr)
        return 2

    if args.password:
        password = args.password
    else:
        p1 = getpass.getpass("Owner password: ")
        p2 = getpass.getpass("Repeat password: ")
        if p1 != p2:
            print("[arbor-auth] ERROR: password mismatch", file=sys.stderr)
            return 2
        password = p1

    if len(password) < 8:
        print("[arbor-auth] ERROR: password too short (min 8 chars)", file=sys.stderr)
        return 2

    user = create_local_user(username, password, role="owner")
    print(f"created owner user_id={user['user_id']} username={user['username']}")
    return 0


def _cmd_create_user(args: argparse.Namespace) -> int:
    _require_privileges()
    username = (args.username or "").strip()
    if not username:
        print("[arbor-auth] ERROR: --username is required", file=sys.stderr)
        return 2
    try:
        role = normalize_role(args.role)
    except ValueError as exc:
        print(f"[arbor-auth] ERROR: {exc}", file=sys.stderr)
        return 2
    if args.password:
        password = args.password
    else:
        p1 = getpass.getpass(f"Password for {username}: ")
        p2 = getpass.getpass("Repeat password: ")
        if p1 != p2:
            print("[arbor-auth] ERROR: password mismatch", file=sys.stderr)
            return 2
        password = p1
    if len(password) < 8:
        print("[arbor-auth] ERROR: password too short (min 8 chars)", file=sys.stderr)
        return 2
    try:
        user = create_local_user(username, password, role=role)
    except Exception as exc:
        print(f"[arbor-auth] ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"created user_id={user['user_id']} username={user['username']} role={user['role']}")
    return 0


def _cmd_list_users(_args: argparse.Namespace) -> int:
    _require_privileges()
    users = list_local_users()
    if not users:
        print("no users")
        return 0
    for user in users:
        status = "disabled" if user.get("disabled_at") is not None else "active"
        print(f"{user['username']}\t{user['role']}\t{status}\t{user['user_id']}")
    return 0


def _cmd_set_role(args: argparse.Namespace) -> int:
    _require_privileges()
    username = (args.username or "").strip()
    if not username:
        print("[arbor-auth] ERROR: --username is required", file=sys.stderr)
        return 2
    try:
        role = normalize_role(args.role)
    except ValueError as exc:
        print(f"[arbor-auth] ERROR: {exc}", file=sys.stderr)
        return 2
    user = set_local_user_role(username, role)
    if user is None:
        print(f"[arbor-auth] ERROR: user '{username}' not found", file=sys.stderr)
        return 1
    print(f"updated username={user['username']} role={user['role']}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arbor-auth")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="show local auth store status")
    status.set_defaults(fn=_cmd_status)

    create_owner = sub.add_parser("create-owner", help="create first local owner user")
    create_owner.add_argument("--username", required=True)
    create_owner.add_argument("--password", default="")
    create_owner.add_argument("--force", action="store_true")
    create_owner.set_defaults(fn=_cmd_create_owner)

    create_user = sub.add_parser("create-user", help="create a local user with explicit role")
    create_user.add_argument("--username", required=True)
    create_user.add_argument("--role", required=True, choices=["owner", "operator", "viewer"])
    create_user.add_argument("--password", default="")
    create_user.set_defaults(fn=_cmd_create_user)

    list_users = sub.add_parser("list-users", help="list local users")
    list_users.set_defaults(fn=_cmd_list_users)

    set_role = sub.add_parser("set-role", help="update role for an existing user")
    set_role.add_argument("--username", required=True)
    set_role.add_argument("--role", required=True, choices=["owner", "operator", "viewer"])
    set_role.set_defaults(fn=_cmd_set_role)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
