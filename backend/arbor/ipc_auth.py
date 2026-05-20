"""
Shared IPC authentication helpers for web <-> daemon requests.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path

IPC_KEY_ENV = "ARBOR_IPC_KEY"
IPC_KEY_FILE_ENV = "ARBOR_IPC_KEY_FILE"
DEFAULT_IPC_KEY_FILE = "/etc/arbor/ipc.key"
IPC_AUTH_ALG = "hmac-sha256"

_cached_ipc_key: bytes | None = None


class IPCAuthError(RuntimeError):
    pass


def load_ipc_key() -> bytes:
    global _cached_ipc_key
    if _cached_ipc_key is not None:
        return _cached_ipc_key

    env_value = os.environ.get(IPC_KEY_ENV, "").strip()
    if env_value:
        _cached_ipc_key = env_value.encode("utf-8")
        return _cached_ipc_key

    key_path = Path(os.environ.get(IPC_KEY_FILE_ENV, DEFAULT_IPC_KEY_FILE))
    try:
        key_value = key_path.read_text().strip()
    except FileNotFoundError as exc:
        raise IPCAuthError(
            f"missing IPC key: set {IPC_KEY_ENV} or create {key_path}"
        ) from exc
    except PermissionError as exc:
        raise IPCAuthError(
            f"cannot read IPC key from {key_path}: set {IPC_KEY_ENV} or fix file permissions"
        ) from exc
    except OSError as exc:
        raise IPCAuthError(f"cannot read IPC key from {key_path}: {exc}") from exc

    if not key_value:
        raise IPCAuthError(f"empty IPC key: {key_path}")

    _cached_ipc_key = key_value.encode("utf-8")
    return _cached_ipc_key


def _canonical_request(cmd: str, args: dict) -> bytes:
    return json.dumps(
        {"cmd": cmd, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_auth(cmd: str, args: dict) -> dict:
    sig = hmac.new(
        load_ipc_key(),
        _canonical_request(cmd, args),
        hashlib.sha256,
    ).hexdigest()
    return {"alg": IPC_AUTH_ALG, "sig": sig}


def sign_request(cmd: str, args: dict | None = None) -> dict:
    normalized_args = args or {}
    if not isinstance(normalized_args, dict):
        raise IPCAuthError("IPC args must be an object")
    return {
        "cmd": cmd,
        "args": normalized_args,
        "auth": build_auth(cmd, normalized_args),
    }


def verify_request(request: dict) -> tuple[str, dict]:
    if not isinstance(request, dict):
        raise IPCAuthError("invalid request object")

    cmd = request.get("cmd")
    args = request.get("args", {})
    auth = request.get("auth")

    if not isinstance(cmd, str) or not cmd:
        raise IPCAuthError("missing command")
    if not isinstance(args, dict):
        raise IPCAuthError("invalid args")
    if not isinstance(auth, dict):
        raise IPCAuthError("missing IPC auth")
    if auth.get("alg") != IPC_AUTH_ALG:
        raise IPCAuthError("unsupported IPC auth algorithm")

    sig = auth.get("sig")
    if not isinstance(sig, str) or not sig:
        raise IPCAuthError("missing IPC auth signature")

    expected = build_auth(cmd, args)["sig"]
    if not hmac.compare_digest(sig, expected):
        raise IPCAuthError("invalid IPC auth signature")

    return cmd, args
