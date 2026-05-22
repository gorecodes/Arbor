"""
Shared IPC authentication helpers for web <-> daemon requests.

Protocol v2 (current): each request carries a 16-byte nonce and a unix
timestamp inside the HMAC-signed payload. The daemon checks freshness
(|now - ts| <= 30s) and rejects replays via an LRU nonce cache; this
module is wire-only.
"""

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

IPC_KEY_ENV = "ARBOR_IPC_KEY"
IPC_KEY_FILE_ENV = "ARBOR_IPC_KEY_FILE"
DEFAULT_IPC_KEY_FILE = "/etc/arbor/ipc.key"
IPC_AUTH_ALG = "hmac-sha256"
IPC_PROTOCOL_VERSION = 2

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


def _canonical_request(cmd: str, args: dict, nonce: str, ts: float) -> bytes:
    return json.dumps(
        {"v": IPC_PROTOCOL_VERSION, "cmd": cmd, "args": args, "nonce": nonce, "ts": ts},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hmac_hex(payload: bytes) -> str:
    return hmac.new(load_ipc_key(), payload, hashlib.sha256).hexdigest()


def sign_request(cmd: str, args: dict | None = None) -> dict:
    normalized_args = args or {}
    if not isinstance(normalized_args, dict):
        raise IPCAuthError("IPC args must be an object")
    nonce = secrets.token_hex(16)
    ts = time.time()
    payload = _canonical_request(cmd, normalized_args, nonce, ts)
    return {
        "v": IPC_PROTOCOL_VERSION,
        "cmd": cmd,
        "args": normalized_args,
        "nonce": nonce,
        "ts": ts,
        "auth": {"alg": IPC_AUTH_ALG, "sig": _hmac_hex(payload)},
    }


def verify_request(request: dict) -> tuple[str, dict, str, float]:
    if not isinstance(request, dict):
        raise IPCAuthError("invalid request object")

    version = request.get("v")
    if version != IPC_PROTOCOL_VERSION:
        raise IPCAuthError(f"unsupported IPC protocol version: {version!r}")

    cmd = request.get("cmd")
    args = request.get("args", {})
    nonce = request.get("nonce")
    ts = request.get("ts")
    auth = request.get("auth")

    if not isinstance(cmd, str) or not cmd:
        raise IPCAuthError("missing command")
    if not isinstance(args, dict):
        raise IPCAuthError("invalid args")
    if not isinstance(nonce, str) or len(nonce) != 32:
        raise IPCAuthError("missing or invalid nonce")
    if not isinstance(ts, (int, float)):
        raise IPCAuthError("missing or invalid timestamp")
    if not isinstance(auth, dict):
        raise IPCAuthError("missing IPC auth")
    if auth.get("alg") != IPC_AUTH_ALG:
        raise IPCAuthError("unsupported IPC auth algorithm")

    sig = auth.get("sig")
    if not isinstance(sig, str) or not sig:
        raise IPCAuthError("missing IPC auth signature")

    expected = _hmac_hex(_canonical_request(cmd, args, nonce, float(ts)))
    if not hmac.compare_digest(sig, expected):
        raise IPCAuthError("invalid IPC auth signature")

    return cmd, args, nonce, float(ts)
