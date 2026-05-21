"""
Entry point: starts uvicorn with TLS.
Certificate paths are read from /etc/arbor/arbor.env or env vars.
"""

import copy
import logging
import os
import sys

import uvicorn
from uvicorn.config import LOGGING_CONFIG

from .approval_mode import ApprovalMode, ApprovalModeError, validate_approval_mode_config
from .config_env import env_int, env_value
from .ipc_auth import IPCAuthError, load_ipc_key


class _StripQueryStringFilter(logging.Filter):
    def filter(self, record):
        args = getattr(record, "args", None)
        if not isinstance(args, tuple) or len(args) < 3 or not isinstance(args[2], str):
            return True
        path = args[2]
        if "?" not in path:
            return True
        record.args = (*args[:2], path.split("?", 1)[0], *args[3:])
        return True


def _log_config():
    config = copy.deepcopy(LOGGING_CONFIG)
    config.setdefault("filters", {})["strip_query_string"] = {
        "()": "arbor.server._StripQueryStringFilter",
    }
    access = config.get("handlers", {}).get("access")
    if access is not None:
        access.setdefault("filters", []).append("strip_query_string")
    return config


def _report_approval_mode(mode: ApprovalMode) -> None:
    if mode is ApprovalMode.NONE:
        print(
            "[arbor] WARNING: ARBOR_APPROVAL_MODE=none — secondary approval is disabled; "
            "privileged operations will run without extra confirmation",
            flush=True,
        )
        return
    if mode is ApprovalMode.TOTP:
        print("[arbor] INFO: ARBOR_APPROVAL_MODE=totp — approval TOTP mode is configured", flush=True)
        return
    print("[arbor] INFO: ARBOR_APPROVAL_MODE=cli — approvals require arbor-approve in a root shell", flush=True)


def run():
    host = env_value("ARBOR_HOST", "127.0.0.1")
    port = env_int("ARBOR_PORT", 8443)
    cert = env_value("ARBOR_CERT", "/etc/arbor/cert.pem")
    key = env_value("ARBOR_KEY", "/etc/arbor/key.pem")

    tls = os.path.exists(cert) and os.path.exists(key)
    if not tls:
        # The bearer token would be sent in clear over plain HTTP. Require an
        # explicit opt-in so accidental misconfiguration doesn't silently
        # downgrade security.
        if env_value("ARBOR_ALLOW_PLAINTEXT") != "1":
            print(
                f"[arbor] ERROR: TLS cert/key not found ({cert}, {key}).\n"
                f"[arbor] Refusing to start in plain HTTP. Either provide the\n"
                f"[arbor] certificate or set ARBOR_ALLOW_PLAINTEXT=1 for dev.",
                file=sys.stderr,
            )
            sys.exit(2)
        print("[arbor] WARNING: ARBOR_ALLOW_PLAINTEXT=1 — running plain HTTP", flush=True)

    try:
        load_ipc_key()
    except IPCAuthError as exc:
        print(f"[arbor] ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        mode = validate_approval_mode_config()
    except ApprovalModeError as exc:
        print(f"[arbor] ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    _report_approval_mode(mode)

    uvicorn.run(
        "arbor.main:app",
        host=host,
        port=port,
        ssl_certfile=cert if tls else None,
        ssl_keyfile=key if tls else None,
        log_level="info",
        log_config=_log_config(),
    )


if __name__ == "__main__":
    run()
