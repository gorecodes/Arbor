"""
Entry point: starts uvicorn with TLS.
Certificate paths are read from /etc/arbor/arbor.conf or env vars.
"""

import copy
import logging
import os
import sys

import uvicorn
from uvicorn.config import LOGGING_CONFIG

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


def run():
    host = os.environ.get("ARBOR_HOST", "127.0.0.1")
    port = int(os.environ.get("ARBOR_PORT", "8443"))
    cert = os.environ.get("ARBOR_CERT", "/etc/arbor/cert.pem")
    key = os.environ.get("ARBOR_KEY", "/etc/arbor/key.pem")

    tls = os.path.exists(cert) and os.path.exists(key)
    if not tls:
        # The bearer token would be sent in clear over plain HTTP. Require an
        # explicit opt-in so accidental misconfiguration doesn't silently
        # downgrade security.
        if os.environ.get("ARBOR_ALLOW_PLAINTEXT") != "1":
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
