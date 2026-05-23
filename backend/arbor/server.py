"""
Entry point: starts uvicorn with optional TLS.
Certificate paths are read from /etc/arbor/arbor.env or env vars when TLS is enabled.
"""

import copy
import logging
import os
import sys

import uvicorn
from uvicorn.config import LOGGING_CONFIG

from .approval_mode import ApprovalMode, ApprovalModeError, validate_approval_mode_config
from .config_env import env_int, env_list, env_value
from .ipc_auth import IPCAuthError, load_ipc_key

ARBOR_TRUSTED_PROXIES_ENV = "ARBOR_TRUSTED_PROXIES"

_TLS_ENABLED_VALUES = {"1", "true", "yes", "on"}
_TLS_DISABLED_VALUES = {"0", "false", "no", "off"}
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "ip6-localhost"}


def _is_loopback_host(host: str) -> bool:
    return host.strip().lower() in _LOOPBACK_HOSTS


def _enforce_loopback_or_tls(host: str, tls: bool) -> None:
    if tls or _is_loopback_host(host):
        return
    if env_value("ARBOR_ALLOW_PLAINTEXT") == "1":
        print(
            f"[arbor] WARNING: ARBOR_ALLOW_PLAINTEXT=1 — plain HTTP on {host!r}. "
            "Only safe behind a VPN or trusted private network.",
            flush=True,
        )
        return
    print(
        f"[arbor] ERROR: refusing to bind {host!r} without TLS. Plain HTTP is only\n"
        f"[arbor] permitted on loopback (127.0.0.1, ::1, localhost). Provide a\n"
        f"[arbor] TLS certificate (ARBOR_CERT, ARBOR_KEY) or place this instance\n"
        f"[arbor] behind a TLS-terminating reverse proxy and bind to 127.0.0.1.\n"
        f"[arbor] To allow plain HTTP on a private/VPN interface set ARBOR_ALLOW_PLAINTEXT=1.",
        file=sys.stderr,
    )
    sys.exit(2)


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


def _resolve_trusted_proxies() -> str:
    """Return the forwarded_allow_ips value for uvicorn.

    Behavior:
      - ARBOR_TRUSTED_PROXIES unset: uvicorn default ('127.0.0.1' only).
      - ARBOR_TRUSTED_PROXIES=<csv list>: that exact list is trusted.
      - ARBOR_TRUSTED_PROXIES='*': trust any peer (use only when the bind
        is otherwise unreachable, e.g. a Unix socket); logs a WARNING.
    """
    raw = env_list(ARBOR_TRUSTED_PROXIES_ENV, [])
    if not raw:
        return "127.0.0.1"
    if raw == ["*"]:
        print(
            "[arbor] WARNING: ARBOR_TRUSTED_PROXIES=* — accepting X-Forwarded-* "
            "from any peer; only safe if the bind is not directly reachable",
            flush=True,
        )
        return "*"
    print(f"[arbor] INFO: trusting X-Forwarded-* from {raw}", flush=True)
    return ",".join(raw)


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


def _tls_override() -> bool | None:
    raw = env_value("ARBOR_TLS", "").strip().lower()
    if not raw:
        return None
    if raw in _TLS_ENABLED_VALUES:
        return True
    if raw in _TLS_DISABLED_VALUES:
        return False
    print(
        f"[arbor] ERROR: invalid ARBOR_TLS={raw!r}; expected one of: "
        "1/0, true/false, yes/no, on/off",
        file=sys.stderr,
    )
    sys.exit(2)


def run():
    host = env_value("ARBOR_HOST", "127.0.0.1")
    port = env_int("ARBOR_PORT", 8443)
    tls_override = _tls_override()
    cert = None
    key = None
    tls = False
    if tls_override is False:
        print("[arbor] INFO: ARBOR_TLS=0 — running plain HTTP", flush=True)
    else:
        cert = env_value("ARBOR_CERT", "/etc/arbor/cert.pem")
        key = env_value("ARBOR_KEY", "/etc/arbor/key.pem")
        tls = os.path.exists(cert) and os.path.exists(key)
        if tls_override is True:
            if not tls:
                print(
                    f"[arbor] ERROR: ARBOR_TLS=1 but TLS cert/key not found ({cert}, {key}).",
                    file=sys.stderr,
                )
                sys.exit(2)
        elif not tls:
            # Legacy behavior for existing deployments that still rely on
            # auto-detecting cert/key presence.
            if env_value("ARBOR_ALLOW_PLAINTEXT") != "1":
                print(
                    f"[arbor] ERROR: TLS cert/key not found ({cert}, {key}).\n"
                    f"[arbor] Refusing to start in plain HTTP. Either provide the\n"
                    f"[arbor] certificate, set ARBOR_TLS=0, or set ARBOR_ALLOW_PLAINTEXT=1.",
                    file=sys.stderr,
                )
                sys.exit(2)
            print("[arbor] WARNING: ARBOR_ALLOW_PLAINTEXT=1 — running plain HTTP", flush=True)

    _enforce_loopback_or_tls(host, tls)

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
        ssl_certfile=cert if tls and cert else None,
        ssl_keyfile=key if tls and key else None,
        log_level="info",
        log_config=_log_config(),
        proxy_headers=True,
        forwarded_allow_ips=_resolve_trusted_proxies(),
    )


if __name__ == "__main__":
    run()
