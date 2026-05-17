"""
Entry point: starts uvicorn with TLS.
Certificate paths are read from /etc/arbor/arbor.conf or env vars.
"""

import os
import sys
import uvicorn


def run():
    host = os.environ.get("ARBOR_HOST", "0.0.0.0")
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

    uvicorn.run(
        "arbor.main:app",
        host=host,
        port=port,
        ssl_certfile=cert if tls else None,
        ssl_keyfile=key if tls else None,
        log_level="info",
    )


if __name__ == "__main__":
    run()
