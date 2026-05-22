# Arbor

> This is a hobby project built to scratch my own itch. While I designed the architecture and heavily used AI (Claude) to speed up the boilerplate and implementation, the code has been thoroughly reviewed and tested on my own machine. It works for my workflow, but it is still an early release.

A local-first web UI for managing Portage from a browser on the same machine.

Designed for Gentoo systems in a local environment. Not intended to be exposed to the internet.

## Table of contents

- [Prerequisites](#prerequisites)
- [Install](#install)
- [First run](#first-run)
- [Start at boot](#start-at-boot)
- [Update](#update)
- [Uninstall](#uninstall)
- [Authentication and approval](#authentication-and-approval)
- [Local users and roles](#local-users-and-roles)
- [LAN access](#lan-access)
- [Configuration](#configuration)
- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Security hardening](#security-hardening)
- [Development](#development)
- [Logs](#logs)

## Prerequisites

- Gentoo Linux
- Python 3.11+
- `openssl`
- OpenRC or systemd

## Install

### Via Portage overlay

```bash
eselect repository add arbor-overlay git https://github.com/gorecodes/arbor-overlay.git
emaint sync -r arbor-overlay
echo 'app-admin/arbor openrc' >> /etc/portage/package.use/arbor   # or: systemd
emerge app-admin/arbor
bash /usr/share/arbor/setup.sh
```

After every package upgrade, run setup again:

```bash
bash /usr/share/arbor/setup.sh
```

This keeps `/etc/arbor` assets and `/var/lib/arbor` permissions aligned with the current release (including local-auth DB ownership).

By default this installs the stable overlay version. If you want the live ebuild that tracks `main`:

```bash
echo '=app-admin/arbor-9999 **' >> /etc/portage/package.accept_keywords/arbor
emerge =app-admin/arbor-9999
bash /usr/share/arbor/setup.sh
```

### Via install script

```bash
git clone https://github.com/gorecodes/Arbor
cd Arbor
sudo bash install.sh
```

The installer will:

1. Install the backend to `/usr/lib/arbor/`
2. Create a Python virtual environment with Arbor installed into it
3. Install the Alpine frontend to `/usr/lib/arbor/frontend/`
4. Create `/usr/bin/arbor` and `/usr/bin/arbor-daemon`
5. Install OpenRC or systemd service files, depending on the detected init system
6. Create the `arbor` system user
7. Enforce local auth mode in `/etc/arbor/arbor.env` (`ARBOR_AUTH_BACKEND=local`)
8. Create `/etc/arbor/arbor.env` if it does not already exist
9. Default Arbor to local-first plain HTTP (`ARBOR_TLS=0`)
10. Generate an IPC key in `/etc/arbor/ipc.key` if one does not already exist

After script-based upgrades, run setup again to refresh runtime permissions:

```bash
sudo bash config/setup.sh
```

## First run

**OpenRC:**
```bash
rc-service arbor-daemon start
rc-service arbor start
```

**systemd:**
```bash
systemctl start arbor-daemon arbor
```

Open `http://localhost:8443` or `http://127.0.0.1:8443` in your browser and sign in with the local owner username/password created during setup.

For a first install, keep Arbor on localhost until you are comfortable with the model: an authenticated local session unlocks root-backed package actions, and LAN exposure is still a deliberate tradeoff rather than the default.

## Start at boot

**OpenRC:**
```bash
rc-update add arbor-daemon default
rc-update add arbor default
```

**systemd:**
```bash
systemctl enable arbor-daemon arbor
```

## Update

### Via Portage overlay

```bash
emaint sync -r arbor-overlay
emerge app-admin/arbor
bash /usr/share/arbor/setup.sh
```

For the live ebuild instead:

```bash
emaint sync -r arbor-overlay
emerge =app-admin/arbor-9999
bash /usr/share/arbor/setup.sh
```

Then restart the services:

- **OpenRC:** `rc-service arbor-daemon restart && rc-service arbor restart`
- **systemd:** `systemctl restart arbor-daemon arbor`

### Via install script

```bash
git pull
sudo bash install.sh
```

Then restart the services:

- **OpenRC:** `rc-service arbor-daemon restart && rc-service arbor restart`
- **systemd:** `systemctl restart arbor-daemon arbor`

## Uninstall

### Via Portage overlay

```bash
emerge --unmerge app-admin/arbor
```

Then stop and disable the services:

- **OpenRC:** `rc-service arbor stop && rc-service arbor-daemon stop && rc-update del arbor default && rc-update del arbor-daemon default`
- **systemd:** `systemctl stop arbor arbor-daemon && systemctl disable arbor-daemon arbor`

```bash
userdel arbor
```

### If installed with `install.sh`

**OpenRC:**
```bash
rc-service arbor stop
rc-service arbor-daemon stop
rc-update del arbor default
rc-update del arbor-daemon default
rm -f /etc/init.d/arbor /etc/init.d/arbor-daemon
```

**systemd:**
```bash
systemctl stop arbor arbor-daemon
systemctl disable arbor arbor-daemon
rm -f /usr/lib/systemd/system/arbor.service /usr/lib/systemd/system/arbor-daemon.service
systemctl daemon-reload
```

```bash
rm -f /usr/bin/arbor /usr/bin/arbor-daemon /usr/bin/arbor-approve \
      /usr/local/bin/arbor /usr/local/bin/arbor-daemon /usr/local/bin/arbor-approve
rm -rf /usr/lib/arbor
userdel arbor
```

Configuration, runtime state, logs, and the persisted SQLite job history are not removed automatically:

```bash
rm -rf /etc/arbor /var/log/arbor /run/arbor /var/lib/arbor
```

## Authentication and approval

**Out of the box after a clean install:** password-only login, and privileged actions (install, uninstall, sync, etc.) require a password re-prompt in the browser (step-up re-auth) before they start. No root shell needed.

Two independent knobs let you change this:

- **`ARBOR_AUTH_MODE`** — what is required *at login* (password only, or password + TOTP)
- **`ARBOR_APPROVAL_MODE`** — what is required *per privileged action* after login

They are independent: you can have TOTP at login with CLI approval, or no TOTP with step-up re-auth, or any combination.

**Important:** `ARBOR_AUTH_MODE=totp` requires that TOTP has already been enabled from the **Security page** in the web UI, which generates `/etc/arbor/totp.secret` automatically. Do not add `ARBOR_AUTH_MODE=totp` to the config before doing this or Arbor will refuse to start.

Common `/etc/arbor/arbor.env` setups:

```bash
# Default: password login, browser step-up re-auth for privileged actions
ARBOR_TLS=0
ARBOR_APPROVAL_MODE=none
ARBOR_ALLOW_AUTO_APPROVAL=1

# Alternative: root-shell arbor-approve instead of browser re-prompt
# ARBOR_APPROVAL_MODE=cli
# (remove the two lines above)

# Add TOTP at login on top of either of the above:
# ARBOR_AUTH_MODE=totp
# ARBOR_TOTP_SECRET_FILE=/etc/arbor/totp.secret  # created by the Security page
```

### Login-time TOTP (2FA)

When `ARBOR_AUTH_MODE=totp`, Arbor requires a TOTP code during login in addition to username and password. Codes are generated by a standard TOTP app such as Google Authenticator, Aegis, or similar.

This is a login-time second factor. It is **not** a per-operation confirmation step.

TOTP starts **disabled** by default.

An authenticated `owner` enables or disables it from the **Security** page in the web UI:

1. Open **Security**.
2. Start TOTP enrollment.
3. Scan the secret into your authenticator app.
4. Confirm with the current 6-digit code.
5. Sign in again with TOTP.

To disable TOTP, the owner must enter the **current password** and a fresh **TOTP code** in the same Security page. Arbor revokes existing sessions when login-time TOTP is enabled or disabled so the policy change takes effect cleanly.

**Important:** TOTP improves convenience for trusted local/LAN use, but it does **not** make Arbor suitable for internet exposure. The TOTP code is still a shared second factor for the whole instance, not a per-user hardware-bound proof.

### Approval modes

After login, privileged operations follow `ARBOR_APPROVAL_MODE`:

- `ARBOR_APPROVAL_MODE=none` (default): the authenticated session requires a password re-prompt in the browser (step-up, valid 120 s) before each privileged action. `ARBOR_ALLOW_AUTO_APPROVAL=1` must be set alongside this.
- `ARBOR_APPROVAL_MODE=cli`: the authenticated session needs root-shell confirmation via `arbor-approve` instead of the browser re-prompt.
- `ARBOR_APPROVAL_MODE=totp`: **no longer supported**. Refused at startup with a migration message; choose `none` or `cli`.

#### `none` (default)

The browser prompts for the password before each privileged action. On success the action starts immediately — no root shell required.

#### `cli`

This is the original shell-first model.

1. Start the action in the browser as usual.
2. Arbor creates a pending approval request and locks the UI.
3. On a root shell, run `arbor-approve approve <request_id>`.
4. The browser notices the approval and starts the action automatically.

```bash
arbor-approve list
arbor-approve approve <request_id>
```

If you reject the prompt in `arbor-approve`, the request is cancelled and the browser unlocks immediately.

## Local users and roles

Arbor local auth supports three roles: `owner`, `operator`, `viewer`.

Examples:

```bash
# create additional users
arbor-auth create-user --username alice --role operator --password 'change-me-now'
arbor-auth create-user --username bob --role viewer --password 'change-me-now'

# list users
arbor-auth list-users

# change role
arbor-auth set-role --username bob --role operator
```

## LAN access

LAN access exists, but it is still not the recommended deployment mode. Arbor binds to loopback by default and should not be treated as an internet-facing service. Even with `ARBOR_AUTH_MODE=totp`, the TOTP secret is shared across the whole instance — useful as a login-time second factor for a trusted operator, **not** a substitute for a hardened multi-user internet auth model.

There are two supported patterns. The reverse-proxy pattern is the recommended one and the only one that works once Arbor refuses a public bind without TLS.

### Pattern A — reverse proxy with TLS termination (recommended)

Arbor stays bound to `127.0.0.1` and a TLS-terminating front-end (Apache, Nginx, Caddy) faces the LAN. The front-end is responsible for the certificate, HSTS, and `X-Forwarded-Proto: https` so HSTS propagates through Arbor's response headers.

Apache example for `https://casa.lan/` proxying to `127.0.0.1:8444`:

```apache
<VirtualHost *:443>
    ServerName casa.lan

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/casa.lan-fullchain.pem
    SSLCertificateKeyFile /etc/apache2/ssl/casa.lan-privkey.pem

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPass /ws/ ws://127.0.0.1:8444/ws/
    ProxyPassReverse /ws/ ws://127.0.0.1:8444/ws/

    ProxyPass / http://127.0.0.1:8444/
    ProxyPassReverse / http://127.0.0.1:8444/
</VirtualHost>
```

Required Apache modules: `mod_proxy`, `mod_proxy_http`, `mod_proxy_wstunnel`, `mod_headers`, `mod_ssl`. `ProxyPreserveHost On` is essential — without it the `Origin` the browser sends will not match `ARBOR_CORS_ORIGINS` and WebSocket handshakes will be refused with `4403 origin not allowed`.

In `/etc/arbor/arbor.env`:

```bash
ARBOR_HOST=127.0.0.1
ARBOR_PORT=8444
ARBOR_TLS=0
ARBOR_CORS_ORIGINS=https://casa.lan
```

### Pattern B — direct TLS on Arbor

Arbor terminates TLS itself. Required because a non-loopback bind without TLS is refused at startup.

```bash
ARBOR_HOST=0.0.0.0
ARBOR_TLS=1
ARBOR_CERT=/etc/arbor/cert.pem
ARBOR_KEY=/etc/arbor/key.pem
ARBOR_CORS_ORIGINS=https://arbor.lan:8443,https://192.168.1.10:8443
```

Then restart the services and open `https://<hostname>:8443`. You will need to accept the certificate warning unless you import the certificate into your browser trust store.

### After any LAN config change

- Sessions made before the change carry the old cookie attributes — log out + log in again to pick up `SameSite=Strict` and the CSRF cookie.
- Hard-refresh the browser to bypass cached `app.js`. Otherwise mutating requests will fail with `403 csrf token missing or invalid` until the new JS is loaded.
- Create and use a local owner account; do not share tokens or shells.

## Configuration

`/etc/arbor/arbor.env` is loaded by both the web service and the daemon:

| Variable | Default | Purpose |
|---|---|---|
| `ARBOR_HOST` | `127.0.0.1` | Bind address; change explicitly for LAN access |
| `ARBOR_PORT` | `8443` | Web server port |
| `ARBOR_TLS` | `0` in the bootstrap config | Set to `0` to disable TLS without checking cert files; set to `1` to require `ARBOR_CERT` and `ARBOR_KEY` |
| `ARBOR_CERT` | `/etc/arbor/cert.pem` | TLS certificate path when `ARBOR_TLS=1` |
| `ARBOR_KEY` | `/etc/arbor/key.pem` | TLS key path when `ARBOR_TLS=1` |
| `ARBOR_AUTH_MODE` | unset (password only) | Set to `totp` to require a TOTP code during login. Enable TOTP from the Security page first. |
| `ARBOR_APPROVAL_MODE` | `none` | Privileged operation approval mode: `none` for browser step-up re-auth (requires `ARBOR_ALLOW_AUTO_APPROVAL=1`), `cli` for root-shell `arbor-approve`. The legacy `totp` value is refused at startup. |
| `ARBOR_ALLOW_AUTO_APPROVAL` | unset | Required alongside `ARBOR_APPROVAL_MODE=none`. Set to `1` to acknowledge that any authenticated session can trigger privileged operations. |
| `ARBOR_TOTP_SECRET` | unset | **No longer accepted from the process environment** (it would leak via `/proc/<pid>/environ`). Use `ARBOR_TOTP_SECRET_FILE`. |
| `ARBOR_TOTP_SECRET_FILE` | `/etc/arbor/totp.secret` when configured | File containing the base32 TOTP secret for `totp` mode (mode `0600`). Managed by the Security page. |
| `ARBOR_TOTP_ISSUER` | `Arbor` | Issuer label embedded in the `otpauth://` TOTP URI |
| `ARBOR_TOTP_ACCOUNT_NAME` | host-derived | Account label embedded in the `otpauth://` TOTP URI |
| `ARBOR_ENABLE_OVERLAY_ADD` | `0` | Enable the dangerous overlay-add flow; overlays are disabled by default because new ebuilds run as root |
| `ARBOR_IPC_KEY` | unset | Optional env override for the shared HMAC key used to authenticate web-to-daemon IPC requests |
| `ARBOR_IPC_KEY_FILE` | `/etc/arbor/ipc.key` | Shared HMAC key file, generated by setup by default |
| `ARBOR_IPC_ALLOWED_UIDS` | uid of user `arbor` | Comma-separated peer uid allowlist for `/run/arbor/daemon.sock`. Anything outside this set is rejected via `SO_PEERCRED`. |
| `ARBOR_TRUSTED_PROXIES` | `127.0.0.1` | Comma-separated IPs passed to uvicorn's `forwarded_allow_ips`. Controls which proxy addresses are trusted to set `X-Forwarded-For` / `X-Forwarded-Proto`. |
| `ARBOR_ALLOW_PLAINTEXT` | unset | Allow plain HTTP on **loopback only** when `ARBOR_TLS` is unset and cert/key are missing. Refused on public binds. |
| `ARBOR_CORS_ORIGINS` | loopback `http(s)` on `localhost`, `127.0.0.1`, `[::1]` (port `8443`) | Comma-separated allowed origins |
| `ARBOR_STATIC_DIR` | auto-detected | Override the frontend static directory |

Overlay add is disabled by default. To enable it, set `ARBOR_ENABLE_OVERLAY_ADD=1` in `/etc/arbor/arbor.env`, restart the services, and use the two-step confirmation flow in the UI. Adding an overlay is equivalent to trusting that repository with root-level code execution during package builds.

## Features

- **Local auth with roles** — local users with `owner`, `operator`, and `viewer` roles
- **Optional TOTP at login** — require a 6-digit TOTP code during sign-in when `ARBOR_AUTH_MODE=totp`
- **Dashboard** — summary cards, recent job activity, compile time by category, source/binary mix, keyword posture, top enabled USE flags, and multi-slot package summaries
- **Installed packages** — filter installed packages, open package details, inspect metadata, USE state, and runtime dependencies
- **Search packages** — search the Portage tree and jump to the selected package
- **USE flags** — inspect global USE state, package-specific overrides, installed build state, and mismatch indicators
- **Install / Uninstall** — pretend first, stream live output, resume running jobs, and require approval before the real root action starts
- **Autounmask flow** — for masked install targets, Arbor can write accepted keywords to `/etc/portage/package.accept_keywords`
- **etc-update review** — after successful installs, pending `._cfg*` files can be reviewed and resolved in the UI
- **Maintenance** — sync, check `@world`, update `@world`, run preserved-rebuild, and depclean with approval on privileged steps
- **Overlays** — list configured overlays, sync them, remove them, and optionally add new ones with explicit danger acknowledgement plus approval
- **Jobs** — view active jobs, reopen live output, browse persisted history with log viewing, delete, and purge actions (stored in SQLite at `/var/lib/arbor/history.db`), and surface recovered orphaned/unknown jobs after daemon restart

## Screenshots

### Dashboard

<img src="https://i.imgur.com/n2h8c4B.png" alt="Arbor dashboard" width="900">

### Installed packages

<img src="https://i.imgur.com/67lOVIN.png" alt="Arbor installed packages list" width="900">

<img src="https://i.imgur.com/yS2qw6s.png" alt="Arbor package dependency view" width="900">

### USE flags

<img src="https://i.imgur.com/YbyPToC.png" alt="Arbor USE flags view" width="900">

### Install / Uninstall

<img src="https://i.imgur.com/H5ix75g.png" alt="Arbor install flow" width="900">

### Maintenance

<img src="https://i.imgur.com/De6G4ng.png" alt="Arbor maintenance view" width="900">

## Architecture

Two processes run with separate privileges:

- **`arbor-daemon`** (root) — performs Portage operations, tracks long-running jobs, and listens on `/run/arbor/daemon.sock`
- **`arbor`** (unprivileged `arbor` user) — FastAPI/uvicorn web server, serves the frontend, and proxies requests to the daemon

The frontend is a no-build Alpine.js app in `frontend/alpine/`.
That directory is the canonical UI source and the one served in development and install-script deployments; there is no separate frontend build step to run for normal development.

## Security hardening

Arbor is still an early-release, local-first admin tool. The default install binds the web UI to `127.0.0.1` over plain HTTP on port `8443`, and it is **not intended for direct internet exposure**. The recommended remote-access pattern is reverse-proxy with TLS termination (see [LAN access](#lan-access)) on a private network or VPN.

### Trust model

- Treat an authenticated Arbor session as **root-equivalent intent**: once logged in, the UI can request root-backed package actions (subject to approval mode and role checks).
- In `cli` mode, root-backed actions are intentionally split into **request in browser / approve in root shell**. The browser cannot complete these actions on its own; approval must go through `arbor-approve`.
- `none` mode requires a password re-prompt in the browser before each privileged action. It is refused at startup unless `ARBOR_ALLOW_AUTO_APPROVAL=1` is set, so the trade-off is always explicit.
- TOTP at login is a convenience tradeoff for trusted local/LAN use. It adds a second factor in the browser, but it does **not** make Arbor safe to expose on the open internet — a valid session plus the shared TOTP secret is not the same as a per-user, phishing-resistant auth design.

### Web edge

- **CSRF**: every state-changing request (`POST`, `PUT`, `DELETE`, `PATCH`) requires a matching `X-CSRF-Token` header that echoes the `arbor_csrf` cookie. The cookie is set at login, rotated on logout/TOTP changes, and verified by middleware before the handler runs. The first WebSocket auth frame must include the same token. The login endpoint itself is the only exemption.
- **Cookies**: both `arbor_session` (HttpOnly) and `arbor_csrf` are `Secure` and `SameSite=Strict`. Cross-site navigations no longer carry the session, which closes most CSRF vectors at the browser level.
- **HSTS**: emitted as `Strict-Transport-Security: max-age=63072000; includeSubDomains` when the request is served over HTTPS (including via a reverse proxy that sets `X-Forwarded-Proto: https`).
- **TLS bind enforcement**: a non-loopback bind (`ARBOR_HOST` other than `127.0.0.1`/`::1`/`localhost`) requires TLS to be active. Arbor refuses to start in plain HTTP on a public interface.
- **WebSocket origin**: a missing `Origin` header is accepted only when bound to loopback. On any public bind, the connecting `Origin` must be in `ARBOR_CORS_ORIGINS`.
- **Security response headers**: a strict CSP (`script-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. `/docs`, `/redoc`, and `/openapi.json` are disabled.

### IPC and daemon

- **Authenticated channel**: web → daemon over `/run/arbor/daemon.sock`, signed with an HMAC-SHA256 key in `/etc/arbor/ipc.key`.
- **Protocol v2**: every signed payload includes a 16-byte nonce and a unix timestamp. The daemon enforces freshness (`|now − ts| ≤ 30s`) and rejects replays via a bounded LRU nonce cache (4096 entries, 5-minute TTL). Captured frames cannot be re-injected.
- **Peer credential check** (`SO_PEERCRED`): the daemon refuses any connection whose peer uid is not in the allowlist. Default: `uid("arbor")`. Override with `ARBOR_IPC_ALLOWED_UIDS`.
- **Boot guards**: the daemon (and web) refuse to start with `ARBOR_APPROVAL_MODE=totp` (legacy, removed) and with `ARBOR_APPROVAL_MODE=none` unless `ARBOR_ALLOW_AUTO_APPROVAL=1` is set. `ARBOR_TOTP_SECRET` in the process environment is refused; use `ARBOR_TOTP_SECRET_FILE`.

### Step-up re-auth

Every state-changing REST endpoint (`POST`, `PUT`, `DELETE`, `PATCH`) and every mutating WebSocket command requires a fresh password confirmation within the last 120 seconds when `ARBOR_APPROVAL_MODE` is not `cli`. A stolen session cookie alone is not enough to launch privileged actions. The frontend handles the re-prompt transparently via a modal; on success the original request is retried automatically.

### Process sandboxing

Both services apply privilege reduction at exec time. The mechanism depends on what is available:

- **`arbor-daemon`** keeps only the capabilities Portage genuinely needs (`CHOWN`, `DAC_OVERRIDE`, `DAC_READ_SEARCH`, `FOWNER`, `FSETID`, `SETGID`, `SETUID`, `SYS_CHROOT`, `MKNOD`, `KILL`, `SYS_ADMIN` for sandbox mount namespaces, `SYS_PTRACE`, `SETPCAP`, `SYS_RESOURCE`) and drops everything else from the bounding set. A RCE in the daemon cannot load kernel modules, open raw sockets to scan the LAN, mess with the clock, reconfigure audit, or exec a setuid helper to climb back to full root.
- **`arbor`** (web) always runs as `uid:gid arbor:arbor`. If `setpriv` is present, `no_new_privs` is also applied.

On **systemd** the hardening is unconditional (`NoNewPrivileges=` and `CapabilityBoundingSet=` in the unit files). On **OpenRC** the init scripts use `setpriv` from `sys-apps/util-linux` when available. If `setpriv` is not installed (it requires `USE=setpriv` on Gentoo — the flag is not always set by default), the services start without the capability bounding set and log a warning. To enable full hardening:

```bash
USE=setpriv emerge sys-apps/util-linux
```

#### Optional AppArmor profile (untested)

Two draft profiles are shipped in `apparmor/usr.bin.arbor-daemon` and `apparmor/usr.bin.arbor`. They restrict the filesystem and capabilities reachable from each process — `arbor-daemon` to Portage paths only, `arbor` to `/var/lib/arbor` and `/var/log/arbor` plus the IPC socket. They are **not enabled by default** and have **not been tested end-to-end against a full emerge workflow**. Treat them as a starting draft for hardening, not as a guarantee.

To try them on a test box (Gentoo with the `apparmor` USE flag and kernel support for `CONFIG_SECURITY_APPARMOR`):

```bash
sudo cp apparmor/usr.bin.arbor-daemon /etc/apparmor.d/
sudo cp apparmor/usr.bin.arbor        /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.arbor-daemon
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.arbor

# Iterate in complain-mode first so failures land in dmesg / journalctl
# without breaking real installs:
sudo aa-complain /etc/apparmor.d/usr.bin.arbor-daemon
sudo aa-complain /etc/apparmor.d/usr.bin.arbor

# When happy:
sudo aa-enforce /etc/apparmor.d/usr.bin.arbor-daemon
sudo aa-enforce /etc/apparmor.d/usr.bin.arbor

sudo rc-service arbor-daemon restart   # or: systemctl restart arbor-daemon
sudo rc-service arbor       restart    # or: systemctl restart arbor
```

If you confirm the profiles work on your setup, please share back the corrections so the "untested" disclaimer can be removed.

### Log rotation

`config/logrotate.d/arbor` is installed into `/etc/logrotate.d/arbor` by `config/setup.sh`. Daily rotation, 10 MB threshold, 14 rotations kept, gzip with `delaycompress`, recreated as `0640 arbor:arbor`. Post-rotate triggers a soft restart on whichever supervisor is active (systemd or OpenRC).

### Other defaults

- Local auth uses scrypt with strong parameters; password comparison and TOTP code comparison are timing-safe (`hmac.compare_digest`).
- Login throttle works on three scopes (IP, username, pair) with exponential backoff; failures are persisted in `auth.db` so a restart does not reset the counter.
- Overlay add remains opt-in behind `ARBOR_ENABLE_OVERLAY_ADD=1`. Even when enabled, adding an untrusted overlay still means trusting it with root-level code execution during package builds.
- The etc-update resolve path refuses unsafe symlinked overwrite targets, and job handling is more honest after restarts: active jobs are snapshotted to disk and may come back as `orphaned` or `unknown` rather than being treated as live.
- Live job buffers and stored history logs are intentionally bounded. Very large jobs may show truncated live output or truncated saved logs.

### Supply chain

CI runs `pip-audit` against the committed `requirements.lock` on every push, every PR, and weekly via cron. Bandit and Semgrep run on the same triggers (`p/python`, `p/security-audit`, `p/owasp-top-ten` rule packs). Dependabot opens PRs for dependency bumps on Mondays. A new CVE in a pinned transitive dep shows up as a red build within seven days even with zero code change.

## Development

Backend setup:

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

Run the web server in local-first HTTP mode:

```bash
ARBOR_TLS=0 .venv/bin/arbor
```

The frontend does not need a build step; it is served directly from `frontend/alpine/`, which is the canonical frontend source tree for this repository.

The daemon still requires root privileges and a working Portage environment.

Local-auth setup should create the owner account via `arbor-auth`. If no local users exist, login is intentionally unavailable until bootstrap is completed.

## Logs

```
/var/log/arbor/daemon.log   # arbor-daemon output
/var/log/arbor/web.log      # arbor web server output
```
