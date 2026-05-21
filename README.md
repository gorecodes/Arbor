# Arbor

> This is a hobby project built to scratch my own itch. While I designed the architecture and heavily used AI (Claude) to speed up the boilerplate and implementation, the code has been thoroughly reviewed and tested on my own machine. It works for my workflow, but it is still an early release.

A local-first web UI for managing Portage from a browser on the same machine.

Designed for Gentoo systems in a local environment. Not intended to be exposed to the internet.

## Approval modes

**Arbor supports three approval modes for privileged actions, selected with `ARBOR_AUTH_MODE`.**

The mode applies to install, uninstall, world update, sync, preserved-rebuild, depclean, overlay changes, and other root-backed admin operations.

Minimal `/etc/arbor/arbor.env` examples:

```bash
# cli (default)
ARBOR_AUTH_MODE=cli

# totp
ARBOR_AUTH_MODE=totp
ARBOR_TOTP_SECRET_FILE=/etc/arbor/totp.secret
# Optional
# ARBOR_TOTP_ISSUER=Arbor
# ARBOR_TOTP_ACCOUNT_NAME=arbor@my-host

#none
ARBOR_AUTH_MODE=none
```

### `cli` (default)

This is the original shell-first model and remains the safest mode for Arbor's intended local-first deployment.

1. Start the action in the browser as usual.
2. Arbor creates a pending approval request and locks the UI.
3. On a root shell, run `arbor-approve approve <request_id>`.
4. The browser notices the approval and starts the action automatically.

If you answer **No** in `arbor-approve`, the request is cancelled, the frontend unlocks, and you can retry without reloading the page.

This means:

- the browser can **request** dangerous actions, but it does not directly self-authorize them
- the approval decision happens in a **root shell**
- refreshing the UI does **not** lose a pending approval request; Arbor restores it and reopens the relevant page

### `totp`

In TOTP mode, Arbor still creates a pending approval request, but approval happens in the Web UI by entering a code from a standard TOTP app such as Google Authenticator or Aegis.

To configure it manually in `/etc/arbor/arbor.env`, set:

Provisioning can be done from a root shell with:

```bash
arbor-approve totp-setup
```

That command can:

- create or reuse the TOTP secret
- print the `otpauth://...` URI
- render an ASCII QR code when the optional `qrcode` dependency is available
- update `/etc/arbor/arbor.env` automatically so `ARBOR_AUTH_MODE=totp` and the secret file path are configured

**Important:** TOTP improves convenience for trusted local/LAN use, but it does **not** make Arbor suitable for internet exposure. The TOTP code is still a shared second factor for the whole instance, not a per-request cryptographic proof bound to a single browser action.

### `none`

In `none` mode, Arbor skips the extra approval step entirely and starts privileged actions immediately after the authenticated browser request.

This exists for fully trusted environments only. Arbor logs a startup warning when `ARBOR_AUTH_MODE=none` is enabled.

## Features

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

## Dashboard

The current dashboard is centered on two main areas plus a top summary strip:

### Recent activity

- Recent job list
- Activity snapshot
- Longest completed builds

### Gentoo composition

- Compile time by category from `/var/log/emerge.log`
- Source / binary mix
- Keyword posture
- Top enabled USE flags
- Multi-slot packages

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

- Arbor is still an early-release, local-first admin tool. The default install binds the web UI to `127.0.0.1` over HTTPS on port `8443`, and it is **not intended for internet exposure**.
- Treat the Arbor token as **root-equivalent**. Arbor now authenticates web-to-daemon IPC requests and avoids putting WebSocket tokens in URLs, but an authenticated session can still trigger root-backed Portage actions.
- In `cli` mode, root-backed actions are intentionally split into **request in browser / approve in root shell**. The browser cannot complete these actions on its own; approval must go through `arbor-approve`.
- `totp` mode is a convenience tradeoff for trusted local/LAN use. It adds a second factor in the browser, but it does **not** make Arbor safe to expose on the internet; a valid session plus the shared TOTP secret is still not the same as a hardened internet-facing auth design.
- `none` mode removes the secondary approval gate entirely and should be treated as equivalent to trusting any authenticated session with direct root-backed action approval.
- Safer defaults are enabled out of the box: localhost bind, tighter token/key handling, response security headers, and overlay add disabled by default.
- Overlay add remains a dangerous admin action. If you enable `ARBOR_ENABLE_OVERLAY_ADD=1`, Arbor requires an explicit approval flow, but adding an untrusted overlay still means trusting it with root-level package build execution.
- The etc-update resolve path now refuses unsafe symlinked overwrite targets, and job handling is more honest after restarts: active jobs are snapshotted to disk and may come back as `orphaned` or `unknown` rather than being treated as live.
- Live job buffers and stored history logs are intentionally bounded. Very large jobs may show truncated live output or truncated saved logs.

## Recent fixes

- Install and uninstall runs now keep the browser-boundary checks aligned with the actual default loopback deployment: WebSocket/CORS allow `localhost`, `127.0.0.1`, and `[::1]` on port `8443` by default.
- The Alpine frontend was migrated to the CSP-safe build and the template surface was refactored away from unsupported inline syntax such as template literals, optional chaining, and nullish coalescing in `x-*` expressions.
- Overlay removal now requires an explicit dangerous-action acknowledgement, and overlay add remains opt-in behind `ARBOR_ENABLE_OVERLAY_ADD=1`.
- Background job recovery now records checkpoints and PID identity metadata so daemon restarts report `orphaned` / `unknown` states honestly instead of pretending a lost job is still fully attached.
- OpenRC services now use respawn supervision by default; systemd already had restart-on-failure behavior.

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
echo 'app-admin/arbor systemd' >> /etc/portage/package.use/arbor   # or: openrc
emerge app-admin/arbor
bash /usr/share/arbor/setup.sh
```

By default this installs the stable overlay version. If you want the live ebuild that tracks `main`:

```bash
echo '=app-admin/arbor-9999 **' >> /etc/portage/package.accept_keywords/arbor
emerge =app-admin/arbor-9999
bash /usr/share/arbor/setup.sh
```

Choose your init system via USE flag before installing, then start the services as shown below.

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
7. Generate a self-signed TLS certificate in `/etc/arbor/` if one does not already exist
8. Generate an access token in `/etc/arbor/token` if one does not already exist
9. Create `/etc/arbor/arbor.env` if it does not already exist
10. Generate an IPC key in `/etc/arbor/ipc.key` if one does not already exist

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

Open `https://localhost:8443` or `https://127.0.0.1:8443` in your browser, accept the self-signed certificate warning, and enter the token from `/etc/arbor/token`.

For a first install, keep Arbor on localhost until you are comfortable with the model: the bearer token unlocks root-backed package actions, and LAN exposure is still a deliberate tradeoff rather than the default.

When you start a privileged action from the UI, Arbor's behavior depends on `ARBOR_AUTH_MODE`:

- `cli`: Arbor pauses and waits for `arbor-approve approve <request_id>` from a root shell.
- `totp`: Arbor pauses and shows a TOTP prompt in the Web UI.
- `none`: Arbor starts the privileged action immediately with no second prompt.

For `cli`, use:

```bash
arbor-approve list
arbor-approve approve <request_id>
```

For `totp`, provision the instance first:

```bash
arbor-approve totp-setup
```

If you reject the prompt in `arbor-approve`, the request is cancelled and the browser unlocks immediately.

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

## Development

Backend setup:

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

Run the web server without TLS for local development:

```bash
ARBOR_ALLOW_PLAINTEXT=1 .venv/bin/arbor
```

The frontend does not need a build step; it is served directly from `frontend/alpine/`, which is the canonical frontend source tree for this repository.

The daemon still requires root privileges and a working Portage environment.

If `/etc/arbor/token` is missing, the web service generates an ephemeral token and prints it on startup.

## Update

### Via Portage overlay

```bash
emaint sync -r arbor-overlay
emerge app-admin/arbor
```

For the live ebuild instead:

```bash
emaint sync -r arbor-overlay
emerge =app-admin/arbor-9999
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

## Logs

```
/var/log/arbor/daemon.log   # arbor-daemon output
/var/log/arbor/web.log      # arbor web server output
```

## Configuration

`/etc/arbor/arbor.env` is loaded by both the web service and the daemon:

| Variable | Default | Purpose |
|---|---|---|
| `ARBOR_HOST` | `127.0.0.1` | Bind address; change explicitly for LAN access |
| `ARBOR_PORT` | `8443` | Web server port |
| `ARBOR_CERT` | `/etc/arbor/cert.pem` | TLS certificate path |
| `ARBOR_KEY` | `/etc/arbor/key.pem` | TLS key path |
| `ARBOR_AUTH_MODE` | `cli` | Secondary approval mode: `cli`, `totp`, or `none` |
| `ARBOR_TOTP_SECRET` | unset | Inline base32 TOTP secret; supported, but prefer the file-based option below |
| `ARBOR_TOTP_SECRET_FILE` | `/etc/arbor/totp.secret` when configured | File containing the base32 TOTP secret for `totp` mode |
| `ARBOR_TOTP_ISSUER` | `Arbor` | Issuer label embedded in the `otpauth://` TOTP URI |
| `ARBOR_TOTP_ACCOUNT_NAME` | host-derived | Account label embedded in the `otpauth://` TOTP URI |
| `ARBOR_ENABLE_OVERLAY_ADD` | `0` | Enable the dangerous overlay-add flow; overlays are disabled by default because new ebuilds run as root |
| `ARBOR_IPC_KEY` | unset | Optional env override for the shared HMAC key used to authenticate web-to-daemon IPC requests |
| `ARBOR_IPC_KEY_FILE` | `/etc/arbor/ipc.key` | Shared HMAC key file, generated by setup by default |
| `ARBOR_ALLOW_PLAINTEXT` | unset | Set to `1` to allow plain HTTP when cert/key are missing |
| `ARBOR_CORS_ORIGINS` | loopback `http(s)` on `localhost`, `127.0.0.1`, `[::1]` (port `8443`) | Comma-separated allowed origins |
| `ARBOR_STATIC_DIR` | auto-detected | Override the frontend static directory |

Overlay add is disabled by default. To enable it, set `ARBOR_ENABLE_OVERLAY_ADD=1` in `/etc/arbor/arbor.env`, restart the services, and use the two-step confirmation flow in the UI. Adding an overlay is equivalent to trusting that repository with root-level code execution during package builds.

For TOTP mode, prefer storing the secret in `ARBOR_TOTP_SECRET_FILE` instead of `ARBOR_TOTP_SECRET` so it stays out of process listings and service unit overrides. `arbor-approve totp-setup` will create and wire this for you by default.

`ARBOR_AUTH_MODE=none` is intentionally noisy: Arbor prints a startup warning because authenticated browser access can immediately trigger privileged actions in that mode.

## LAN access

LAN access exists, but it is still not the recommended deployment mode. Arbor now ships with several hardening changes for safer local use, but it still binds only to loopback by default and should not be treated as an internet-facing service.

Even with `ARBOR_AUTH_MODE=totp`, Arbor is **not** designed to become safe for public internet exposure. TOTP here is a usability-oriented second approval factor for a trusted operator, not a substitute for a hardened multi-user internet auth model.

For LAN access you must configure both:

1. `ARBOR_HOST` so the web server listens on a LAN-reachable address.
2. `ARBOR_CORS_ORIGINS` so browser requests and WebSocket origins from that LAN address are accepted.

Example `/etc/arbor/arbor.env`:

```bash
ARBOR_HOST=0.0.0.0
ARBOR_CORS_ORIGINS=https://arbor.lan:8443,https://192.168.1.10:8443
```

Then restart the services and open:

```bash
https://<hostname>:8443
```

You will need to accept the certificate warning unless you import the certificate into your browser trust store.

To read the token remotely:

```bash
ssh yourbox sudo cat /etc/arbor/token
```
