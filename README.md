# Arbor

> This is a hobby project built to scratch my own itch. While I designed the architecture and heavily used AI (Claude) to speed up the boilerplate and implementation, the code has been thoroughly reviewed and tested on my own machine. It works for my workflow, but it is still an early release.

A local web UI for managing Portage from a browser on the same machine.

Designed for Gentoo systems in a local environment. Not intended to be exposed to the internet.

## Features

- **Dashboard** — summary cards, recent job activity, compile time by category, source/binary mix, keyword posture, top enabled USE flags, and multi-slot package summaries
- **Installed packages** — filter installed packages, open package details, inspect metadata, USE state, and runtime dependencies
- **Search packages** — search the Portage tree and jump to the selected package
- **USE flags** — inspect global USE state, package-specific overrides, installed build state, and mismatch indicators
- **Install / Uninstall** — pretend first, stream live output, resume running jobs, and launch install or uninstall from package details
- **Autounmask flow** — for masked install targets, Arbor can write accepted keywords to `/etc/portage/package.accept_keywords`
- **etc-update review** — after successful installs, pending `._cfg*` files can be reviewed and resolved in the UI
- **Maintenance** — sync, check `@world`, update `@world`, run preserved-rebuild, and depclean with a separate pretend/confirm flow
- **Overlays** — list configured overlays, add new ones, sync them, and remove them
- **Jobs** — view active jobs, reopen live output, and browse persisted history with log viewing, delete, and purge actions (stored in SQLite at `/var/lib/arbor/history.db`)

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

This separation is intentional: the web UI stays unprivileged, while only the package-management backend requires root access.

## Requirements

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
4. Create `/usr/local/bin/arbor` and `/usr/local/bin/arbor-daemon`
5. Install OpenRC or systemd service files, depending on the detected init system
6. Create the `arbor` system user
7. Generate a self-signed TLS certificate in `/etc/arbor/` if one does not already exist
8. Generate an access token in `/etc/arbor/token` if one does not already exist
9. Create `/etc/arbor/arbor.env` if it does not already exist

## First start

**OpenRC:**
```bash
rc-service arbor-daemon start
rc-service arbor start
```

**systemd:**
```bash
systemctl start arbor-daemon arbor
```

Open `https://localhost:8443` in your browser, accept the self-signed certificate warning, and enter the token from `/etc/arbor/token`.

## Enable at boot

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

The frontend does not need a build step; it is served directly from `frontend/alpine/`.

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
rm -f /usr/local/bin/arbor /usr/local/bin/arbor-daemon
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

`/etc/arbor/arbor.env` controls the web server:

| Variable | Default | Purpose |
|---|---|---|
| `ARBOR_HOST` | `0.0.0.0` | Bind address |
| `ARBOR_PORT` | `8443` | Web server port |
| `ARBOR_CERT` | `/etc/arbor/cert.pem` | TLS certificate path |
| `ARBOR_KEY` | `/etc/arbor/key.pem` | TLS key path |
| `ARBOR_ALLOW_PLAINTEXT` | unset | Set to `1` to allow plain HTTP when cert/key are missing |
| `ARBOR_CORS_ORIGINS` | `https://localhost:8443,http://localhost:5173` | Comma-separated allowed origins |
| `ARBOR_STATIC_DIR` | auto-detected | Override the frontend static directory |

## Logs

```text
/var/log/arbor/daemon.log   # arbor-daemon output
/var/log/arbor/web.log      # web server output
```

## LAN access

LAN access exists, but for now it is not the recommended deployment mode. Until the planned security-hardening work lands in upcoming releases, prefer using Arbor only from the same machine. If you still need to access it from another machine on the LAN, the generated self-signed certificate includes `localhost` and the system hostname, so you can use:

```bash
https://<hostname>:8443
```

You will need to accept the certificate warning unless you import the certificate into your browser trust store.

To read the token remotely:

```bash
ssh yourbox sudo cat /etc/arbor/token
```
