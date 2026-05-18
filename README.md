# Arbor

> This is a hobby project built to scratch my own itch. While I designed the architecture and heavily used AI (Claude) to speed up the boilerplate and implementation, the code has been thoroughly reviewed and tested on my own machine. It works perfectly for my workflow, but it's an early release — issues and PRs are highly welcome.

A local web UI for managing Portage — browse packages, install, uninstall, and track running jobs from your browser.

Designed for Gentoo systems on a local/LAN network. Not intended to be exposed to the internet.

## Screenshots

![Package browser and dependency tree](https://i.imgur.com/ww2S5zU.png)

![Install flow with live emerge output](https://i.imgur.com/aZqroc4.png)

![Maintenance — world update, depclean, sync](https://i.imgur.com/AllJcX6.png)

## Architecture

Two processes run as separate privileges:

- **arbor-daemon** (root) — spawns emerge, streams output over a Unix socket
- **arbor** (unprivileged `arbor` user) — FastAPI/uvicorn HTTPS server on port 8443, serves the frontend and proxies daemon commands

## Prerequisites

- Gentoo Linux with OpenRC
- Python 3.11+
- `openssl` (for certificate generation)

## Install

### Via Portage overlay (recommended for Gentoo)

```bash
eselect repository add arbor-overlay git https://github.com/gorecodes/arbor-overlay.git
emaint sync -r arbor-overlay
ACCEPT_KEYWORDS="**" emerge 'app-admin/arbor'
bash /usr/share/arbor/setup.sh
```

### Via install script

```bash
git clone https://github.com/gorecodes/Arbor
cd Arbor
sudo bash install.sh
```

The installer will:

1. Install the backend to `/usr/lib/arbor/` with a Python venv
2. Install OpenRC service files
3. Create the `arbor` system user
4. Generate a self-signed TLS certificate in `/etc/arbor/`
5. Generate a random access token (printed once, also saved to `/etc/arbor/token`)

## First run

```bash
rc-service arbor-daemon start
rc-service arbor start
```

Open `https://localhost:8443` in your browser. Accept the self-signed certificate warning, then enter the token shown during install (or read it with `sudo cat /etc/arbor/token`).

## Start at boot

```bash
rc-update add arbor-daemon default
rc-update add arbor default
```

## Update

### Via Portage overlay

```bash
emaint sync -r arbor-overlay
emerge 'app-admin/arbor'
rc-service arbor restart; rc-service arbor-daemon restart
```

### Via install script

```bash
git pull
sudo bash install.sh
rc-service arbor stop; rc-service arbor-daemon stop
rc-service arbor-daemon start; rc-service arbor start
```

The installer skips certificate and token generation if `/etc/arbor/cert.pem` and `/etc/arbor/token` already exist.

## Logs

```
/var/log/arbor/daemon.log   # arbor-daemon output
/var/log/arbor/web.log      # arbor web server output
```

## Configuration

`/etc/arbor/arbor.env` — environment variables for the web server:

```
ARBOR_HOST=0.0.0.0
ARBOR_PORT=8443
ARBOR_CERT=/etc/arbor/cert.pem
ARBOR_KEY=/etc/arbor/key.pem
```

## LAN access

The self-signed certificate includes your hostname as a SAN. To access from another machine on your LAN, open `https://<hostname>:8443`. You will need to accept the certificate warning or import `cert.pem` into your browser's trust store.

To find the token from another machine: `ssh yourbox sudo cat /etc/arbor/token`.
