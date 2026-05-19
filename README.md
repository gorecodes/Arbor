# Arbor

> Arbor is a hobby project built to scratch a very specific itch.
> The architecture and overall design are mine, while AI tools (Claude/Copilot) helped speed up boilerplate and implementation.
> The code has been reviewed and tested on my own machine, but this is still an early release — issues and PRs are very welcome.

Arbor is a local web UI for managing Portage on Gentoo.
It lets you browse packages, inspect dependency trees, review USE flags, install or remove packages, and follow running jobs from the browser.

The goal is **not** to hide Portage’s complexity.
The goal is to make it easier to visualize and manage that complexity without losing low-level control.

Arbor is designed for **local or LAN use only**.
It is **not intended to be exposed to the public internet**.

## Features

- Browse available packages from a web UI
- Inspect dependency trees more easily than in plain terminal output
- Review package details and USE flags
- Install and uninstall packages
- Track live `emerge` output from the browser
- Run maintenance tasks like world update, depclean, and sync
- Keep the privileged package-management path separate from the web server
- **Dashboard** — system gauges (CPU, RAM, disk) with live load average
- **Package browser** — search packages, view details, dependency tree, installed files
- **Install / Uninstall** — live emerge output streamed to the browser, with emerge option flags
- **Maintenance** — world update, depclean, preserved-rebuild, sync, all with pretend mode
- **Jobs** — active running jobs with live output; completed jobs are automatically archived to **History**
- **History** — searchable log of all past emerge operations, filterable by kind, with per-entry log viewer and purge (persisted in SQLite at `/var/lib/arbor/history.db`)
- **Overlays** — list all configured repositories, add new overlays via `eselect repository`, and sync individual overlays with live output

> **Known issues:**
> - Overlay removal is not yet working — under investigation.
> - History entries with very large logs return HTTP 500 when opened — under investigation.

## Screenshots

![Package browser and dependency tree](https://i.imgur.com/ww2S5zU.png)

![Install flow with live emerge output](https://i.imgur.com/aZqroc4.png)

![Maintenance — world update, depclean, sync](https://i.imgur.com/AllJcX6.png)

## Architecture

Arbor runs as two separate processes with different privilege levels:

- **`arbor-daemon`** runs as root and is responsible for spawning `emerge` and streaming output over a Unix socket
- **`arbor`** runs as the unprivileged `arbor` system user and serves the FastAPI/uvicorn HTTPS web app on port 8443, proxying allowed commands to the daemon

This separation is intentional: the web UI stays unprivileged, while only the package-management backend requires root access.

## Requirements
- Gentoo Linux with OpenRC or systemd
- Python 3.11+
- `openssl` (used for certificate generation)

## Install

### Portage overlay (recommended)

```bash
eselect repository add arbor-overlay git https://github.com/gorecodes/arbor-overlay.git
emaint sync -r arbor-overlay
# choose your init system via USE flag:
echo 'app-admin/arbor systemd' >> /etc/portage/package.use/arbor   # or: openrc
ACCEPT_KEYWORDS="**" emerge app-admin/arbor
bash /usr/share/arbor/setup.sh
```

### Install script

```bash
git clone https://github.com/gorecodes/Arbor
cd Arbor
sudo bash install.sh
```

The installer automatically detects your init system (OpenRC or systemd) and will:

1. Install the backend to `/usr/lib/arbor/` with a Python venv
2. Install the appropriate service files
3. Create the `arbor` system user
4. Generate a self-signed TLS certificate in `/etc/arbor/`
5. Generate a random access token, printed once and stored in `/etc/arbor/token`

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

Open `https://localhost:8443` in your browser. Accept the self-signed certificate warning, then enter the token shown during install (or read it with `sudo cat /etc/arbor/token`).

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

## Update

### Via Portage overlay

```bash
emaint sync -r arbor-overlay
emerge app-admin/arbor
```

Then restart the services (OpenRC: `rc-service arbor restart; rc-service arbor-daemon restart` / systemd: `systemctl restart arbor-daemon arbor`).

### Via install script

```bash
git pull
sudo bash install.sh
```

If `/etc/arbor/cert.pem` and `/etc/arbor/token` already exist, the installer will keep them and skip regeneration.

## Uninstall

### Via Portage overlay

```bash
emerge --unmerge app-admin/arbor
```

**OpenRC:** `rc-update del arbor; rc-update del arbor-daemon`  
**systemd:** `systemctl disable arbor-daemon arbor`

```bash
userdel arbor
```

### Via install script

**OpenRC:**
```bash
rc-service arbor stop
rc-service arbor-daemon stop
rc-update del arbor
rc-update del arbor-daemon
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

Configuration files and logs are **not** removed automatically:

```bash
rm -rf /etc/arbor /var/log/arbor /run/arbor
```

> **Note:** `/etc/arbor/` contains your TLS certificate and access token. Keep it if you plan to reinstall and want to preserve the current setup.

## Configuration

Web server settings live in:

```text
/etc/arbor/arbor.env
```

Example:

```env
ARBOR_HOST=0.0.0.0
ARBOR_PORT=8443
ARBOR_CERT=/etc/arbor/cert.pem
ARBOR_KEY=/etc/arbor/key.pem
```

## Logs

```text
/var/log/arbor/daemon.log   # arbor-daemon output
/var/log/arbor/web.log      # web server output
```

## LAN access

The self-signed certificate includes your hostname as a SAN.
To access Arbor from another machine on your LAN, open:

```text
https://<hostname>:8443
```

You will need to either accept the browser warning or import `cert.pem` into that browser’s trust store.

To read the access token remotely:

```bash
ssh yourbox sudo cat /etc/arbor/token
```

## Security notes

Arbor is meant for trusted local or LAN environments only.

- Do **not** expose it directly to the internet
- Anyone with a valid token can access the web UI
- The token is stored locally in `/etc/arbor/token`
- The HTTPS certificate is self-signed by default

If you are deploying Arbor on a shared or semi-trusted network, review permissions carefully and treat the token as a secret.

## Troubleshooting

A few things to check first if something does not work:

- Verify both services are running:
  ```bash
  rc-service arbor status
  rc-service arbor-daemon status
  ```
- Check logs:
  ```bash
  tail -f /var/log/arbor/web.log /var/log/arbor/daemon.log
  ```
- If the browser refuses the connection, confirm the certificate files exist in `/etc/arbor/`
- If LAN access fails, verify that your hostname resolves correctly from the client machine

## Contributing

Issues and PRs are welcome.

Useful areas for contribution include:

- bug fixes
- UI improvements
- Gentoo/OpenRC polish
- systemd support and testing
- documentation and install flow improvements
