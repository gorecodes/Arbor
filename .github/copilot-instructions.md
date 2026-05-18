# Arbor — Copilot Instructions

## Architecture

Two processes with separate privileges communicate over a Unix socket at `/run/arbor/daemon.sock`:

- **`arbor-daemon`** (`backend/daemon/main.py`) — runs as **root**, performs all Portage operations. Listens on the Unix socket and responds to commands.
- **`arbor`** (`backend/arbor/`) — runs as unprivileged `arbor` user. FastAPI/uvicorn HTTPS server on port 8443. Serves the frontend and proxies all Portage commands to the daemon via the socket client in `backend/arbor/daemon_client.py`.

### Daemon protocol

The socket speaks **newline-delimited JSON**. Each request is one JSON line `{"cmd": "...", "args": {...}}`. The daemon responds with a stream of JSON lines, terminated by a line containing `{"done": true}` or `{"error": "..."}`. Long-running jobs (emerge install/uninstall/etc.) are tracked in an in-memory `_Job` registry with a pub/sub queue pattern — clients can reconnect and replay logs.

### Frontend

The frontend is **Alpine.js, no-build** (`frontend/alpine/`). It is a single IIFE in `app.js` that exposes component factories on `window` for Alpine's `x-data`. Routing is hash-based (`#/dashboard`, `#/packages/:cpv`, etc.) via `navigate()` / `_applyRoute()`. There is no npm build step for the frontend. The `frontend/index.html` at the repo root is a leftover Vite stub — ignore it.

### Authentication

- REST endpoints: Bearer token in `Authorization` header, validated via `backend/arbor/auth.py`.
- WebSocket endpoints: token passed as a `?token=` query parameter (headers aren't accessible in browser WS APIs).
- Token source: `/etc/arbor/token` file; falls back to an ephemeral in-memory token if the file is absent (printed to stdout on startup).

## Build & run

### Backend (development)

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e .
```

Run without TLS (dev only):
```bash
ARBOR_ALLOW_PLAINTEXT=1 .venv/bin/arbor
```

The daemon requires root and a running Portage tree — it can't be usefully run in a standard dev environment without Gentoo. Use `python3 -c "import ast; ast.parse(open('backend/daemon/main.py').read())"` as a syntax check.

### Frontend (no build needed)

The Alpine frontend is plain files — open `frontend/alpine/index.html` directly or let the FastAPI server serve it from `frontend/alpine/`.

### Install to system

```bash
sudo bash install.sh
```

## Key conventions

### Daemon handlers

All handlers in `daemon/main.py` are **async generators** registered in `HANDLERS`. They yield dicts and must always end with a `{"done": true}` chunk or raise (the dispatch loop in `handle_client` handles the error case).

All Portage API calls are **synchronous** (portage is not async-safe) and must run inside `await in_thread(fn, *args)` using the module-level `ThreadPoolExecutor`. Never call `import portage` at module level — import it inside the sync helper function.

### Atom handling

All atoms from clients must be passed through `_checked_atom()` (normalizes bare CPVs with `=` prefix, then validates via regex + portage's own `Atom` parser). Never pass raw user input to subprocess or file writes. Emerge flags are whitelisted in `_INSTALL_OPTS` / `_UPDATE_OPTS` and parsed through `_parse_opts()` — unknown tokens are silently dropped.

### WebSocket flow

Two patterns in `backend/arbor/main.py`:
1. **`_ws_emerge`** — fire-and-forget streaming (pretend, autounmask): open socket → stream chunks → close.
2. **`_ws_job_cmd`** — for stateful jobs (install, uninstall, world-update, etc.): start job → get `job_id` → attach via `job_attach` command to stream logs. This allows reconnection.

### Frontend components

Each UI section is a factory function (`dashboardComponent`, `packageListComponent`, etc.) that returns a plain object for Alpine's `x-data`. Global state lives in `Alpine.store('router')` and `Alpine.store('auth')`. The `makeEmergeOptions()` mixin provides emerge flag UI state, persisted in `localStorage`.

### Security notes

- The web server refuses to start without TLS unless `ARBOR_ALLOW_PLAINTEXT=1` is explicitly set.
- Only `package.accept_keywords` is ever written by the daemon on the user's behalf (via `_write_keywords`). All other portage config changes go through the etc-update flow.
- CORS is restricted to loopback by default; override with `ARBOR_CORS_ORIGINS`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ARBOR_HOST` | `0.0.0.0` | Bind address |
| `ARBOR_PORT` | `8443` | HTTPS port |
| `ARBOR_CERT` | `/etc/arbor/cert.pem` | TLS certificate |
| `ARBOR_KEY` | `/etc/arbor/key.pem` | TLS key |
| `ARBOR_ALLOW_PLAINTEXT` | unset | Set to `1` to allow plain HTTP in dev |
| `ARBOR_CORS_ORIGINS` | loopback only | Comma-separated allowed origins |
| `ARBOR_STATIC_DIR` | auto-detected | Override frontend static directory |

## Logs (installed)

```
/var/log/arbor/daemon.log   # arbor-daemon
/var/log/arbor/web.log      # arbor web server
```
