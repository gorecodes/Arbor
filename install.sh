#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO="$(cd "$(dirname "$0")" && pwd)"

# --- prerequisite checks ---
need() {
  command -v "$1" &>/dev/null || { echo "ERROR: '$1' not found — install it first" >&2; exit 1; }
}
need python3
need openssl

python3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null || {
  echo "ERROR: Python 3.11+ required (found $(python3 --version 2>&1))" >&2; exit 1
}

# --- backend ---
echo "==> Installing backend to /usr/lib/arbor"
mkdir -p /usr/lib/arbor
cp -r "$REPO/backend/"* /usr/lib/arbor/

echo "==> Setting up Python venv (with system site-packages for portage access)"
python3 -m venv --system-site-packages /usr/lib/arbor/.venv
/usr/lib/arbor/.venv/bin/pip install --quiet /usr/lib/arbor/

echo "==> Creating entry point symlinks in /usr/local/bin"
ln -sf /usr/lib/arbor/.venv/bin/arbor        /usr/local/bin/arbor
ln -sf /usr/lib/arbor/.venv/bin/arbor-daemon /usr/local/bin/arbor-daemon

# --- frontend ---
echo "==> Installing frontend"
rm -rf /usr/lib/arbor/frontend
mkdir -p /usr/lib/arbor/frontend
cp -r "$REPO/frontend/alpine/." /usr/lib/arbor/frontend/
chown -R root:arbor /usr/lib/arbor/frontend 2>/dev/null || true

# --- OpenRC ---
echo "==> Installing OpenRC services"
cp "$REPO/openrc/arbor-daemon" /etc/init.d/arbor-daemon
cp "$REPO/openrc/arbor"        /etc/init.d/arbor
chmod 755 /etc/init.d/arbor-daemon /etc/init.d/arbor

# --- first-time setup ---
echo "==> First-time setup (user, cert, token)"
bash "$REPO/config/setup.sh" "$REPO"

echo ""
echo "==> Installation complete. Start with:"
echo "    rc-service arbor-daemon start"
echo "    rc-service arbor start"
echo ""
echo "==> To start at boot:"
echo "    rc-update add arbor-daemon default"
echo "    rc-update add arbor default"
