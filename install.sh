#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO="$(cd "$(dirname "$0")" && pwd)"

_detect_init() {
  if [ -d /run/systemd/system ]; then
    echo systemd
  elif command -v openrc-run &>/dev/null || [ -f /sbin/openrc ]; then
    echo openrc
  else
    echo unknown
  fi
}
INIT_SYSTEM="$(_detect_init)"
echo "==> Detected init system: ${INIT_SYSTEM}"

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

echo "==> Creating entry point symlinks in /usr/bin"
ln -sf /usr/lib/arbor/.venv/bin/arbor        /usr/bin/arbor
ln -sf /usr/lib/arbor/.venv/bin/arbor-daemon /usr/bin/arbor-daemon
ln -sf /usr/lib/arbor/.venv/bin/arbor-approve /usr/bin/arbor-approve
ln -sf /usr/lib/arbor/.venv/bin/arbor-auth /usr/bin/arbor-auth

# --- frontend ---
echo "==> Installing frontend"
rm -rf /usr/lib/arbor/frontend
mkdir -p /usr/lib/arbor/frontend
cp -r "$REPO/frontend/alpine/." /usr/lib/arbor/frontend/
chown -R root:arbor /usr/lib/arbor/frontend 2>/dev/null || true

# --- OpenRC / systemd services ---
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
  echo "==> Installing systemd units"
  install -m 644 "$REPO/systemd/arbor-daemon.service" /usr/lib/systemd/system/arbor-daemon.service
  install -m 644 "$REPO/systemd/arbor.service"        /usr/lib/systemd/system/arbor.service
  systemctl daemon-reload
elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
  echo "==> Installing OpenRC services"
  cp "$REPO/openrc/arbor-daemon" /etc/init.d/arbor-daemon
  cp "$REPO/openrc/arbor"        /etc/init.d/arbor
  chmod 755 /etc/init.d/arbor-daemon /etc/init.d/arbor
else
  echo "WARNING: Unknown init system — skipping service installation" >&2
fi

# --- first-time setup ---
echo "==> First-time setup (user, local HTTP bootstrap, IPC key)"
bash "$REPO/config/setup.sh" "$REPO"

echo ""
echo "==> Installation complete. Start with:"
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
  echo "    systemctl start arbor-daemon arbor"
  echo ""
  echo "==> To start at boot:"
  echo "    systemctl enable arbor-daemon arbor"
else
  echo "    rc-service arbor-daemon start"
  echo "    rc-service arbor start"
  echo ""
  echo "==> To start at boot:"
  echo "    rc-update add arbor-daemon default"
  echo "    rc-update add arbor default"
fi
