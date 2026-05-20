#!/bin/bash
# Arbor first-time setup: creates user, dirs, self-signed cert, token
# Usage: setup.sh [REPO_DIR]
#   REPO_DIR — optional path to the source repo (used to copy arbor.env template)

set -e

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO="${1:-}"

# --- system user ---
echo "==> Creating arbor system user"
useradd -r -s /sbin/nologin -G portage arbor 2>/dev/null || true

# --- /etc/arbor ---
echo "==> Creating /etc/arbor"
install -d -m 750 -o root -g arbor /etc/arbor

# --- /var/log/arbor ---
echo "==> Creating /var/log/arbor"
install -d -m 750 -o arbor -g arbor /var/log/arbor

# --- TLS certificate ---
if [[ -f /etc/arbor/cert.pem ]]; then
  echo "==> TLS certificate already exists — skipping"
else
  echo "==> Generating self-signed TLS certificate (valid 10 years)"
  HOSTNAME_SAN=$(hostname -f 2>/dev/null || hostname)
  openssl req -x509 -newkey rsa:4096 -keyout /etc/arbor/key.pem \
    -out /etc/arbor/cert.pem -sha256 -days 3650 -nodes \
    -subj "/CN=${HOSTNAME_SAN}" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:${HOSTNAME_SAN}" \
    2>/dev/null
  chmod 600 /etc/arbor/key.pem
  chown arbor:arbor /etc/arbor/key.pem
  chmod 644 /etc/arbor/cert.pem
  chown root:root /etc/arbor/cert.pem
fi
chmod 600 /etc/arbor/key.pem
chown arbor:arbor /etc/arbor/key.pem
chmod 644 /etc/arbor/cert.pem
chown root:root /etc/arbor/cert.pem

# --- access token ---
if [[ -f /etc/arbor/token ]]; then
  echo "==> Token already exists — skipping"
else
  echo "==> Generating access token"
  token=$(openssl rand -base64 32)
  printf '%s\n' "$token" > /etc/arbor/token
  chmod 600 /etc/arbor/token
  chown arbor:arbor /etc/arbor/token
  echo ""
  echo "    Access token: $token"
  echo "    (saved to /etc/arbor/token)"
  echo ""
fi
chmod 600 /etc/arbor/token
chown arbor:arbor /etc/arbor/token

# --- env config ---
if [[ -f /etc/arbor/arbor.env ]]; then
  echo "==> /etc/arbor/arbor.env already exists — skipping"
else
  if [[ -n "$REPO" && -f "$REPO/config/arbor.env.example" ]]; then
    cp "$REPO/config/arbor.env.example" /etc/arbor/arbor.env
  else
    cat > /etc/arbor/arbor.env <<'EOF'
ARBOR_HOST=127.0.0.1
ARBOR_PORT=8443
ARBOR_CERT=/etc/arbor/cert.pem
ARBOR_KEY=/etc/arbor/key.pem
ARBOR_ENABLE_OVERLAY_ADD=0
EOF
  fi
  echo "==> Created /etc/arbor/arbor.env"
fi

# --- IPC key ---
if [[ -f /etc/arbor/ipc.key ]]; then
  echo "==> IPC key file already exists — skipping"
else
  echo "==> Generating IPC key"
  ipc_key=$(openssl rand -hex 32)
  printf '%s\n' "$ipc_key" > /etc/arbor/ipc.key
  chmod 600 /etc/arbor/ipc.key
  chown arbor:arbor /etc/arbor/ipc.key
fi

chmod 640 /etc/arbor/arbor.env
chown root:arbor /etc/arbor/arbor.env
