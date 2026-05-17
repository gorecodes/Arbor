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
  chmod 640 /etc/arbor/key.pem /etc/arbor/cert.pem
  chown root:arbor /etc/arbor/key.pem /etc/arbor/cert.pem
fi

# --- access token ---
if [[ -f /etc/arbor/token ]]; then
  echo "==> Token already exists — skipping"
else
  echo "==> Generating access token"
  token=$(openssl rand -base64 32)
  printf '%s\n' "$token" > /etc/arbor/token
  chmod 640 /etc/arbor/token
  chown root:arbor /etc/arbor/token
  echo ""
  echo "    Access token: $token"
  echo "    (saved to /etc/arbor/token)"
  echo ""
fi

# --- env config ---
if [[ -f /etc/arbor/arbor.env ]]; then
  echo "==> /etc/arbor/arbor.env already exists — skipping"
else
  if [[ -n "$REPO" && -f "$REPO/config/arbor.env.example" ]]; then
    cp "$REPO/config/arbor.env.example" /etc/arbor/arbor.env
  else
    cat > /etc/arbor/arbor.env <<'EOF'
ARBOR_HOST=0.0.0.0
ARBOR_PORT=8443
ARBOR_CERT=/etc/arbor/cert.pem
ARBOR_KEY=/etc/arbor/key.pem
EOF
  fi
  chmod 640 /etc/arbor/arbor.env
  chown root:arbor /etc/arbor/arbor.env
  echo "==> Created /etc/arbor/arbor.env"
fi
