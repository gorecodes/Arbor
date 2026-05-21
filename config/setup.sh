#!/bin/bash
# Arbor first-time setup: creates user, dirs, self-signed cert, local-auth bootstrap
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

# --- /var/lib/arbor ---
echo "==> Creating /var/lib/arbor"
install -d -m 750 -o arbor -g arbor /var/lib/arbor

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
ARBOR_AUTH_BACKEND=local
# ARBOR_AUTH_MODE=cli
# ARBOR_TOTP_SECRET_FILE=/etc/arbor/totp.secret
# ARBOR_TOTP_ISSUER=Arbor
# ARBOR_TOTP_ACCOUNT_NAME=arbor@my-host
EOF
  fi
  echo "==> Created /etc/arbor/arbor.env"
fi

chmod 640 /etc/arbor/arbor.env
chown root:arbor /etc/arbor/arbor.env

# Enforce local-only auth backend in every setup run.
if grep -q '^ARBOR_AUTH_BACKEND=' /etc/arbor/arbor.env; then
  sed -i 's/^ARBOR_AUTH_BACKEND=.*/ARBOR_AUTH_BACKEND=local/' /etc/arbor/arbor.env
else
  printf '\nARBOR_AUTH_BACKEND=local\n' >> /etc/arbor/arbor.env
fi

# --- local auth bootstrap (mandatory mode) ---
echo "==> Local auth backend enforced"
if command -v arbor-auth >/dev/null 2>&1; then
  auth_status=$(arbor-auth status 2>/dev/null || true)
  if [[ "$auth_status" == "empty" ]]; then
    owner_username="${ARBOR_BOOTSTRAP_OWNER_USERNAME:-}"
    owner_password="${ARBOR_BOOTSTRAP_OWNER_PASSWORD:-}"

    if [[ -z "$owner_username" && -t 0 ]]; then
      read -rp "Owner username [owner]: " owner_username
      owner_username="${owner_username:-owner}"
    fi
    if [[ -z "$owner_password" && -t 0 ]]; then
      read -rsp "Owner password: " owner_password
      echo ""
      read -rsp "Repeat owner password: " owner_password_confirm
      echo ""
      if [[ "$owner_password" != "$owner_password_confirm" ]]; then
        echo "ERROR: owner password mismatch" >&2
        exit 1
      fi
    fi

    if [[ -z "$owner_username" || -z "$owner_password" ]]; then
      echo "==> Skipping owner bootstrap (set ARBOR_BOOTSTRAP_OWNER_USERNAME and ARBOR_BOOTSTRAP_OWNER_PASSWORD or run arbor-auth create-owner manually)"
    else
      echo "==> Creating initial local owner user"
      arbor-auth create-owner --username "$owner_username" --password "$owner_password"
    fi
  else
    echo "==> Local auth already initialized"
  fi
else
  echo "==> arbor-auth not found; skip local owner bootstrap"
fi

# Ensure auth DB ownership is service-safe even if bootstrap ran as root.
if [[ -f /var/lib/arbor/auth.db ]]; then
  chmod 640 /var/lib/arbor/auth.db
  chown arbor:arbor /var/lib/arbor/auth.db
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

chmod 600 /etc/arbor/ipc.key
chown arbor:arbor /etc/arbor/ipc.key
