#!/bin/bash
# Arbor first-time setup: creates user, dirs, local-auth bootstrap, and IPC key
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
ARBOR_TLS=0
ARBOR_ENABLE_OVERLAY_ADD=0
ARBOR_AUTH_BACKEND=local
# ARBOR_AUTH_MODE=cli
# ARBOR_APPROVAL_MODE=cli
# ARBOR_TOTP_SECRET_FILE=/etc/arbor/totp.secret
# ARBOR_TOTP_ISSUER=Arbor
# ARBOR_TOTP_ACCOUNT_NAME=arbor@my-host
# Direct TLS on Arbor itself (optional)
# ARBOR_TLS=1
# ARBOR_CERT=/etc/arbor/cert.pem
# ARBOR_KEY=/etc/arbor/key.pem
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

# --- logrotate ---
if [[ -d /etc/logrotate.d ]]; then
  if [[ -n "$REPO" && -f "$REPO/config/logrotate.d/arbor" ]]; then
    install -m 0644 -o root -g root \
      "$REPO/config/logrotate.d/arbor" /etc/logrotate.d/arbor
    echo "==> Installed /etc/logrotate.d/arbor"
  fi
fi
