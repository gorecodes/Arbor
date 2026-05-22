#!/bin/bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SITE_PACKAGES_DIR="${ARBOR_SITE_PACKAGES_DIR:-/usr/lib/python3.13/site-packages}"
FRONTEND_DIR="${ARBOR_FRONTEND_DIR:-/usr/share/arbor/frontend}"

install_arbor_approve_wrapper() {
  local arbor_link arbor_exec_target python_exec_dir arbor_script arbor_shebang

  arbor_link="$(readlink /usr/bin/arbor 2>/dev/null || true)"
  arbor_script="$(find /usr/lib/python-exec -maxdepth 2 -type f -name arbor 2>/dev/null | sort | head -n 1)"

  if [[ -n "$arbor_link" && -n "$arbor_script" ]]; then
    python_exec_dir="$(dirname "$arbor_script")"
    arbor_shebang="$(head -n 1 "$arbor_script")"
    if [[ "$arbor_shebang" != '#!'* ]]; then
      echo "Could not determine arbor interpreter from: $arbor_script" >&2
      exit 1
    fi
    install -d "$python_exec_dir"
    install -m 755 /dev/stdin "$python_exec_dir/arbor-approve" <<EOF
$arbor_shebang
# -*- coding: utf-8 -*-
import re
import sys
from arbor.approval_cli import main
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\\.pyw|\\.exe)?$", "", sys.argv[0])
    sys.exit(main())
EOF
    ln -sf "$arbor_link" /usr/bin/arbor-approve
    return
  fi

  arbor_exec_target="$(readlink -f /usr/bin/arbor 2>/dev/null || true)"
  if [[ -z "$arbor_exec_target" || ! -f "$arbor_exec_target" ]]; then
    arbor_exec_target="/usr/bin/arbor"
  fi
  if [[ ! -f "$arbor_exec_target" ]]; then
    echo "Missing installed arbor launcher: /usr/bin/arbor" >&2
    exit 1
  fi

  arbor_shebang="$(head -n 1 "$arbor_exec_target")"
  if [[ "$arbor_shebang" != '#!'* ]]; then
    echo "Could not determine arbor interpreter from: $arbor_exec_target" >&2
    exit 1
  fi

  install -m 755 /dev/stdin /usr/bin/arbor-approve <<EOF
$arbor_shebang
# -*- coding: utf-8 -*-
import re
import sys
from arbor.approval_cli import main
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\\.pyw|\\.exe)?$", "", sys.argv[0])
    sys.exit(main())
EOF
}

install_arbor_auth_wrapper() {
  local arbor_link arbor_exec_target python_exec_dir arbor_script arbor_shebang

  arbor_link="$(readlink /usr/bin/arbor 2>/dev/null || true)"
  arbor_script="$(find /usr/lib/python-exec -maxdepth 2 -type f -name arbor 2>/dev/null | sort | head -n 1)"

  if [[ -n "$arbor_link" && -n "$arbor_script" ]]; then
    python_exec_dir="$(dirname "$arbor_script")"
    arbor_shebang="$(head -n 1 "$arbor_script")"
    if [[ "$arbor_shebang" != '#!'* ]]; then
      echo "Could not determine arbor interpreter from: $arbor_script" >&2
      exit 1
    fi
    install -d "$python_exec_dir"
    install -m 755 /dev/stdin "$python_exec_dir/arbor-auth" <<EOF
$arbor_shebang
# -*- coding: utf-8 -*-
import re
import sys
from arbor.local_auth_cli import main
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\\.pyw|\\.exe)?$", "", sys.argv[0])
    sys.exit(main())
EOF
    ln -sf "$arbor_link" /usr/bin/arbor-auth
    return
  fi

  arbor_exec_target="$(readlink -f /usr/bin/arbor 2>/dev/null || true)"
  if [[ -z "$arbor_exec_target" || ! -f "$arbor_exec_target" ]]; then
    arbor_exec_target="/usr/bin/arbor"
  fi
  if [[ ! -f "$arbor_exec_target" ]]; then
    echo "Missing installed arbor launcher: /usr/bin/arbor" >&2
    exit 1
  fi

  arbor_shebang="$(head -n 1 "$arbor_exec_target")"
  if [[ "$arbor_shebang" != '#!'* ]]; then
    echo "Could not determine arbor interpreter from: $arbor_exec_target" >&2
    exit 1
  fi

  install -m 755 /dev/stdin /usr/bin/arbor-auth <<EOF
$arbor_shebang
# -*- coding: utf-8 -*-
import re
import sys
from arbor.local_auth_cli import main
if __name__ == "__main__":
    sys.argv[0] = re.sub(r"(-script\\.pyw|\\.exe)?$", "", sys.argv[0])
    sys.exit(main())
EOF
}

sync_tree() {
  local src="$1"
  local dst="$2"

  if [[ ! -d "$src" ]]; then
    echo "Missing source directory: $src" >&2
    exit 1
  fi

  rm -rf "$dst"
  install -d "$dst"
  cp -r "$src"/. "$dst"/
  find "$dst" \( -name '__pycache__' -o -name '*.pyc' \) -prune -exec rm -rf {} +
  chown -R root:root "$dst"
}

restart_openrc() {
  if rc-service arbor status >/dev/null 2>&1; then
    rc-service arbor stop
  fi
  rc-service arbor-daemon restart
  rc-service arbor restart
}

restart_systemd() {
  if systemctl is-active --quiet arbor; then
    systemctl stop arbor
  fi
  systemctl restart arbor-daemon
  systemctl restart arbor
}

echo "==> Syncing backend packages"
sync_tree "$REPO_DIR/backend/arbor" "$SITE_PACKAGES_DIR/arbor"
sync_tree "$REPO_DIR/backend/daemon" "$SITE_PACKAGES_DIR/daemon"

echo "==> Syncing frontend"
sync_tree "$REPO_DIR/frontend/alpine" "$FRONTEND_DIR"

echo "==> Syncing OpenRC init scripts"
if [[ -d /etc/init.d ]]; then
  install -m 0755 -o root -g root "$REPO_DIR/openrc/arbor-daemon" /etc/init.d/arbor-daemon
  install -m 0755 -o root -g root "$REPO_DIR/openrc/arbor"        /etc/init.d/arbor
fi

echo "==> Syncing logrotate config"
if [[ -d /etc/logrotate.d ]]; then
  install -m 0644 -o root -g root "$REPO_DIR/config/logrotate.d/arbor" /etc/logrotate.d/arbor
fi

echo "==> Installing arbor-approve wrapper"
install_arbor_approve_wrapper
echo "==> Installing arbor-auth wrapper"
install_arbor_auth_wrapper

echo "==> Restarting services"
if command -v rc-service >/dev/null 2>&1; then
  restart_openrc
elif command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  restart_systemd
else
  echo "No supported service manager found; restart arbor-daemon and arbor manually." >&2
  exit 1
fi

echo "==> Sync complete"
