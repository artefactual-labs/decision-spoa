#!/bin/sh
set -e

SPOA_SERVICE="decision-spoa.service"
UPDATE_SERVICE="decision-geoip-db-updates.service"
UPDATE_TIMER="decision-geoip-db-updates.timer"
DATA_DIR="/var/lib/decision"
POLICY_DIR="/etc/decision-policy"
RUN_USER="haproxy"
RUN_GROUP="haproxy"

if ! getent passwd "$RUN_USER" >/dev/null 2>&1; then
  RUN_USER="root"
fi

if ! getent group "$RUN_GROUP" >/dev/null 2>&1; then
  RUN_GROUP="root"
fi

install -d -m0750 -o "$RUN_USER" -g "$RUN_GROUP" "$DATA_DIR"
install -d -m0750 -o root -g "$RUN_GROUP" "$POLICY_DIR"

if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled >/dev/null 2>&1; then
  if command -v semanage >/dev/null 2>&1; then
    for PORT in 9907 9908; do
      semanage port -a -t http_port_t -p tcp "$PORT" >/dev/null 2>&1 || \
        semanage port -m -t http_port_t -p tcp "$PORT" >/dev/null 2>&1 || true
    done
  fi
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now "$SPOA_SERVICE" >/dev/null 2>&1 || true
  systemctl enable --now "$UPDATE_TIMER" >/dev/null 2>&1 || true
  systemctl start "$UPDATE_SERVICE" >/dev/null 2>&1 || true
fi

exit 0
