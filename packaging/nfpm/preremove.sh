#!/bin/sh
set -e

SPOA_SERVICE="decision-spoa.service"
UPDATE_TIMER="decision-geoip-db-updates.timer"
ACTION="$1"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  case "$ACTION" in
    remove|purge|0)
      systemctl stop "$SPOA_SERVICE" >/dev/null 2>&1 || true
      systemctl disable "$SPOA_SERVICE" >/dev/null 2>&1 || true
      systemctl stop "$UPDATE_TIMER" >/dev/null 2>&1 || true
      systemctl disable "$UPDATE_TIMER" >/dev/null 2>&1 || true
      ;;
  esac
fi

exit 0
