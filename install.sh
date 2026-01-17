#!/usr/bin/env bash
set -Eeuo pipefail

early_error() {
  echo "[FATAL] line=$2 cmd='$3' exit=$1" >&2
  exit "$1"
}
trap 'early_error $? $LINENO "$BASH_COMMAND"' ERR

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="/opt/monitor"
SERVICE_NAME="monitor-lite"

log() {
  printf '[install] %s\n' "$*" >&2
}

if [[ -x "${SCRIPT_DIR}/bootstrap.sh" ]]; then
  log "Running bootstrap.sh"
  "${SCRIPT_DIR}/bootstrap.sh"
fi

if [[ "$EUID" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

log "Installing to ${TARGET_DIR}"
$SUDO mkdir -p "$TARGET_DIR"
$SUDO cp "${SCRIPT_DIR}/monitor.sh" "${TARGET_DIR}/monitor.sh"
$SUDO chmod +x "${TARGET_DIR}/monitor.sh"  # при строгих политиках можно заменить на: $SUDO chmod u+x "${TARGET_DIR}/monitor.sh"

if [[ ! -f "${TARGET_DIR}/.env" ]]; then
  log "Creating ${TARGET_DIR}/.env from .env.example"
  $SUDO cp "${SCRIPT_DIR}/.env.example" "${TARGET_DIR}/.env"
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  log "systemd detected, installing timer"
  SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  TIMER_FILE="/etc/systemd/system/${SERVICE_NAME}.timer"

  if ! systemctl list-unit-files "${SERVICE_NAME}.service" --no-legend --no-pager 2>/dev/null | awk 'NF{print $1}' | grep -q "${SERVICE_NAME}.service"; then
    $SUDO tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=Monitor Lite

[Service]
Type=oneshot
WorkingDirectory=${TARGET_DIR}
ExecStart=${TARGET_DIR}/monitor.sh
EOF
  fi

  if ! systemctl list-unit-files "${SERVICE_NAME}.timer" --no-legend --no-pager 2>/dev/null | awk 'NF{print $1}' | grep -q "${SERVICE_NAME}.timer"; then
    $SUDO tee "$TIMER_FILE" >/dev/null <<EOF
[Unit]
Description=Run Monitor Lite every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF
  fi

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now "${SERVICE_NAME}.timer"
  log "Timer enabled: ${SERVICE_NAME}.timer"
else
  if [[ -d /etc/cron.d ]] && command -v crontab >/dev/null 2>&1; then
    log "systemd not detected, installing cron"
    CRON_FILE="/etc/cron.d/${SERVICE_NAME}"
    $SUDO tee "$CRON_FILE" >/dev/null <<EOF
* * * * * root ${TARGET_DIR}/monitor.sh >/dev/null 2>&1
EOF
    log "Cron installed: ${CRON_FILE}"
  else
    log "No systemd or cron detected; automatic scheduling is not available"
    RUNNER="${TARGET_DIR}/run.sh"
    $SUDO tee "$RUNNER" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

while true; do
  "${SCRIPT_DIR}/monitor.sh" || true
  sleep 60
done
EOF
    $SUDO chmod +x "$RUNNER"  # при строгих политиках можно заменить на: $SUDO chmod u+x "$RUNNER"
    log "Created runner: ${RUNNER} (start it manually if needed)"
  fi
fi
