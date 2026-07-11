#!/usr/bin/env bash
# VM bootstrap for the PULL-BASED (no-terminal) deploy. Runs from the instance
# startup-script on boot. Sets up the honeypot service + an updater timer that
# fetches the latest release binary and config. Idempotent (safe every boot).
set -euo pipefail

RAW=https://raw.githubusercontent.com/bogdanripa/bot-detector/main/deploy
DIR=/opt/honeypot

id honeypot >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin honeypot
mkdir -p "$DIR/certs"
chown -R honeypot:honeypot "$DIR"

curl -fsSL -o "$DIR/update.sh" "$RAW/update.sh"
chmod +x "$DIR/update.sh"

cat > /etc/systemd/system/honeypot.service <<UNIT
[Unit]
Description=Bot-detector honeypot
After=network-online.target
Wants=network-online.target
[Service]
User=honeypot
Group=honeypot
WorkingDirectory=$DIR
EnvironmentFile=-$DIR/env
ExecStart=$DIR/honeypot
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/honeypot-update.service <<UNIT
[Unit]
Description=Update honeypot from the latest release
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
ExecStart=$DIR/update.sh
UNIT

cat > /etc/systemd/system/honeypot-update.timer <<UNIT
[Unit]
Description=Poll for honeypot updates
[Timer]
OnBootSec=20
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable honeypot.service honeypot-update.timer
systemctl start honeypot-update.service   # first pull: writes env, installs binary, starts honeypot
systemctl start honeypot-update.timer
echo "honeypot bootstrap complete"
