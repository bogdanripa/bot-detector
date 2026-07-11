#!/usr/bin/env bash
# One-time VM bootstrap for the honeypot. Run as root ON THE VM:
#   sudo bash setup-vm.sh '<deploy-ssh-public-key>' ['<domain>']
#
# Arg 1 (required): the deploy SSH *public* key — lets the GitHub Action's
#                   `deployer` user push new binaries.
# Arg 2 (optional): a domain for Let's Encrypt (omit → self-signed cert).
#
# Creates the `honeypot` (service) and `deployer` (CI) users, /opt/honeypot,
# a narrow sudo rule, and the systemd unit. Idempotent.
set -euo pipefail

PUB="${1:?usage: setup-vm.sh '<deploy-ssh-public-key>' [domain]}"
DOMAIN="${2:-}"

id honeypot >/dev/null 2>&1 || useradd --system --home /opt/honeypot --shell /usr/sbin/nologin honeypot
id deployer >/dev/null 2>&1 || useradd -m -s /bin/bash deployer

mkdir -p /opt/honeypot/certs /home/deployer/.ssh
chown -R deployer:deployer /opt/honeypot
chown -R honeypot:honeypot /opt/honeypot/certs

grep -qF "$PUB" /home/deployer/.ssh/authorized_keys 2>/dev/null || echo "$PUB" >> /home/deployer/.ssh/authorized_keys
chown -R deployer:deployer /home/deployer/.ssh
chmod 700 /home/deployer/.ssh
chmod 600 /home/deployer/.ssh/authorized_keys

echo 'deployer ALL=(root) NOPASSWD: /usr/bin/systemctl restart honeypot' > /etc/sudoers.d/deployer-honeypot
chmod 440 /etc/sudoers.d/deployer-honeypot

DOMAIN_LINE=""
[ -n "$DOMAIN" ] && DOMAIN_LINE="Environment=BD_DOMAIN=$DOMAIN"
cat > /etc/systemd/system/honeypot.service <<UNIT
[Unit]
Description=Bot-detector honeypot
After=network-online.target
Wants=network-online.target
[Service]
User=honeypot
Group=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/opt/honeypot/honeypot
Environment=BD_ADDR=:443
$DOMAIN_LINE
Environment=BD_CERT_CACHE=/opt/honeypot/certs
Environment=BD_ENFORCE_BAND=suspicious
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable honeypot
echo "VM configured. domain=${DOMAIN:-<self-signed>}  service=honeypot (enabled)"
