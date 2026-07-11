#!/usr/bin/env bash
# Build the honeypot for linux/amd64 and deploy the single binary to the VM.
# Usage:  HOST=user@VM_IP ./deploy/deploy.sh
set -euo pipefail
: "${HOST:?set HOST=user@VM_IP (e.g. HOST=me@34.9.8.7 ./deploy/deploy.sh)}"

echo "→ building linux/amd64 binary (assets embedded)…"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /tmp/honeypot ./honeypot/server

echo "→ copying to $HOST…"
scp /tmp/honeypot "$HOST:/tmp/honeypot"

echo "→ installing + restarting…"
ssh "$HOST" 'sudo install -m755 /tmp/honeypot /opt/honeypot/honeypot && \
             sudo chown honeypot:honeypot /opt/honeypot/honeypot && \
             sudo systemctl restart honeypot && \
             sleep 1 && sudo systemctl --no-pager --lines=8 status honeypot'
echo "✓ deployed"
