#!/usr/bin/env bash
# Pull the newest honeypot binary (from the GitHub "latest" release) and config
# (from VM metadata), and restart the service only if something changed.
# Run by honeypot-update.timer every couple of minutes. Idempotent.
set -euo pipefail

DIR=/opt/honeypot
URL=https://github.com/bogdanripa/bot-detector/releases/download/latest/honeypot
META=http://metadata.google.internal/computeMetadata/v1/instance/attributes
md() { curl -sf -H 'Metadata-Flavor: Google' "$META/$1" 2>/dev/null || true; }

DOMAIN=$(md bd-domain)
ENFORCE=$(md bd-enforce); ENFORCE=${ENFORCE:-suspicious}

# --- config (env file), only rewrite if changed ---
NEWENV=$(mktemp)
cat > "$NEWENV" <<E
BD_ADDR=:443
BD_ENFORCE_BAND=$ENFORCE
BD_CERT_CACHE=$DIR/certs
BD_DOMAIN=$DOMAIN
E
envchanged=0
if ! cmp -s "$NEWENV" "$DIR/env" 2>/dev/null; then
  install -m600 -o honeypot -g honeypot "$NEWENV" "$DIR/env"
  envchanged=1
fi
rm -f "$NEWENV"

# --- binary, only replace if changed ---
binchanged=0
if curl -fsSL -o "$DIR/honeypot.new" "$URL"; then
  if ! cmp -s "$DIR/honeypot.new" "$DIR/honeypot" 2>/dev/null; then
    install -m755 -o honeypot -g honeypot "$DIR/honeypot.new" "$DIR/honeypot"
    binchanged=1
  fi
  rm -f "$DIR/honeypot.new"
fi

if [ "$envchanged" = 1 ] || [ "$binchanged" = 1 ]; then
  systemctl restart honeypot || true
  logger -t honeypot-update "updated bin=$binchanged env=$envchanged domain=${DOMAIN:-<self-signed>}"
fi
