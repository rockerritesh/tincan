#!/usr/bin/env bash
# Provision agent-tunnel on the VM. Idempotent: safe to re-run for upgrades.
#
# The broker binds 127.0.0.1 only. cloudflared dials *out* to Cloudflare, so no
# inbound firewall rule is needed and the VM keeps no listening public port.
set -euo pipefail

APP_DIR=/opt/agent-tunnel
DATA_DIR=/var/lib/agent-tunnel
ENV_FILE=/etc/agent-tunnel.env
SVC_USER=agenttunnel
STAGE=/tmp/agent-tunnel-stage

echo "==> node"
if ! command -v node >/dev/null 2>&1 || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 20 ]; then
  echo "installing Node 22 from NodeSource"
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - >/dev/null
  sudo apt-get install -y nodejs >/dev/null
fi
node -v

echo "==> cloudflared"
if ! command -v cloudflared >/dev/null 2>&1; then
  ARCH=$(dpkg --print-architecture)
  curl -fsSL -o /tmp/cloudflared.deb \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}.deb"
  sudo dpkg -i /tmp/cloudflared.deb >/dev/null
  rm -f /tmp/cloudflared.deb
fi
cloudflared --version

echo "==> service user and directories"
id -u "$SVC_USER" >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
sudo mkdir -p "$APP_DIR" "$DATA_DIR"
sudo rsync -a --delete "$STAGE/" "$APP_DIR/"
sudo chown -R root:root "$APP_DIR"
sudo chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"
sudo chmod 750 "$DATA_DIR"

echo "==> environment file"
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" >/dev/null <<EOF
BROKER_TOKEN=${BROKER_TOKEN}
PORT=8787
HOST=127.0.0.1
DATA_DIR=${DATA_DIR}
EOF
  echo "wrote $ENV_FILE"
else
  echo "$ENV_FILE already exists — leaving the existing token in place"
fi
sudo chown root:"$SVC_USER" "$ENV_FILE"
sudo chmod 640 "$ENV_FILE"

echo "==> systemd units"
sudo tee /etc/systemd/system/agent-tunnel-broker.service >/dev/null <<EOF
[Unit]
Description=agent-tunnel message broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
EnvironmentFile=$ENV_FILE
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node $APP_DIR/server/broker.mjs
Restart=always
RestartSec=3

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/agent-tunnel-cloudflared.service >/dev/null <<EOF
[Unit]
Description=Cloudflare quick tunnel for agent-tunnel broker
After=agent-tunnel-broker.service
Requires=agent-tunnel-broker.service

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
ExecStart=/usr/bin/cloudflared tunnel --url http://127.0.0.1:8787 --no-autoupdate --loglevel info
Restart=always
RestartSec=5

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

echo "==> url helper"
sudo tee /usr/local/bin/agent-tunnel-url >/dev/null <<'EOF'
#!/usr/bin/env bash
# Print the current public URL of the quick tunnel. The URL is only ever
# announced in the cloudflared log, and changes each time that service restarts.
set -euo pipefail
journalctl -u agent-tunnel-cloudflared --no-pager -o cat \
  | grep -Eo 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1
EOF
sudo chmod +x /usr/local/bin/agent-tunnel-url

echo "==> enable and (re)start"
sudo systemctl daemon-reload
sudo systemctl enable --now agent-tunnel-broker.service >/dev/null
sudo systemctl restart agent-tunnel-broker.service
sudo systemctl enable --now agent-tunnel-cloudflared.service >/dev/null
sudo systemctl restart agent-tunnel-cloudflared.service

echo "==> waiting for the tunnel to announce a URL"
for _ in $(seq 1 45); do
  URL="$(/usr/local/bin/agent-tunnel-url 2>/dev/null || true)"
  [ -n "$URL" ] && break
  sleep 1
done

echo
echo "broker:      $(systemctl is-active agent-tunnel-broker.service)"
echo "cloudflared: $(systemctl is-active agent-tunnel-cloudflared.service)"
echo "local health:"
curl -sf http://127.0.0.1:8787/v1/health || echo "  LOCAL HEALTH FAILED"
echo
echo "PUBLIC_URL=${URL:-NONE}"

echo "==> bootstrap invite"
if [ ! -f "$DATA_DIR/.bootstrapped" ]; then
  sudo -u "$SVC_USER" /usr/bin/node "$APP_DIR/server/bootstrap.mjs" \
    --data-dir "$DATA_DIR" --label "owner" --ttl-minutes 60
  sudo -u "$SVC_USER" touch "$DATA_DIR/.bootstrapped"
else
  echo "already bootstrapped; run server/bootstrap.mjs by hand to mint another invite"
fi
