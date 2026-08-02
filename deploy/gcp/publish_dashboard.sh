#!/usr/bin/env bash
set -euo pipefail

DASHBOARD_PORT="${DASHBOARD_PORT:-8001}"
PUBLIC_IP="${PUBLIC_IP:-$(curl -fsS --max-time 10 https://api.ipify.org)}"
PUBLIC_HOST="${PUBLIC_HOST:-${PUBLIC_IP//./-}.sslip.io}"

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y caddy

sudo tee /etc/caddy/Caddyfile >/dev/null <<EOF
${PUBLIC_HOST} {
    encode zstd gzip
    reverse_proxy 127.0.0.1:${DASHBOARD_PORT}
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy no-referrer
        -Server
    }
}
EOF

sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo systemctl reload-or-restart caddy
sudo systemctl restart honeypot-ingest.service honeypot-dashboard.service

echo "Dashboard: https://${PUBLIC_HOST}/"
echo "Health:    https://${PUBLIC_HOST}/health"
