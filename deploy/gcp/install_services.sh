#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/opt/honeypot}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"
COWRIE_LOG="${COWRIE_LOG:-/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json}"

if [[ ! -f "$PROJECT_DIR/requirements-runtime.txt" ]]; then
  echo "Repository not found at $PROJECT_DIR" >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv

"$PYTHON_BIN" -m venv "$PROJECT_DIR/.venv"
"$PROJECT_DIR/.venv/bin/python" -m pip install --upgrade pip
"$PROJECT_DIR/.venv/bin/python" -m pip install -r "$PROJECT_DIR/requirements-runtime.txt"

install -d -o cowrie -g cowrie -m 0750 "$PROJECT_DIR/data"
install -d -o cowrie -g cowrie -m 0750 "$PROJECT_DIR/honeypot-web"
touch "$PROJECT_DIR/honeypot-web/alerts.db"
chown cowrie:cowrie "$PROJECT_DIR/honeypot-web/alerts.db"

cat >"$PROJECT_DIR/.env" <<EOF
COWRIE_JSON_LOG=$COWRIE_LOG
ALERTS_DB_PATH=$PROJECT_DIR/honeypot-web/alerts.db
INGEST_STATE_FILE=$PROJECT_DIR/data/cowrie-offset.json
INGEST_POLL_SECONDS=1
ENABLE_REMOTE_GEO=true
GEO_LOOKUP_URL=https://ipwho.is/{ip}
EOF
chown root:cowrie "$PROJECT_DIR/.env"
chmod 0640 "$PROJECT_DIR/.env"

cat >/etc/systemd/system/honeypot-ingest.service <<EOF
[Unit]
Description=Cowrie JSON to SQLite ingestion
After=network-online.target cowrie.service
Wants=network-online.target
Requires=cowrie.service

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/.venv/bin/python $PROJECT_DIR/honeypot-scripts/cowrie_to_sqlite.py
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR/data $PROJECT_DIR/honeypot-web

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/honeypot-dashboard.service <<EOF
[Unit]
Description=Honeypot FastAPI dashboard
After=network-online.target honeypot-ingest.service
Wants=network-online.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=$PROJECT_DIR/honeypot-web
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/.venv/bin/uvicorn fastapi_app:app --host 127.0.0.1 --port 8001 --workers 1
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR/data $PROJECT_DIR/honeypot-web

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-ingest.service honeypot-dashboard.service
systemctl --no-pager --full status honeypot-ingest.service honeypot-dashboard.service
curl --fail --silent http://127.0.0.1:8001/health
