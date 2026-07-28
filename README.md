# Honeypot telemetry dashboard

An SSH-honeypot monitoring project built around Cowrie. It enriches incoming
connection attempts with GeoIP data, records them in SQLite, and presents a
live FastAPI dashboard with a streaming attack map.

## Architecture

```text
Internet → Cowrie → cowrie_geo_push.py → alerts.db → FastAPI dashboard
                                      └→ optional Loki / email / Telegram alerts
```

`honeypot-scripts/cowrie_geo_push.py` reads Cowrie's log, enriches IP addresses
with GeoLite2 city/ASN data, and writes alerts to `honeypot-web/alerts.db`.
The dashboard reads that database directly and publishes new events through
Server-Sent Events (SSE). A legacy JSON snapshot is used only when the database
has not yet received any alerts.

## Run locally

Create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the live dashboard:

```powershell
Set-Location honeypot-web
..\.venv\Scripts\python.exe -m uvicorn fastapi_app:app --host 0.0.0.0 --port 8001
```

Open `http://127.0.0.1:8001`. The live map plots GeoIP coordinates, fits the
available locations on load, and receives new events through `/stream`.

## Configure ingestion

Copy `.env.example` to `.env` and update the paths for the host that runs
Cowrie. At minimum, configure:

```dotenv
LOG_FILE=/path/to/cowrie.log
GEO_DB_PATH=/path/to/GeoLite2-City.mmdb
GEO_ASN_PATH=/path/to/GeoLite2-ASN.mmdb
ALERTS_DB_PATH=/path/to/Honeypot/honeypot-web/alerts.db
```

Run the ingestion job continuously with your service manager or scheduler:

```bash
python honeypot-scripts/cowrie_geo_push.py
```

For real-time alerts, run it on a short interval or as a supervised service.
The dashboard becomes live only after this job can access Cowrie's log and
write rows to `alerts.db`.

## Deploy on a VPS

Use an Ubuntu VPS for the full stack. Cowrie needs a persistent SSH listener,
and this project also needs a persistent ingestion process and SQLite storage.
Serverless hosts are not suitable for the full deployment.

1. Install Python, Cowrie, and the GeoLite2 databases on the VPS.
2. Clone this repository and create `.env` with the VPS paths.
3. Run the ingestion script as a service.
4. Run Uvicorn behind a reverse proxy for the dashboard.
5. Expose only the Cowrie listener publicly; protect dashboard access.

Keep the honeypot isolated from production systems and do not forward its
captured credentials or sessions into your own infrastructure.

## Project layout

- `honeypot-web/fastapi_app.py` — live API, SSE stream, and dashboard routes.
- `honeypot-web/templates/dashboard.html` — live dashboard and Leaflet map.
- `honeypot-scripts/cowrie_geo_push.py` — Cowrie log ingestion and enrichment.
- `honeypot-scripts/update_attack_map.py` — optional static map generator.
- `.env.example` — configuration template.

## Validation

```powershell
.\.venv\Scripts\python.exe -m py_compile honeypot-web\fastapi_app.py honeypot-scripts\cowrie_geo_push.py
```
