# Honeypot telemetry dashboard

An SSH-honeypot monitoring project built around Cowrie. It enriches incoming
connection attempts with GeoIP data, records them in SQLite, and presents a
live FastAPI dashboard with a streaming attack map.

## Architecture

```text
Internet → Cowrie → cowrie_to_sqlite.py → alerts.db → FastAPI dashboard
```

`honeypot-scripts/cowrie_to_sqlite.py` follows Cowrie's JSON log, enriches each
new source IP once, caches the result, and writes attempts to
`honeypot-web/alerts.db`. No email or messaging credentials are used.
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
COWRIE_JSON_LOG=/path/to/cowrie.json
ALERTS_DB_PATH=/path/to/Honeypot/honeypot-web/alerts.db
```

Run the ingestion job continuously with your service manager or scheduler:

```bash
python honeypot-scripts/cowrie_to_sqlite.py
```

Run it continuously as a systemd service. The dashboard becomes live after the
ingestor can access Cowrie's JSON log and write rows to `alerts.db`.

## Deploy on a VPS

Use an Ubuntu VPS for the full stack. Cowrie needs a persistent SSH listener,
and this project also needs a persistent ingestion process and SQLite storage.
Serverless hosts are not suitable for the full deployment.

1. Install Python and Cowrie on the VPS.
2. Clone this repository and create `.env` with the VPS paths.
3. Run the ingestion script as a service.
4. Run Uvicorn behind a reverse proxy for the dashboard.
5. Expose only the Cowrie listener publicly; protect dashboard access.

Keep the honeypot isolated from production systems and do not forward its
captured credentials or sessions into your own infrastructure.

## Deploy the historical dashboard to Vercel

If you no longer run Cowrie, deploy the static historical map in
`static-dashboard/`. In Vercel, import this repository and set **Root Directory**
to `static-dashboard`. It needs no environment variables or backend service.

This static deployment deliberately labels itself as a snapshot. It uses the
bundled `cowrie_alerts.json` file and will not receive new attempts until a
live Cowrie/VPS backend is restored.

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
