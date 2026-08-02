from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


HERE = Path(__file__).resolve().parent
ALERTS_PATH = HERE / "cowrie_alerts.json"
DB_PATH = Path(os.getenv("ALERTS_DB_PATH", HERE / "alerts.db"))
STATIC_DIR = HERE / "static"
TEMPLATES_DIR = HERE / "templates"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _file_mtime_iso(path: Path) -> Optional[str]:
    try:
        ts = path.stat().st_mtime
    except FileNotFoundError:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def load_events() -> List[Dict[str, Any]]:
    """
    Read events from the live SQLite store, falling back to the legacy JSON snapshot.

    The Cowrie ingestion process writes alerts.db; querying it here keeps the
    dashboard and map current without requiring a second export process.
    """
    if DB_PATH.exists():
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    """
                    SELECT id, event_type, session, ip, source_port, country, city,
                           username, password, timestamp, latitude AS lat,
                           longitude AS lon, severity, message, command
                    FROM alerts
                    WHERE ip IS NOT NULL
                    ORDER BY id DESC
                    LIMIT 2000
                    """
                ).fetchall()
            if rows:
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            # Keep the legacy dashboard usable during a database migration or lock issue.
            if not ALERTS_PATH.exists():
                raise HTTPException(status_code=500, detail=f"Failed to read alerts.db: {exc}")

    if not ALERTS_PATH.exists():
        return []

    try:
        raw = ALERTS_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read cowrie_alerts.json: {e}")

    if not isinstance(data, list):
        raise HTTPException(status_code=500, detail="cowrie_alerts.json must be a JSON array")

    events: List[Dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        events.append(item)

    # Newest-first if timestamps are available; otherwise keep file order.
    def key(ev: Dict[str, Any]) -> str:
        ts = ev.get("timestamp")
        return ts if isinstance(ts, str) else ""

    if any(isinstance(e.get("timestamp"), str) for e in events):
        events.sort(key=key, reverse=True)
    return events


def event_id(ev: Dict[str, Any]) -> Tuple[Any, ...]:
    """
    Best-effort stable identifier without requiring changes to cowrie_geo_push.py.
    If a timestamp exists in the future, it will make this more accurate.
    """
    return (
        ev.get("id"),
        ev.get("ip"),
        ev.get("country"),
        ev.get("city"),
        ev.get("lat"),
        ev.get("lon"),
        ev.get("timestamp"),
    )


def compute_stats(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_attacks = len(events)
    unique_ips = len({e.get("ip") for e in events if e.get("ip")})

    countries = [e.get("country") or "Unknown" for e in events]
    top_countries = [{"country": c, "count": n} for c, n in Counter(countries).most_common(10)]
    ips = [e.get("ip") for e in events if e.get("ip")]
    top_ips = [{"ip": ip, "count": n} for ip, n in Counter(ips).most_common(10)]

    last_ts: Optional[str] = None
    for e in events:
        ts = e.get("timestamp")
        if isinstance(ts, str) and ts:
            last_ts = ts
            break
    if last_ts is None:
        last_ts = _file_mtime_iso(ALERTS_PATH)

    return {
        "total_attacks": total_attacks,
        "unique_ip_count": unique_ips,
        "top_countries": top_countries,
        "top_ips": top_ips,
        "last_attack_timestamp": last_ts,
        "generated_at": _utc_now_iso(),
    }


def compute_db_stats() -> Dict[str, Any]:
    """Compute complete database totals without the event-window limit."""
    with sqlite3.connect(DB_PATH, timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        summary = conn.execute(
            """
            SELECT COUNT(*) AS total_attacks,
                   COUNT(DISTINCT ip) AS unique_ip_count,
                   MAX(timestamp) AS last_attack_timestamp,
                   SUM(CASE WHEN event_type = 'cowrie.login.failed' THEN 1 ELSE 0 END) AS failed_logins,
                   SUM(CASE WHEN event_type = 'cowrie.login.success' THEN 1 ELSE 0 END) AS successful_logins,
                   SUM(CASE WHEN event_type = 'cowrie.session.connect' THEN 1 ELSE 0 END) AS connection_only,
                   SUM(CASE WHEN command IS NOT NULL AND command != '' THEN 1 ELSE 0 END) AS commands_observed
            FROM alerts
            """
        ).fetchone()
        countries = conn.execute(
            """SELECT COALESCE(country, 'Unknown') AS value, COUNT(*) AS count
               FROM alerts GROUP BY value ORDER BY count DESC LIMIT 10"""
        ).fetchall()
        ips = conn.execute(
            """SELECT ip AS value, COUNT(*) AS count
               FROM alerts WHERE ip IS NOT NULL GROUP BY ip ORDER BY count DESC LIMIT 10"""
        ).fetchall()
        usernames = conn.execute(
            """SELECT username AS value, COUNT(*) AS count
               FROM alerts WHERE username IS NOT NULL AND username != ''
               GROUP BY username ORDER BY count DESC LIMIT 10"""
        ).fetchall()
        passwords = conn.execute(
            """SELECT password AS value, COUNT(*) AS count
               FROM alerts WHERE password IS NOT NULL AND password != ''
               GROUP BY password ORDER BY count DESC LIMIT 10"""
        ).fetchall()
    return {
        **dict(summary),
        "top_countries": [{"country": row["value"], "count": row["count"]} for row in countries],
        "top_ips": [{"ip": row["value"], "count": row["count"]} for row in ips],
        "top_usernames": [{"username": row["value"], "count": row["count"]} for row in usernames],
        "top_passwords": [{"password": row["value"], "count": row["count"]} for row in passwords],
        "generated_at": _utc_now_iso(),
    }


app = FastAPI(title="Honeypot Live Dashboard API", version="1.0.0")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/events")
def get_events(limit: int = 200) -> JSONResponse:
    events = load_events()
    if limit < 1:
        limit = 1
    if limit > 2000:
        limit = 2000
    return JSONResponse(content={"events": events[:limit], "count": min(len(events), limit)})


@app.get("/stats")
def get_stats() -> JSONResponse:
    if DB_PATH.exists():
        try:
            return JSONResponse(content=compute_db_stats())
        except sqlite3.Error:
            pass
    return JSONResponse(content=compute_stats(load_events()))


@app.get("/map")
def get_map(request: Request) -> HTMLResponse:
    """
    Keep the legacy link useful by serving the live dashboard map.  The previous
    route pointed at a stale generated file in a different directory.
    """
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/stream")
async def stream() -> StreamingResponse:
    """
    Server-Sent Events stream of newly observed alerts.

    The primary source is alerts.db, with the legacy JSON snapshot used only
    when the database is not available. New alerts are detected by diffing IDs.
    """

    async def gen() -> AsyncGenerator[bytes, None]:
        # The UI loads existing history from /events. Seed the stream cursor with
        # current IDs so a new browser receives only attempts recorded afterward.
        try:
            last_ids: Set[Tuple[Any, ...]] = {event_id(ev) for ev in load_events()}
        except HTTPException:
            last_ids = set()

        source_path = DB_PATH if DB_PATH.exists() else ALERTS_PATH
        try:
            last_mtime: Optional[float] = source_path.stat().st_mtime
        except FileNotFoundError:
            last_mtime = None

        # Initial handshake event lets the UI show "connected".
        yield f"event: hello\ndata: {json.dumps({'connected_at': _utc_now_iso()})}\n\n".encode("utf-8")

        while True:
            source_path = DB_PATH if DB_PATH.exists() else ALERTS_PATH
            try:
                st = source_path.stat()
                mtime = st.st_mtime
            except FileNotFoundError:
                mtime = None

            # Only reload when the snapshot changes; otherwise keep the connection alive.
            if mtime is not None and mtime != last_mtime:
                last_mtime = mtime
                try:
                    events = load_events()
                except HTTPException as e:
                    payload = {"error": e.detail, "at": _utc_now_iso()}
                    yield f"event: error\ndata: {json.dumps(payload)}\n\n".encode("utf-8")
                    await asyncio.sleep(2)
                    continue

                current_ids = {event_id(ev) for ev in events}
                new_ids = current_ids - last_ids
                last_ids = current_ids

                if new_ids:
                    # Emit in file order (best-effort recent-first if timestamps exist).
                    for ev in events:
                        if event_id(ev) in new_ids:
                            yield f"event: attack\ndata: {json.dumps(ev)}\n\n".encode("utf-8")
                else:
                    yield f"event: keepalive\ndata: {json.dumps({'at': _utc_now_iso()})}\n\n".encode("utf-8")
            else:
                yield f"event: keepalive\ndata: {json.dumps({'at': _utc_now_iso()})}\n\n".encode("utf-8")

            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "database_exists": DB_PATH.exists(),
        "database_mtime": _file_mtime_iso(DB_PATH),
        "alerts_file_exists": ALERTS_PATH.exists(),
        "alerts_file_mtime": _file_mtime_iso(ALERTS_PATH),
        "pid": os.getpid(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("fastapi_app:app", host="0.0.0.0", port=8000, reload=False)

