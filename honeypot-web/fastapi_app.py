from __future__ import annotations

import asyncio
import json
import os
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
    Reads the latest events snapshot from cowrie_alerts.json.
    Expected format: JSON array of objects with at least ip/country/city/lat/lon.
    """
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

    ***REMOVED*** newest-first if we ever get timestamps; otherwise keep file order
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
        "last_attack_timestamp": last_ts,
        "generated_at": _utc_now_iso(),
    }


app = FastAPI(title="Honeypot Live Dashboard API", version="1.0.0")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("dashboard.html", {"request": request})


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
    events = load_events()
    return JSONResponse(content=compute_stats(events))


@app.get("/map")
def get_map() -> HTMLResponse:
    """
    Optional legacy map support: serve the generated static/attack_map.html if present.
    This keeps the existing 'generated Folium HTML map' workflow working without
    requiring Flask to run.
    """
    map_path = STATIC_DIR / "attack_map.html"
    if not map_path.exists():
        raise HTTPException(status_code=404, detail="attack_map.html not found. Generate it or disable map link.")
    return HTMLResponse(content=map_path.read_text(encoding="utf-8"))


@app.get("/stream")
async def stream() -> StreamingResponse:
    """
    Server-Sent Events stream of newly observed events in cowrie_alerts.json.

    Note: cowrie_alerts.json is a snapshot file (not an append-only log), so we
    detect "new" events by diffing event IDs between polls.
    """

    async def gen() -> AsyncGenerator[bytes, None]:
        last_ids: Set[Tuple[Any, ...]] = set()
        last_mtime: Optional[float] = None

        ***REMOVED*** Initial handshake event so the UI can show "connected"
        yield f"event: hello\ndata: {json.dumps({'connected_at': _utc_now_iso()})}\n\n".encode("utf-8")

        while True:
            try:
                st = ALERTS_PATH.stat()
                mtime = st.st_mtime
            except FileNotFoundError:
                mtime = None

            ***REMOVED*** Only reload if file changed, otherwise just keep-alive
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
                    ***REMOVED*** Emit events in file order (best-effort "recent first" if timestamps exist)
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
        "alerts_file_exists": ALERTS_PATH.exists(),
        "alerts_file_mtime": _file_mtime_iso(ALERTS_PATH),
        "pid": os.getpid(),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("fastapi_app:app", host="0.0.0.0", port=8000, reload=False)

