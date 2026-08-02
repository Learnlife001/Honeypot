"""Continuously ingest Cowrie JSON events into the dashboard SQLite database."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / ".env")

LOG_FILE = Path(
    os.getenv(
        "COWRIE_JSON_LOG",
        "/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json",
    )
)
DB_PATH = Path(os.getenv("ALERTS_DB_PATH", ROOT / "honeypot-web" / "alerts.db"))
STATE_FILE = Path(os.getenv("INGEST_STATE_FILE", ROOT / "data" / "cowrie-offset.json"))
REMOTE_GEO = os.getenv("ENABLE_REMOTE_GEO", "true").lower() in {"1", "true", "yes"}
GEO_LOOKUP_URL = os.getenv("GEO_LOOKUP_URL", "https://ipwho.is/{ip}")
POLL_SECONDS = max(float(os.getenv("INGEST_POLL_SECONDS", "1")), 0.2)


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db() -> None:
    with closing(connect_db()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT UNIQUE,
                event_type TEXT,
                session TEXT,
                ip TEXT NOT NULL,
                source_port INTEGER,
                country TEXT,
                city TEXT,
                username TEXT,
                password TEXT,
                timestamp TEXT,
                latitude REAL,
                longitude REAL,
                asn TEXT,
                org TEXT,
                severity TEXT,
                client_version TEXT,
                hassh TEXT,
                message TEXT,
                command TEXT
            )
            """
        )
        conn.commit()
        existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        migrations = {
            "event_key": "TEXT",
            "event_type": "TEXT",
            "session": "TEXT",
            "source_port": "INTEGER",
            "latitude": "REAL",
            "longitude": "REAL",
            "asn": "TEXT",
            "org": "TEXT",
            "severity": "TEXT",
            "client_version": "TEXT",
            "hassh": "TEXT",
            "message": "TEXT",
            "command": "TEXT",
        }
        for column, sql_type in migrations.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {sql_type}")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_event_key ON alerts(event_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip_time ON alerts(ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                country TEXT,
                city TEXT,
                latitude REAL,
                longitude REAL,
                asn TEXT,
                org TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def geo_for_ip(conn: sqlite3.Connection, ip: str) -> dict[str, Any]:
    cached = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    if cached:
        return dict(cached)
    result: dict[str, Any] = {
        "country": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": None,
        "org": None,
    }
    if REMOTE_GEO and public_ip(ip):
        try:
            response = requests.get(GEO_LOOKUP_URL.format(ip=ip), timeout=5)
            response.raise_for_status()
            payload = response.json()
            if payload.get("success", True):
                connection = payload.get("connection") or {}
                result.update(
                    country=payload.get("country") or "Unknown",
                    city=payload.get("city") or "Unknown",
                    latitude=payload.get("latitude"),
                    longitude=payload.get("longitude"),
                    asn=str(connection.get("asn")) if connection.get("asn") else None,
                    org=connection.get("org") or connection.get("isp"),
                )
        except (requests.RequestException, ValueError, TypeError):
            pass
    conn.execute(
        """
        INSERT OR REPLACE INTO geo_cache
            (ip, country, city, latitude, longitude, asn, org, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (
            ip,
            result["country"],
            result["city"],
            result["latitude"],
            result["longitude"],
            result["asn"],
            result["org"],
        ),
    )
    return result


def event_key(event: dict[str, Any]) -> str:
    stable = "|".join(
        str(event.get(key, ""))
        for key in ("eventid", "session", "src_ip", "src_port", "timestamp")
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def severity(conn: sqlite3.Connection, ip: str, timestamp: str) -> str:
    row = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE ip = ? AND datetime(timestamp) >= datetime(?, '-2 minutes')
        """,
        (ip, timestamp),
    ).fetchone()
    count = int(row[0]) if row else 0
    if count >= 9:
        return "high"
    if count >= 3:
        return "medium"
    return "low"


def ingest_event(conn: sqlite3.Connection, event: dict[str, Any]) -> bool:
    kind = str(event.get("eventid") or "")
    ip = str(event.get("src_ip") or "")
    session = str(event.get("session") or "")
    timestamp = str(event.get("timestamp") or "")
    if not ip or not timestamp:
        return False

    if kind in {"cowrie.login.failed", "cowrie.login.success"} and session:
        updated = conn.execute(
            """
            UPDATE alerts
            SET event_type = ?, username = ?, password = ?, message = ?
            WHERE id = (
                SELECT id FROM alerts WHERE session = ? ORDER BY id DESC LIMIT 1
            )
            """,
            (kind, event.get("username"), event.get("password"), event.get("message"), session),
        ).rowcount
        if updated:
            return True

    if kind == "cowrie.command.input" and session:
        updated = conn.execute(
            """
            UPDATE alerts
            SET command = ?, message = COALESCE(?, message)
            WHERE id = (
                SELECT id FROM alerts WHERE session = ? ORDER BY id DESC LIMIT 1
            )
            """,
            (event.get("input"), event.get("message"), session),
        ).rowcount
        return bool(updated)

    if kind in {"cowrie.session.closed", "cowrie.client.version"} and session:
        updated = conn.execute(
            """
            UPDATE alerts
            SET message = COALESCE(?, message),
                client_version = COALESCE(?, client_version)
            WHERE id = (
                SELECT id FROM alerts WHERE session = ? ORDER BY id DESC LIMIT 1
            )
            """,
            (event.get("message"), event.get("version"), session),
        ).rowcount
        return bool(updated)

    if kind != "cowrie.session.connect" and kind not in {
        "cowrie.login.failed",
        "cowrie.login.success",
    }:
        return False

    geo = geo_for_ip(conn, ip)
    conn.execute(
        """
        INSERT OR IGNORE INTO alerts (
            event_key, event_type, session, ip, source_port, country, city,
            username, password, timestamp, latitude, longitude, asn, org, severity,
            message, command
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_key(event),
            kind,
            session or None,
            ip,
            event.get("src_port"),
            geo["country"],
            geo["city"],
            event.get("username"),
            event.get("password"),
            timestamp,
            geo["latitude"],
            geo["longitude"],
            geo["asn"],
            geo["org"],
            severity(conn, ip, timestamp),
            event.get("message"),
            event.get("input"),
        ),
    )
    return True


def load_state() -> dict[str, int]:
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return {"inode": int(value.get("inode", 0)), "offset": int(value.get("offset", 0))}
    except (FileNotFoundError, ValueError, TypeError, json.JSONDecodeError):
        return {"inode": 0, "offset": 0}


def save_state(inode: int, offset: int) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"inode": inode, "offset": offset}), encoding="utf-8")
    temporary.replace(STATE_FILE)


def process_available() -> int:
    if not LOG_FILE.exists():
        return 0
    stat = LOG_FILE.stat()
    state = load_state()
    offset = state["offset"] if state["inode"] == stat.st_ino else 0
    if offset > stat.st_size:
        offset = 0
    processed = 0
    with LOG_FILE.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        with closing(connect_db()) as conn:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                processed += int(ingest_event(conn, event))
            conn.commit()
        save_state(stat.st_ino, handle.tell())
    return processed


def main() -> None:
    init_db()
    print(f"Watching {LOG_FILE} -> {DB_PATH}", flush=True)
    while True:
        count = process_available()
        if count:
            print(f"Stored {count} Cowrie event(s)", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
