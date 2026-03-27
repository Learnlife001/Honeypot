import os
import sqlite3

import geoip2.database


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "honeypot-web", "alerts.db"))
GEO_DB_PATH = os.getenv("GEO_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb")

BATCH_SIZE = int(os.getenv("BACKFILL_BATCH_SIZE", "500"))


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=30000;")
    conn.row_factory = sqlite3.Row
    return conn


def ensure_coordinate_columns(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            country TEXT,
            city TEXT,
            username TEXT,
            password TEXT,
            timestamp TEXT,
            latitude REAL,
            longitude REAL
        )
        """
    )
    for stmt in (
        "ALTER TABLE alerts ADD COLUMN latitude REAL",
        "ALTER TABLE alerts ADD COLUMN longitude REAL",
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass


def lookup_coords(reader, ip):
    try:
        res = reader.city(ip)
        lat = res.location.latitude
        lon = res.location.longitude
        if lat is None or lon is None:
            return None, None
        return float(lat), float(lon)
    except Exception:
        return None, None


def backfill():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"alerts.db not found at {DB_PATH}")

    if not os.path.exists(GEO_DB_PATH):
        raise FileNotFoundError(f"GeoLite2 DB not found at {GEO_DB_PATH}")

    conn = get_db_connection()
    try:
        ensure_coordinate_columns(conn)
        conn.commit()

        updated = 0

        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            while True:
                rows = conn.execute(
                    """
                    SELECT id, ip
                    FROM alerts
                    WHERE latitude IS NULL OR longitude IS NULL
                    LIMIT ?
                    """,
                    (BATCH_SIZE,),
                ).fetchall()

                if not rows:
                    break

                params = []
                for row in rows:
                    ip = row["ip"]
                    if not ip:
                        continue
                    lat, lon = lookup_coords(reader, ip)
                    if lat is None or lon is None:
                        continue
                    params.append((lat, lon, row["id"]))

                if params:
                    conn.executemany(
                        "UPDATE alerts SET latitude = ?, longitude = ? WHERE id = ?",
                        params,
                    )
                    updated += len(params)

                conn.commit()

        print(f"Backfill complete. Updated rows: {updated}")
    finally:
        conn.close()


if __name__ == "__main__":
    backfill()

