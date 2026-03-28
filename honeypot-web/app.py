from flask import Flask, jsonify, render_template, send_from_directory
import os
import sqlite3
import subprocess
import sys
import atexit
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "alerts.db")
MAP_DIR = os.path.join(BASE_DIR, "..", "honeypot-scripts")
MAP_FILE = "attack_map.html"
UPDATE_MAP_SCRIPT = os.path.join(BASE_DIR, "..", "honeypot-scripts", "update_attack_map.py")
scheduler = BackgroundScheduler()


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    return conn


def run_update_attack_map():
    try:
        subprocess.run(
            [sys.executable, UPDATE_MAP_SCRIPT],
            cwd=os.path.dirname(UPDATE_MAP_SCRIPT),
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"update_attack_map.py failed: {exc.stderr or exc}")


def start_scheduler():
    if scheduler.running:
        return
    scheduler.add_job(
        run_update_attack_map,
        trigger="interval",
        minutes=5,
        id="update_attack_map_job",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        run_update_attack_map,
        trigger="date",
        run_date=datetime.now(),
        id="update_attack_map_startup",
        replace_existing=True,
        max_instances=1,
    )
    scheduler.start()


def init_db():
    conn = get_db_connection()
    conn.execute("PRAGMA journal_mode=WAL;")
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
        # Feature 1: ASN enrichment (GeoLite2-ASN)
        "ALTER TABLE alerts ADD COLUMN asn TEXT",
        "ALTER TABLE alerts ADD COLUMN org TEXT",
        # Feature 2: attack severity classification
        "ALTER TABLE alerts ADD COLUMN severity TEXT",
        # Feature 5: bot fingerprint storage
        "ALTER TABLE alerts ADD COLUMN client_version TEXT",
        "ALTER TABLE alerts ADD COLUMN hassh TEXT",
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Indexes: speed ip + time-window queries (leaderboard, reports) and timestamp ordering; username GROUP BY
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_ip_timestamp
            ON alerts(ip, timestamp)
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
            ON alerts(timestamp)
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alerts_username
            ON alerts(username)
            """
        )
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def get_recent_alerts(limit=50):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT ip, country, city, username, password, timestamp,
               asn, org, severity, client_version, hassh
        FROM alerts
        ORDER BY datetime(timestamp) DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_top_counts(column_name, limit=10, hours=None):
    conn = get_db_connection()
    time_filter = ""
    params = []
    if hours is not None:
        time_filter = "WHERE datetime(timestamp) >= datetime('now', ?)"
        params.append(f"-{hours} hours")
    params.append(limit)
    rows = conn.execute(
        f"""
        SELECT COALESCE(NULLIF(TRIM({column_name}), ''), 'Unknown') AS label, COUNT(*) AS count
        FROM alerts
        {time_filter}
        GROUP BY label
        ORDER BY count DESC
        LIMIT ?
        """,
        tuple(params),
    ).fetchall()
    conn.close()
    return {row["label"]: row["count"] for row in rows}


def get_severity_counts(hours=None):
    """Feature 2: counts per severity tier for /stats (all-time) or windowed reports."""
    conn = get_db_connection()
    time_filter = ""
    params = []
    if hours is not None:
        time_filter = "WHERE datetime(timestamp) >= datetime('now', ?)"
        params.append(f"-{hours} hours")
    rows = conn.execute(
        f"""
        SELECT COALESCE(NULLIF(TRIM(severity), ''), 'low') AS sev, COUNT(*) AS count
        FROM alerts
        {time_filter}
        GROUP BY sev
        """,
        tuple(params),
    ).fetchall()
    conn.close()
    base = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for row in rows:
        key = (row["sev"] or "low").lower()
        if key in base:
            base[key] = row["count"]
    return base


def get_attack_statistics():
    conn = get_db_connection()
    cursor = conn.cursor()

    total_row = cursor.execute(
        "SELECT COUNT(*) AS total FROM alerts"
    ).fetchone()

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE timestamp >= datetime('now', '-5 minutes')
    """)
    attacks_last_5_minutes = cursor.fetchone()[0]

    conn.close()

    return {
        "country_counts": get_top_counts("country", 10),
        "ip_counts": get_top_counts("ip", 10),
        "username_counts": get_top_counts("username", 10),
        "password_counts": get_top_counts("password", 10),
        "total_attacks": total_row["total"] if total_row else 0,
        "attacks_last_5_minutes": attacks_last_5_minutes,
        "severity_counts": get_severity_counts(),
    }


def get_timeline(hours=24):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket, COUNT(*) AS count
        FROM alerts
        WHERE datetime(timestamp) >= datetime('now', ?)
        GROUP BY hour_bucket
        ORDER BY hour_bucket ASC
        """,
        (f"-{hours} hours",),
    ).fetchall()
    conn.close()
    return [{"hour": row["hour_bucket"], "count": row["count"]} for row in rows]


def get_timeline_regions(hours=24):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT
            strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_bucket,
            COALESCE(NULLIF(TRIM(country), ''), 'Unknown') AS country,
            COUNT(*) AS count
        FROM alerts
        WHERE datetime(timestamp) >= datetime('now', ?)
        GROUP BY hour_bucket, country
        ORDER BY hour_bucket ASC, count DESC
        """,
        (f"-{hours} hours",),
    ).fetchall()
    conn.close()

    grouped = {}
    for row in rows:
        hour = row["hour_bucket"]
        if hour not in grouped:
            grouped[hour] = {}
        grouped[hour][row["country"]] = row["count"]

    return [{"hour": hour, "regions": grouped[hour]} for hour in grouped]


def get_active_attackers_top(limit=10):
    """Feature 3: leaderboard of IPs by attempt count in last 5 minutes."""
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT ip, COUNT(*) AS attempts
        FROM alerts
        WHERE timestamp >= datetime('now', '-5 minutes')
        GROUP BY ip
        ORDER BY attempts DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [{"ip": row["ip"], "attempts": row["attempts"]} for row in rows]


def get_daily_report():
    """Feature 6: 24h-focused summary JSON (reuses shared query helpers)."""
    hours = 24
    return {
        "top_countries": get_top_counts("country", 10, hours=hours),
        "top_ips": get_top_counts("ip", 10, hours=hours),
        "top_usernames": get_top_counts("username", 10, hours=hours),
        "top_passwords": get_top_counts("password", 10, hours=hours),
        "top_asns": get_top_counts("asn", 10, hours=hours),
        "severity_distribution": get_severity_counts(hours=24),
        "attack_velocity_last_24h": get_timeline(hours),
    }


init_db()
start_scheduler()
atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)


@app.route("/")
def dashboard():
    alerts = get_recent_alerts()
    return render_template("index.html", alerts=alerts)


@app.route("/map")
def map_view():
    return send_from_directory(MAP_DIR, MAP_FILE)


@app.route("/alerts-data")
def alerts_data():
    return jsonify(get_recent_alerts())


@app.route("/stats")
def stats():
    return jsonify(get_attack_statistics())


@app.route("/timeline")
def timeline():
    return jsonify(get_timeline())


@app.route("/timeline-regions")
def timeline_regions():
    return jsonify(get_timeline_regions())


@app.route("/active-attackers")
def active_attackers():
    return jsonify(get_active_attackers_top())


@app.route("/report/daily")
def report_daily():
    return jsonify(get_daily_report())


if __name__ == "__main__":
    init_db()
    print("Flask app running at http://<your_vm_ip>:5000/")
    app.run(host="0.0.0.0", port=5000)