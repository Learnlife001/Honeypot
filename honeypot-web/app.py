from flask import Flask, jsonify, render_template, send_from_directory
import os
import sqlite3
import subprocess
import sys
import atexit
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "alerts.db")
MAP_DIR = os.path.join(BASE_DIR, "static")
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
            timestamp TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def get_recent_alerts(limit=50):
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT ip, country, city, username, password, timestamp
        FROM alerts
        ORDER BY datetime(timestamp) DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_top_counts(column_name, limit=10):
    conn = get_db_connection()
    rows = conn.execute(
        f"""
        SELECT COALESCE(NULLIF(TRIM({column_name}), ''), 'Unknown') AS label, COUNT(*) AS count
        FROM alerts
        GROUP BY label
        ORDER BY count DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return {row["label"]: row["count"] for row in rows}


def get_attack_statistics():
    conn = get_db_connection()
    total_row = conn.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()
    conn.close()

    return {
        "country_counts": get_top_counts("country", 10),
        "ip_counts": get_top_counts("ip", 10),
        "username_counts": get_top_counts("username", 10),
        "password_counts": get_top_counts("password", 10),
        "total_attacks": total_row["total"] if total_row else 0,
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


if __name__ == "__main__":
    init_db()
    print("Flask app running at http://<your_vm_ip>:5000/")
    app.run(host="0.0.0.0", port=5000)