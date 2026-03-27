from flask import Flask, jsonify, render_template, send_from_directory
import os
import sqlite3

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "alerts.db")
MAP_DIR = os.path.join(BASE_DIR, "..", "honeypot-scripts")
MAP_FILE = "attack_map.html"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
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


init_db()


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


if __name__ == "__main__":
    init_db()
    print("Flask app running at http://<your_vm_ip>:5000/")
    app.run(host="0.0.0.0", port=5000)