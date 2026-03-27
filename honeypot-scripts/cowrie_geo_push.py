import os
import re
import time
import json
import sqlite3
import requests
from datetime import datetime, timezone
import geoip2.database
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables from .env (project root) if present
load_dotenv()

# Config (use env vars; do not hardcode secrets)
LOKI_URL = os.getenv("LOKI_URL", "http://localhost:3100/loki/api/v1/push")
LOG_FILE = os.getenv("LOG_FILE", "/home/azureuser/cowrie/var/log/cowrie/cowrie.log")
GEO_DB_PATH = os.getenv("GEO_DB_PATH", "/var/lib/GeoIP/GeoLite2-City.mmdb")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
LOG_ALERT_FILE = os.getenv("LOG_ALERT_FILE", "/home/azureuser/telegram_alert_log.txt")
LAST_POSITION_FILE = os.getenv(
    "LAST_POSITION_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "last_position.txt"),
)
ALERTS_DB_PATH = os.getenv(
    "ALERTS_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "honeypot-web", "alerts.db"),
)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")

alerted_ips = set()


def load_last_position():
    if not os.path.exists(LAST_POSITION_FILE):
        return 0
    try:
        with open(LAST_POSITION_FILE, "r", encoding="utf-8") as pos_file:
            return int(pos_file.read().strip() or "0")
    except (ValueError, OSError):
        return 0


def save_last_position(position):
    with open(LAST_POSITION_FILE, "w", encoding="utf-8") as pos_file:
        pos_file.write(str(position))


def get_db_connection():
    conn = sqlite3.connect(ALERTS_DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


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
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()


def insert_alert(ip, country, city, username, password, timestamp, latitude=None, longitude=None):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO alerts (ip, country, city, username, password, timestamp, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (ip, country, city, username, password, timestamp, latitude, longitude),
    )
    conn.commit()
    conn.close()

def resolve_geo(ip, reader):
    try:
        res = reader.city(ip)
        city = res.city.name or "Unknown"
        country = res.country.name or "Unknown"
        lat = res.location.latitude
        lon = res.location.longitude
        return city, country, lat, lon
    except:
        return None, None, None, None

def send_telegram_batch_alert(entries):
    max_length = 4000
    header = "**Cowrie Alerts**\n"
    message = header
    for entry in entries:
        part = f"• `{entry['ip']}` - {entry['city']}, {entry['country']}\n"
        if len(message) + len(part) > max_length:
            post_telegram(message)
            message = header + part
        else:
            message += part
    if message.strip() != header.strip():
        post_telegram(message)

def post_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("❌ Telegram credentials missing (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID).")
        return
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    try:
        resp = requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json=payload)
        if resp.status_code == 200:
            print("✔️ Telegram alert sent.")
        else:
            print(f"❌ Telegram error ({resp.status_code})")
    except Exception as e:
        print(f"❌ Telegram exception: {e}")

def send_email_batch_alert(entries):
    if not EMAIL_USER or not EMAIL_PASS or not EMAIL_TO:
        print("❌ Email credentials missing (EMAIL_USER / EMAIL_PASS / EMAIL_TO).")
        return
    body = "\n".join([f"{e['ip']} - {e['city']}, {e['country']}" for e in entries])
    msg = MIMEText(f"Honeypot Alert:\n\n{body}")
    msg["Subject"] = "Cowrie Batch Alert"
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_TO
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print("✔️ Email alert sent.")
    except Exception as e:
        print(f"❌ Email error: {e}")

def process_logs():
    init_db()
    new_alerts = []
    seen_ips = set()

    if not os.path.exists(LOG_FILE):
        print("Log file not found.")
        return

    start_position = load_last_position()
    file_size = os.path.getsize(LOG_FILE)
    if start_position > file_size:
        start_position = 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_position)
        lines = f.readlines()
        save_last_position(f.tell())

    with geoip2.database.Reader(GEO_DB_PATH) as reader:
        for line in lines:
            if "New connection" not in line:
                continue
            match = re.search(r"New connection: (\d+\.\d+\.\d+\.\d+)", line)
            if not match:
                continue
            ip = match.group(1)
            if ip in alerted_ips or ip in seen_ips:
                continue
            seen_ips.add(ip)
            city, country, lat, lon = resolve_geo(ip, reader)
            if lat is None or lon is None:
                continue
            event_timestamp = datetime.now(timezone.utc).isoformat()
            username = "Unknown"
            password = "Unknown"
            timestamp_ns = str(int(time.time() * 1e9))
            structured_log = json.dumps({
                "ip": ip,
                "city": city,
                "country": country,
                "lat": lat,
                "lon": lon,
                "timestamp": event_timestamp
            })
            payload = {
                "streams": [
                    {
                        "stream": {"job": "cowrie_enriched"},
                        "values": [[timestamp_ns, structured_log]]
                    }
                ]
            }
            requests.post(LOKI_URL, json=payload)
            new_alerts.append({
                "ip": ip, "city": city, "country": country,
                "lat": lat, "lon": lon,
                "username": username,
                "password": password,
                "timestamp": event_timestamp
            })
            insert_alert(ip, country, city, username, password, event_timestamp, lat, lon)
            with open(LOG_ALERT_FILE, "a", encoding="utf-8") as logf:
                logf.write(f"{ip},{city},{country},{event_timestamp}\n")

    if new_alerts:
        send_telegram_batch_alert(new_alerts)
        send_email_batch_alert(new_alerts)

if __name__ == "__main__":
    process_logs()

