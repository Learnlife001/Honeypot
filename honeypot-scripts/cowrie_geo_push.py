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
# Feature 1: GeoLite2 ASN DB path (optional; enrichment skipped if missing)
GEO_ASN_PATH = os.getenv("GEO_ASN_PATH", "/usr/share/GeoIP/GeoLite2-ASN.mmdb")
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
        "ALTER TABLE alerts ADD COLUMN asn TEXT",
        "ALTER TABLE alerts ADD COLUMN org TEXT",
        "ALTER TABLE alerts ADD COLUMN severity TEXT",
        "ALTER TABLE alerts ADD COLUMN client_version TEXT",
        "ALTER TABLE alerts ADD COLUMN hassh TEXT",
    ):
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Indexes: speed ip + time-window lookups (severity, brute-force, aggregations) and time-ordered reads
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


def resolve_asn(ip, asn_reader):
    """Feature 1: ASN + org from GeoLite2-ASN; NULL on failure or missing reader."""
    if asn_reader is None:
        return None, None
    try:
        res = asn_reader.asn(ip)
        num = res.autonomous_system_number
        org = res.autonomous_system_organization
        asn_str = str(num) if num is not None else None
        return asn_str, org
    except Exception:
        return None, None


def ipv4_subnet24_prefix(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3]) + "."


def classify_severity(conn, ip, event_ts, username):
    """
    Feature 2: severity tiers (highest matching wins).
    Order: critical > high > medium > low.
    """
    # critical: multiple distinct IPs in same /24 within 60 seconds
    prefix = ipv4_subnet24_prefix(ip)
    if prefix:
        rows = conn.execute(
            """
            SELECT DISTINCT ip FROM alerts
            WHERE ip LIKE ? AND datetime(timestamp) >= datetime(?, '-60 seconds')
            """,
            (prefix + "%", event_ts),
        ).fetchall()
        existing_ips = {r[0] for r in rows}
        if len(existing_ips) >= 2:
            return "critical"
        if len(existing_ips) == 1 and ip not in existing_ips:
            return "critical"

    # high: credential spraying (3+ distinct non-placeholder usernames / 10 min)
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT username) FROM alerts
        WHERE ip = ? AND datetime(timestamp) >= datetime(?, '-10 minutes')
          AND username IS NOT NULL AND TRIM(username) != ''
          AND username NOT IN ('Unknown')
        """,
        (ip, event_ts),
    ).fetchone()
    spray_existing = row[0] if row else 0
    spray_usernames = spray_existing
    if username and username not in ("Unknown", "") and username.strip():
        row2 = conn.execute(
            """
            SELECT 1 FROM alerts
            WHERE ip = ? AND datetime(timestamp) >= datetime(?, '-10 minutes')
              AND username = ?
            LIMIT 1
            """,
            (ip, event_ts, username),
        ).fetchone()
        if not row2:
            spray_usernames = spray_existing + 1
    if spray_usernames >= 3:
        return "high"

    row = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE ip = ? AND datetime(timestamp) >= datetime(?, '-2 minutes')
        """,
        (ip, event_ts),
    ).fetchone()
    if row and row[0] >= 2:
        return "medium"

    return "low"


def detect_bruteforce(conn, ip, event_ts):
    """Feature 4: same IP, 5+ attempts within 60 seconds (including this event)."""
    row = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE ip = ? AND datetime(timestamp) >= datetime(?, '-60 seconds')
        """,
        (ip, event_ts),
    ).fetchone()
    prior = row[0] if row else 0
    if prior + 1 >= 5:
        print(f"[BRUTEFORCE DETECTED] IP: {ip}")
        send_telegram_alert(ip)


def send_telegram_alert(ip):
    """Feature 4: optional single-IP alert hook (no Telegram dependency)."""
    # Placeholder for future wiring to TELEGRAM_BOT_TOKEN / CHAT_ID
    _ = ip


def collect_bot_fingerprints(lines):
    """
    Feature 5: derive hassh + SSH client banner per IP from sequential Cowrie lines
    following each New connection (best-effort; NULL if not seen in batch).
    """
    meta = {}
    current_ip = None
    for line in lines:
        m = re.search(r"New connection: (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            current_ip = m.group(1)
            continue
        if not current_ip:
            continue
        hm = re.search(r"hassh[=:]\s*([a-fA-F0-9]{32})", line, re.I)
        if hm:
            meta.setdefault(current_ip, {})["hassh"] = hm.group(1)
        vm = re.search(
            r"(?:Remote SSH version|remote version|SSH client version|client version)[:=]\s*(SSH-2\.0[-\w\.]+)",
            line,
            re.I,
        )
        if vm:
            meta.setdefault(current_ip, {})["client_version"] = vm.group(1)
    return meta


def insert_alert(
    ip,
    country,
    city,
    username,
    password,
    timestamp,
    latitude=None,
    longitude=None,
    asn=None,
    org=None,
    severity=None,
    client_version=None,
    hassh=None,
    conn=None,
):
    own = conn is None
    if own:
        conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO alerts (
            ip, country, city, username, password, timestamp,
            latitude, longitude, asn, org, severity, client_version, hassh
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip,
            country,
            city,
            username,
            password,
            timestamp,
            latitude,
            longitude,
            asn,
            org,
            severity,
            client_version,
            hassh,
        ),
    )
    if own:
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
    except Exception:
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

    ip_bot_meta = collect_bot_fingerprints(lines)

    asn_reader = None
    try:
        if os.path.isfile(GEO_ASN_PATH):
            asn_reader = geoip2.database.Reader(GEO_ASN_PATH)

        with geoip2.database.Reader(GEO_DB_PATH) as reader:
            conn = get_db_connection()
            try:
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
                    bot = ip_bot_meta.get(ip, {})
                    client_version = bot.get("client_version")
                    hassh = bot.get("hassh")
                    asn, org = resolve_asn(ip, asn_reader)
                    severity = classify_severity(conn, ip, event_timestamp, username)
                    detect_bruteforce(conn, ip, event_timestamp)

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
                    insert_alert(
                        ip, country, city, username, password, event_timestamp,
                        lat, lon, asn, org, severity, client_version, hassh, conn=conn,
                    )
                    conn.commit()
                    with open(LOG_ALERT_FILE, "a", encoding="utf-8") as logf:
                        logf.write(f"{ip},{city},{country},{event_timestamp}\n")

            finally:
                conn.close()
    finally:
        if asn_reader is not None:
            asn_reader.close()

    if new_alerts:
        send_telegram_batch_alert(new_alerts)
        send_email_batch_alert(new_alerts)


if __name__ == "__main__":
    process_logs()
