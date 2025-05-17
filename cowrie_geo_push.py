import os
import re
import time
import json
import requests
from datetime import datetime, timedelta, timezone
import geoip2.database
import smtplib
from email.mime.text import MIMEText

***REMOVED*** Config
LOKI_URL = "http://localhost:3100/loki/api/v1/push"
LOG_FILE = "/home/azureuser/cowrie/var/log/cowrie/cowrie.log"
GEO_DB_PATH = "/var/lib/GeoIP/GeoLite2-City.mmdb"
BOT_TOKEN = "***REMOVED***"
CHAT_ID = "***REMOVED***"
LOG_ALERT_FILE = "/home/azureuser/telegram_alert_log.txt"

EMAIL_USER = "***REMOVED***"
EMAIL_PASS = "zdtcxnwjditfufwb"
EMAIL_TO = "ilearnlife23@gmail.com"

alerted_ips = set()

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
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "Markdown"
    }
    try:
        resp = requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json=payload)
        if resp.status_code == 200:
            print("✔️ Telegram alert sent.")
        else:
            print(f"❌ Telegram error ({resp.status_code})")
    except Exception as e:
        print(f"❌ Telegram exception: {e}")

def send_email_batch_alert(entries):
    body = "\n".join([f"{e['ip']} - {e['city']}, {e['country']}" for e in entries])
    msg = MIMEText(f"Honeypot Alert:\n\n{body}")
    msg["Subject"] = "Cowrie Batch Alert"
    msg["From"] = EMAIL_USER
    msg["To"] = EMAIL_TO
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        print("✔️ Email alert sent.")
    except Exception as e:
        print(f"❌ Email error: {e}")

def process_logs():
    new_alerts = []
    seen_ips = set()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=20)

    if not os.path.exists(LOG_FILE):
        print("Log file not found.")
        return

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    reader = geoip2.database.Reader(GEO_DB_PATH)

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
        timestamp_ns = str(int(time.time() * 1e9))
        structured_log = json.dumps({
            "ip": ip,
            "city": city,
            "country": country,
            "lat": lat,
            "lon": lon,
            "timestamp": datetime.now(timezone.utc).isoformat()
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
            "lat": lat, "lon": lon
        })
        with open(LOG_ALERT_FILE, "a") as logf:
            logf.write(f"{ip},{city},{country},{datetime.now(timezone.utc).isoformat()}\n")

    if new_alerts:
        send_telegram_batch_alert(new_alerts)
        send_email_batch_alert(new_alerts)

if __name__ == "__main__":
    process_logs()

