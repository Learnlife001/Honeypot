import re
import csv
from datetime import datetime
import geoip2.database
import os
from dotenv import load_dotenv

load_dotenv()

log_file = os.getenv("COWRIE_LOG_FILE", "/home/azureuser/cowrie/var/log/cowrie/cowrie.log")
output_file = os.getenv("KEPLER_OUTPUT_CSV", "kepler_ready.csv")
geoip_db = os.getenv("GEOIP_DB_PATH", "/usr/share/GeoIP/GeoLite2-City.mmdb")

reader = geoip2.database.Reader(geoip_db)

seen_ips = set()

with open(log_file, "r") as f, open(output_file, "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["ip", "timestamp", "latitude", "longitude"])
    
    for line in f:
        match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z).*?(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            timestamp, ip = match.groups()
            if ip in seen_ips:
                continue
            try:
                geo = reader.city(ip)
                lat = geo.location.latitude
                lon = geo.location.longitude
                writer.writerow([ip, timestamp, lat, lon])
                seen_ips.add(ip)
            except:
                continue
