import csv
import geoip2.database
import pandas as pd

***REMOVED*** Path to input and output CSV
input_csv = "kepler_ip_only.csv"
output_csv = "kepler_ready.csv"
geoip_db = "/usr/share/GeoIP/GeoLite2-City.mmdb"

***REMOVED*** Load the IP-only data
df = pd.read_csv(input_csv)

***REMOVED*** Open the GeoIP database
reader = geoip2.database.Reader(geoip_db)

***REMOVED*** Create output file and write header
with open(output_csv, "w", newline="") as out:
    writer = csv.writer(out)
    writer.writerow(["ip", "timestamp", "latitude", "longitude"])

    for _, row in df.iterrows():
        ip = row["ip"]
        ts = row["timestamp"]
        try:
            res = reader.city(ip)
            lat = res.location.latitude
            lon = res.location.longitude
            if lat is not None and lon is not None:
                writer.writerow([ip, ts, lat, lon])
        except Exception as e:
            continue

