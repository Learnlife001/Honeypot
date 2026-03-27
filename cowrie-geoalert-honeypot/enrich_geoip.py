import csv
import geoip2.database

# Path to your downloaded file from Grafana
INPUT_CSV = "cowrie_ip_logs.csv"
OUTPUT_CSV = "kepler_ready.csv"
GEO_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"  # adjust if yours is different

reader = geoip2.database.Reader(GEO_DB)

with open(INPUT_CSV, "r") as infile, open(OUTPUT_CSV, "w", newline='') as outfile:
    csv_reader = csv.reader(infile)
    csv_writer = csv.writer(outfile)
    csv_writer.writerow(["ip", "timestamp", "latitude", "longitude"])

    for row in csv_reader:
        try:
            ip = row[0].strip().split(",")[0]
            timestamp = row[0].strip().split(",")[1] if "," in row[0] else ""
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            csv_writer.writerow([ip, timestamp, lat, lon])
        except:
            continue

import csv
import geoip2.database

# Path to your downloaded file from Grafana
INPUT_CSV = "cowrie_ip_logs.csv"
OUTPUT_CSV = "kepler_ready.csv"
GEO_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"  # adjust if yours is different

reader = geoip2.database.Reader(GEO_DB)

with open(INPUT_CSV, "r") as infile, open(OUTPUT_CSV, "w", newline='') as outfile:
    csv_reader = csv.reader(infile)
    csv_writer = csv.writer(outfile)
    csv_writer.writerow(["ip", "timestamp", "latitude", "longitude"])

    for row in csv_reader:
        try:
            ip = row[0].strip().split(",")[0]
            timestamp = row[0].strip().split(",")[1] if "," in row[0] else ""
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            csv_writer.writerow([ip, timestamp, lat, lon])
        except:
            continue
