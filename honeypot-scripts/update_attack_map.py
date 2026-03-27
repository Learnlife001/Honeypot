import os
import sqlite3

import folium
from folium.plugins import HeatMap, MarkerCluster

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "honeypot-web", "alerts.db"))
MAP_FILE = os.path.join(SCRIPT_DIR, "attack_map.html")


def main():
    if not os.path.exists(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT ip, country, city, latitude, longitude, timestamp
        FROM alerts
        WHERE latitude IS NOT NULL
        AND longitude IS NOT NULL
        """
    ).fetchall()
    conn.close()

    if not rows:
        print("No alerts with coordinates in database; writing empty world map.")
        center_lat, center_lon = 20.0, 0.0
    else:
        lats = [float(r["latitude"]) for r in rows]
        lons = [float(r["longitude"]) for r in rows]
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)

    attack_map = folium.Map(location=[center_lat, center_lon], zoom_start=2)
    marker_cluster = MarkerCluster(name="Attack Markers").add_to(attack_map)
    heat_data = []

    for row in rows:
        lat = float(row["latitude"])
        lon = float(row["longitude"])
        ip = row["ip"] or "Unknown"
        country = row["country"] or "Unknown"
        city = row["city"] or "Unknown"
        ts = row["timestamp"] or "Unknown"
        popup_text = (
            f"IP: {ip}<br>"
            f"Country: {country}<br>"
            f"City: {city}<br>"
            f"Timestamp: {ts}"
        )
        folium.Marker(
            location=[lat, lon],
            popup=popup_text,
            tooltip=str(ip),
            icon=folium.Icon(color="red", icon="info-sign"),
        ).add_to(marker_cluster)
        heat_data.append([lat, lon])

    if heat_data:
        HeatMap(heat_data, name="Attack Density", radius=10, blur=14).add_to(attack_map)
    folium.LayerControl(collapsed=False).add_to(attack_map)

    attack_map.save(MAP_FILE)
    print(f"Updated map saved as {MAP_FILE}")


if __name__ == "__main__":
    main()
