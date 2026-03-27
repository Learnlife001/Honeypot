import os
import pandas as pd
import folium
from folium.plugins import HeatMap, MarkerCluster

INPUT_FILE = "new_ips.csv"
OUTPUT_FILE = "attack_ips_geo.csv"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAP_FILE = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "honeypot-web", "static", "attack_map.html"))


def main():
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print("new_ips.csv not found")
        return

    if df.empty:
        print("new_ips.csv is empty")
        return

    ip_column = "ip" if "ip" in df.columns else "source_ip" if "source_ip" in df.columns else None
    required_columns = [ip_column, "latitude", "longitude"]

    for col in required_columns:
        if col not in df.columns:
            print(f"Missing required column: {col}")
            return

    df = df.dropna(subset=["latitude", "longitude"]).copy()
    df["country"] = df["country"] if "country" in df.columns else "Unknown"
    df["city"] = df["city"] if "city" in df.columns else "Unknown"
    df["timestamp"] = df["timestamp"] if "timestamp" in df.columns else "Unknown"

    if df.empty:
        print("No valid coordinate data available")
        return

    os.makedirs(os.path.dirname(MAP_FILE), exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    center_lat = df["latitude"].mean()
    center_lon = df["longitude"].mean()

    attack_map = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=2
    )

    marker_cluster = MarkerCluster(name="Attack Markers").add_to(attack_map)
    heat_data = []

    for _, row in df.iterrows():
        popup_text = (
            f"IP: {row[ip_column]}<br>"
            f"Country: {row['country']}<br>"
            f"City: {row['city']}<br>"
            f"Timestamp: {row['timestamp']}"
        )

        folium.Marker(
            location=[row["latitude"], row["longitude"]],
            popup=popup_text,
            tooltip=str(row[ip_column]),
            icon=folium.Icon(color="red", icon="info-sign"),
        ).add_to(marker_cluster)
        heat_data.append([row["latitude"], row["longitude"]])

    HeatMap(heat_data, name="Attack Density", radius=10, blur=14).add_to(attack_map)
    folium.LayerControl(collapsed=False).add_to(attack_map)

    attack_map.save(MAP_FILE)

    print(f"Updated map saved as {MAP_FILE}")


if __name__ == "__main__":
    main()