import pandas as pd
import folium

INPUT_FILE = "new_ips.csv"
OUTPUT_FILE = "attack_ips_geo.csv"
MAP_FILE = "attack_map.html"


def main():
    try:
        df = pd.read_csv(INPUT_FILE)
    except FileNotFoundError:
        print("new_ips.csv not found")
        return

    if df.empty:
        print("new_ips.csv is empty")
        return

    required_columns = ["ip", "latitude", "longitude"]

    for col in required_columns:
        if col not in df.columns:
            print(f"Missing required column: {col}")
            return

    df = df.dropna(subset=["latitude", "longitude"])

    if df.empty:
        print("No valid coordinate data available")
        return

    df.to_csv(OUTPUT_FILE, index=False)

    center_lat = df["latitude"].mean()
    center_lon = df["longitude"].mean()

    attack_map = folium.Map(
        location=[center_lat, center_lon],
        zoom_start=2
    )

    for _, row in df.iterrows():
        popup_text = f"IP: {row['ip']}"

        folium.CircleMarker(
            location=[row["latitude"], row["longitude"]],
            radius=4,
            popup=popup_text,
            color="red",
            fill=True,
            fill_opacity=0.7
        ).add_to(attack_map)

    attack_map.save(MAP_FILE)

    print("Updated map saved as attack_map.html")


if __name__ == "__main__":
    main()