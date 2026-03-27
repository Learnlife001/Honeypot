import folium
import json
import os

***REMOVED*** Path to JSON alert data file
json_file = "cowrie_alerts.json"

***REMOVED*** Default map center
map_center = [0, 0]
m = folium.Map(location=map_center, zoom_start=2)

***REMOVED*** Load IP data
if os.path.exists(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)
        for entry in data:
            ip = entry.get("ip")
            country = entry.get("country")
            city = entry.get("city")
            lat = entry.get("lat")
            lon = entry.get("lon")

            if lat and lon:
                folium.Marker(
                    [lat, lon],
                    tooltip=f"{ip} ({country}, {city})",
                    icon=folium.Icon(color="red")
                ).add_to(m)

***REMOVED*** Save map
m.save("attack_map.html")
print("Map generated: attack_map.html")
