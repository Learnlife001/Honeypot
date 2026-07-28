import pandas as pd
import folium

# Step 1: Read the CSV file into a DataFrame.
df = pd.read_csv('attack_ips_geo.csv')

# Step 2: Create a map centered on the average latitude and longitude.
# This gives a balanced starting point for viewing all points.
center_lat = df['latitude'].mean()
center_lon = df['longitude'].mean()
attack_map = folium.Map(location=[center_lat, center_lon], zoom_start=2)

# Step 3: Add markers for each IP location.
for index, row in df.iterrows():
    # Create the popup text with IP, country, and city.
    popup_text = f"IP: {row['source_ip']}<br>Country: {row['country']}<br>City: {row['city']}"
    # Add a marker to the map.
    folium.Marker(
        location=[row['latitude'], row['longitude']],
        popup=popup_text,
        tooltip=row['source_ip']
    ).add_to(attack_map)

# Step 4: Save the map to an HTML file.
attack_map.save('attack_map.html')
print("Map has been saved as 'attack_map.html'. Open it in a browser to view!")
