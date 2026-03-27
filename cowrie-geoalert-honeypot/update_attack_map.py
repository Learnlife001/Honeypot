import pandas as pd
import folium
import subprocess

# Function to geolocate an IP using mmdblookup with better error handling
def geolocate_ip(ip):
    try:
        # Run mmdblookup commands to get geolocation data
        country_cmd = f"mmdblookup -f /var/lib/GeoIP/GeoLite2-City.mmdb --ip {ip} country names en | sed 's/ <utf8_string>//'"
        country = subprocess.check_output(country_cmd, shell=True, text=True).strip()
        if not country:
            country = "Unknown"
    except subprocess.CalledProcessError as e:
        print(f"Error looking up country for IP {ip}: {e}")
        country = "Unknown"

    try:
        city_cmd = f"mmdblookup -f /var/lib/GeoIP/GeoLite2-City.mmdb --ip {ip} city names en | sed 's/ <utf8_string>//'"
        city = subprocess.check_output(city_cmd, shell=True, text=True).strip()
        if not city:
            city = "Unknown"
    except subprocess.CalledProcessError as e:
        print(f"Error looking up city for IP {ip}: {e}")
        city = "Unknown"

    try:
        lat_cmd = f"mmdblookup -f /var/lib/GeoIP/GeoLite2-City.mmdb --ip {ip} location latitude | sed 's/ <double>//'"
        latitude = float(subprocess.check_output(lat_cmd, shell=True, text=True).strip())
    except (subprocess.CalledProcessError, ValueError) as e:
        print(f"Error looking up latitude for IP {ip}: {e}")
        latitude = 0.0

    try:
        lon_cmd = f"mmdblookup -f /var/lib/GeoIP/GeoLite2-City.mmdb --ip {ip} location longitude | sed 's/ <double>//'"
        longitude = float(subprocess.check_output(lon_cmd, shell=True, text=True).strip())
    except (subprocess.CalledProcessError, ValueError) as e:
        print(f"Error looking up longitude for IP {ip}: {e}")
        longitude = 0.0

    return country, city, latitude, longitude

# Step 1: Read the existing attack_ips_geo.csv (if it exists)
try:
    existing_df = pd.read_csv('attack_ips_geo.csv')
except FileNotFoundError:
    # Create an empty DataFrame with the correct columns if the file doesn't exist
    existing_df = pd.DataFrame(columns=['source_ip', 'country', 'city', 'latitude', 'longitude'])

# Step 2: Read the new IP data from Grafana export (new_ips.csv)
grafana_df = pd.read_csv('new_ips.csv')

# Extract unique IPs from the Grafana data
unique_ips = grafana_df['source_ip'].dropna().unique()

# Create a DataFrame for the new IPs
new_data = []
for ip in unique_ips:
    print(f"Geolocating IP: {ip}")
    country, city, latitude, longitude = geolocate_ip(ip)
    new_data.append({
        'source_ip': ip,
        'country': country,
        'city': city,
        'latitude': latitude,
        'longitude': longitude
    })
new_df = pd.DataFrame(new_data)

# Step 3: Merge the new data with the existing data, avoiding duplicates
combined_df = pd.concat([existing_df, new_df], ignore_index=True)
combined_df = combined_df.drop_duplicates(subset=['source_ip'], keep='last')

# Step 4: Save the updated CSV
combined_df.to_csv('attack_ips_geo.csv', index=False)

# Step 5: Regenerate the map
center_lat = combined_df['latitude'].mean()
center_lon = combined_df['longitude'].mean()
attack_map = folium.Map(location=[center_lat, center_lon], zoom_start=2)

for index, row in combined_df.iterrows():
    popup_text = f"IP: {row['source_ip']}<br>Country: {row['country']}<br>City: {row['city']}"
    folium.Marker(
        location=[row['latitude'], row['longitude']],
        popup=popup_text,
        tooltip=row['source_ip']
    ).add_to(attack_map)

attack_map.save('attack_map.html')
print("Updated map has been saved as 'attack_map.html'. Open it in a browser to view!")
