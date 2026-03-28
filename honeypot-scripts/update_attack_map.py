import json
import os
import sqlite3
from collections import defaultdict

import folium

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "honeypot-web", "alerts.db"))
MAP_FILE = os.path.join(SCRIPT_DIR, "attack_map.html")

MAX_MARKERS_PER_FRAME = 300
MAX_HEAT_POINTS_PER_FRAME = 8000


def _build_replay_injection(markers_by_hour: dict, heat_by_hour: dict) -> str:
    markers_json = json.dumps(markers_by_hour, ensure_ascii=False)
    heat_json = json.dumps(heat_by_hour, ensure_ascii=False)

    return f"""
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css"/>
<link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css"/>
<script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>
<script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
<script>
(function () {{
  window.HONEYPOT_MARKERS_BY_HOUR = {markers_json};
  window.HONEYPOT_HEAT_BY_HOUR = {heat_json};
  window.HONEYPOT_REPLAY_MAX_MARKERS = {MAX_MARKERS_PER_FRAME};

  var replayCluster = null;
  var heatLayer = null;
  var mapInstance = null;
  var fadeOutTimer = null;
  var heatTransitionRaf = null;
  var lastHeatLatLngs = [];

  function getMap() {{
    var el = document.querySelector(".folium-map");
    if (!el || !window[el.id]) return null;
    return window[el.id];
  }}

  function mergeAllMarkers() {{
    var out = [];
    var by = window.HONEYPOT_MARKERS_BY_HOUR || {{}};
    Object.keys(by).forEach(function (k) {{
      (by[k] || []).forEach(function (m) {{ out.push(m); }});
    }});
    return out;
  }}

  function mergeAllHeat() {{
    var out = [];
    var bh = window.HONEYPOT_HEAT_BY_HOUR || {{}};
    Object.keys(bh).forEach(function (k) {{
      (bh[k] || []).forEach(function (p) {{ out.push(p); }});
    }});
    return out;
  }}

  function fadeOutThen(cluster, done) {{
    if (fadeOutTimer) {{
      clearInterval(fadeOutTimer);
      fadeOutTimer = null;
    }}
    var layers = cluster.getLayers();
    if (!layers.length) {{
      done();
      return;
    }}
    var step = 0;
    fadeOutTimer = setInterval(function () {{
      step += 0.12;
      layers.forEach(function (m) {{
        try {{ m.setOpacity(Math.max(0, 1 - step)); }} catch (e) {{}}
      }});
      if (step >= 1) {{
        clearInterval(fadeOutTimer);
        fadeOutTimer = null;
        cluster.clearLayers();
        done();
      }}
    }}, 35);
  }}

  function cancelHeatTransition() {{
    if (heatTransitionRaf) {{
      cancelAnimationFrame(heatTransitionRaf);
      heatTransitionRaf = null;
    }}
  }}

  function applyHeatOpacity(o) {{
    o = Math.max(0, Math.min(1, o));
    try {{
      if (heatLayer && typeof heatLayer.setOptions === "function") {{
        heatLayer.setOptions({{ opacity: o }});
      }}
    }} catch (e1) {{}}
    try {{
      if (heatLayer && heatLayer._canvas && heatLayer._canvas.style) {{
        heatLayer._canvas.style.opacity = String(o);
      }} else if (heatLayer && typeof heatLayer.getElement === "function") {{
        var el = heatLayer.getElement();
        if (el && el.style) el.style.opacity = String(o);
      }}
    }} catch (e2) {{}}
  }}

  function runHeatTransition(nextPts, markersToFadeIn) {{
    cancelHeatTransition();
    if (!markersToFadeIn) markersToFadeIn = [];
    var half = 150;
    var t0 = performance.now();
    function fadeOutStep(ts) {{
      var p = Math.min(1, (ts - t0) / half);
      applyHeatOpacity(1 - p);
      if (p < 1) {{
        heatTransitionRaf = requestAnimationFrame(fadeOutStep);
      }} else {{
        heatLayer.setLatLngs(nextPts);
        lastHeatLatLngs = nextPts.slice();
        applyHeatOpacity(0);
        t0 = performance.now();
        function fadeInStep(ts2) {{
          var q = Math.min(1, (ts2 - t0) / half);
          applyHeatOpacity(q);
          markersToFadeIn.forEach(function (m) {{
            try {{ m.setOpacity(q); }} catch (e) {{}}
          }});
          if (q < 1) {{
            heatTransitionRaf = requestAnimationFrame(fadeInStep);
          }} else {{
            heatTransitionRaf = null;
            applyHeatOpacity(1);
            markersToFadeIn.forEach(function (m) {{
              try {{ m.setOpacity(1); }} catch (e) {{}}
            }});
          }}
        }}
        heatTransitionRaf = requestAnimationFrame(fadeInStep);
      }}
    }}
    heatTransitionRaf = requestAnimationFrame(fadeOutStep);
  }}

  function renderMapHour(hourKey) {{
    if (!window.HONEYPOT_MARKERS_BY_HOUR || !mapInstance || !replayCluster || !heatLayer) return;

    cancelHeatTransition();
    applyHeatOpacity(1);

    var list = [];
    var heatPts = [];
    var showAll = !hourKey;

    if (showAll) {{
      list = mergeAllMarkers();
      heatPts = mergeAllHeat();
    }} else {{
      list = (window.HONEYPOT_MARKERS_BY_HOUR[hourKey] || []).slice();
      heatPts = (window.HONEYPOT_HEAT_BY_HOUR[hourKey] || []).slice();
    }}

    if (list.length > window.HONEYPOT_REPLAY_MAX_MARKERS) {{
      list = list.slice(0, window.HONEYPOT_REPLAY_MAX_MARKERS);
    }}
    if (heatPts.length > {MAX_HEAT_POINTS_PER_FRAME}) {{
      heatPts = heatPts.slice(0, {MAX_HEAT_POINTS_PER_FRAME});
    }}

    fadeOutThen(replayCluster, function () {{
      var markersToFadeIn = [];
      list.forEach(function (pt) {{
        var marker = L.marker([pt.lat, pt.lon], {{ opacity: 0 }});
        if (pt.popup) marker.bindPopup(pt.popup);
        replayCluster.addLayer(marker);
        markersToFadeIn.push(marker);
      }});
      try {{ replayCluster.refreshClusters(); }} catch (e) {{}}
      runHeatTransition(heatPts, markersToFadeIn);
    }});
  }}

  window.honeypotRenderMapHour = renderMapHour;

  function initReplayLayers() {{
    mapInstance = getMap();
    if (!mapInstance) return;

    replayCluster = L.markerClusterGroup({{ showCoverageOnHover: false, maxClusterRadius: 50 }});
    replayCluster.addTo(mapInstance);

    heatLayer = L.heatLayer([], {{ radius: 10, blur: 14, maxZoom: 17, opacity: 1 }});
    heatLayer.addTo(mapInstance);
    lastHeatLatLngs = [];

    renderMapHour(null);

    window.addEventListener("message", function (ev) {{
      if (!ev.data || ev.data.type !== "honeypot-replay-hour") return;
      var key = ev.data.hourKey;
      if (!key) {{
        renderMapHour(null);
      }} else {{
        renderMapHour(key);
      }}
    }});
  }}

  if (document.readyState === "loading") {{
    document.addEventListener("DOMContentLoaded", initReplayLayers);
  }} else {{
    initReplayLayers();
  }}
}})();
</script>
"""


def main():
    if not os.path.exists(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT ip, country, city, latitude, longitude, timestamp,
               strftime('%Y-%m-%d %H', timestamp) AS hour_key
        FROM alerts
        WHERE latitude IS NOT NULL
        AND longitude IS NOT NULL
        """
    ).fetchall()
    conn.close()

    markers_by_hour: dict = defaultdict(list)
    heat_by_hour: dict = defaultdict(list)

    for row in rows:
        hk = row["hour_key"]
        if not hk:
            continue
        lat = float(row["latitude"])
        lon = float(row["longitude"])
        ip = row["ip"] or "Unknown"
        country = row["country"] or "Unknown"
        city = row["city"] or "Unknown"
        ts = row["timestamp"] or "Unknown"
        popup = (
            f"IP: {ip}<br>"
            f"Country: {country}<br>"
            f"City: {city}<br>"
            f"Timestamp: {ts}"
        )
        markers_by_hour[hk].append({"lat": lat, "lon": lon, "popup": popup})
        heat_by_hour[hk].append([lat, lon])

    markers_by_hour = dict(markers_by_hour)
    heat_by_hour = dict(heat_by_hour)

    if not rows:
        print("No alerts with coordinates in database; writing empty world map.")
        center_lat, center_lon = 20.0, 0.0
    else:
        lats = [float(r["latitude"]) for r in rows]
        lons = [float(r["longitude"]) for r in rows]
        center_lat = sum(lats) / len(lats)
        center_lon = sum(lons) / len(lons)

    attack_map = folium.Map(location=[center_lat, center_lon], zoom_start=2)
    attack_map.save(MAP_FILE)

    injection = _build_replay_injection(markers_by_hour, heat_by_hour)
    with open(MAP_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    if "</html>" in content:
        content = content.replace("</html>", injection + "\n</html>", 1)
    else:
        content = content + injection
    with open(MAP_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Updated map saved as {MAP_FILE}")


if __name__ == "__main__":
    main()
