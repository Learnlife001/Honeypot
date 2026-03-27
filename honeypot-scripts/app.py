from flask import Flask, render_template, send_from_directory
import json
import os

app = Flask(__name__)

@app.route("/")
def dashboard():
    alerts = []
    if os.path.exists("cowrie_alerts.json"):
        with open("cowrie_alerts.json") as f:
            alerts = json.load(f)
    return render_template("index.html", alerts=alerts)

@app.route("/map")
def map():
    return send_from_directory("static", "attack_map.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

