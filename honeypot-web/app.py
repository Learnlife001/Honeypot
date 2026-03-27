from flask import Flask, render_template, send_from_directory
import json
import os

app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = []

    alerts_path = "/home/azureuser/cowrie-geoalert-honeypot/honeypot-web/cowrie_alerts.json"

    if os.path.exists(alerts_path):
        with open(alerts_path) as f:
            alerts = json.load(f)

    return render_template("index.html", alerts=alerts)


@app.route("/map")
def map_view():
    return send_from_directory(
        "/home/azureuser/cowrie-geoalert-honeypot/honeypot-scripts",
        "attack_map.html"
    )


if __name__ == "__main__":
    print("Flask app running at http://<your_vm_ip>:5000/")
    app.run(host="0.0.0.0", port=5000)