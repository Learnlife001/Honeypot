#!/usr/bin/env python3
"""
Cron-safe: GET /report/daily from a running Flask instance and save JSON locally.
Server response also triggers write_daily_report_file on the server; this copy is for backups.

Usage:
  REPORT_URL=http://127.0.0.1:5000/report/daily python generate_reports.py
"""

import json
import os
import sys
import urllib.error
import urllib.request


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(base_dir, "reports", "daily_report.json")
    url = os.environ.get("REPORT_URL", "http://127.0.0.1:5000/report/daily")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.load(resp)
    except urllib.error.URLError as exc:
        print(f"Failed to fetch report: {exc}", file=sys.stderr)
        sys.exit(1)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
