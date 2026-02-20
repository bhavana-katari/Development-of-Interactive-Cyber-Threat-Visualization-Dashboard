import requests
import json

url = "http://127.0.0.1:8050/_dash-update-component"

payload = {
    "output": "active-threats-display.children",
    "outputs": [
        {"id": "active-threats-display", "property": "children"},
        {"id": "blocked-threats-display", "property": "children"},
        {"id": "critical-alerts-display", "property": "children"},
        {"id": "total-scanned-display", "property": "children"},
        {"id": "network-devices-display", "property": "children"},
        {"id": "network-vulnerabilities-display", "property": "children"},
        {"id": "network-ports-display", "property": "children"},
        {"id": "wifi-signal-display", "property": "children"},
        {"id": "connected-devices-display", "property": "children"},
        {"id": "current-bandwidth-display", "property": "children"},
        {"id": "packet-loss-display", "property": "children"},
        {"id": "network-latency-display", "property": "children"},
        {"id": "last-update-display", "property": "children"},
        {"id": "live-threat-feed-display", "property": "children"},
        {"id": "real-network-activity-graph", "property": "figure"}
    ],
    "inputs": [
        {"id": "update-interval", "property": "n_intervals", "value": 1}
    ],
    "changedPropIds": ["update-interval.n_intervals"]
}

try:
    response = requests.post(url, json=payload)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        print("Response received (truncated):", response.text[:200])
    else:
        print("Error:", response.text)
except Exception as e:
    print(f"Connection failed: {e}")
