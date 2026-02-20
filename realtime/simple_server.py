# cyber-threat-dashboard/realtime/simple_server.py
import asyncio
import websockets
import json
import random
from datetime import datetime
import time

# Sample data
COUNTRIES = [
    ("United States", 37.0902, -95.7129),
    ("Russia", 61.5240, 105.3188),
    ("China", 35.8617, 104.1954),
    ("Germany", 51.1657, 10.4515),
    ("India", 20.5937, 78.9629),
    ("France", 46.6034, 1.8883),
    ("UK", 55.3781, -3.4360),
    ("Brazil", -14.2350, -51.9253),
    ("Japan", 36.2048, 138.2529),
    ("Australia", -25.2744, 133.7751),
]

THREAT_TYPES = [
    "Botnet", "Ransomware", "Phishing", "DDoS", "Malware",
    "SQL Injection", "XSS", "Zero-Day", "Rootkit"
]

async def send_realtime_data(websocket, path):
    """Send real-time data to connected clients"""
    print("✅ Client connected to WebSocket")
    
    try:
        while True:
            # Generate random threat
            country, lat, lon = random.choice(COUNTRIES)
            threat_type = random.choice(THREAT_TYPES)
            
            # Create threat data
            threat = {
                "id": random.randint(1000, 9999),
                "country": country,
                "lat": lat,
                "lon": lon,
                "threat_type": threat_type,
                "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                "ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "duration": f"{random.randint(1, 120)}m"
            }
            
            # Send to client
            await websocket.send(json.dumps(threat))
            print(f"📡 Sent threat: {threat_type} from {country}")
            
            # Wait 3-7 seconds before next threat
            await asyncio.sleep(random.uniform(3, 7))
            
    except websockets.exceptions.ConnectionClosed:
        print("❌ Client disconnected")

# Start WebSocket server
start_server = websockets.serve(send_realtime_data, "localhost", 8765)

print("🚀 Starting SIMPLE WebSocket Server on port 8765")
print("📡 WebSocket URL: ws://localhost:8765")
print("Press Ctrl+C to stop")

# Run the server
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()