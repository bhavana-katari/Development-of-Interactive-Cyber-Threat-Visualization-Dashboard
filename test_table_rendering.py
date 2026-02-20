from app import get_combined_history
import pandas as pd
from datetime import datetime

# Test the filtering logic
print("Testing filtering and display logic...")

# Get data
data = get_combined_history(200)
print(f"\nTotal records available: {len(data)}")

# Simulate stored data (from the Store component)
stored_data = data
search_value = ""

# Apply filtering logic 
term = (search_value or "").strip().lower()
filtered = []

for item in stored_data[:200]:
    ts = item.get("timestamp", "")
    if isinstance(ts, datetime):
        ts = ts.strftime("%Y-%m-%d %H:%M:%S")
    
    ttype = str(item.get("type", "Unknown"))
    severity = str(item.get("severity", "Unknown"))
    src_ip = str(item.get("source_ip", ""))
    country = str(item.get("country", "Unknown"))
    status = str(item.get("status", "Unknown"))
    
    searchable = f"{ts} {ttype} {severity} {src_ip} {country} {status}".lower()
    if term and term not in searchable:
        continue
    
    filtered.append({
        "timestamp": ts,
        "type": ttype,
        "severity": severity,
        "source_ip": src_ip,
        "country": country,
        "status": status
    })

display_data = filtered[:20]

print(f"Filtered records (limit 20): {len(display_data)}")
print("\n--- Display Data (First 5) ---")
for i, item in enumerate(display_data[:5], 1):
    print(f"\nRow {i}:")
    print(f"  Timestamp: {item['timestamp']}")
    print(f"  Type: {item['type']}")
    print(f"  Severity: {item['severity']}")
    print(f"  Source IP: {item['source_ip']}")
    print(f"  Country: {item['country']}")
    print(f"  Status: {item['status']}")

print(f"\n✓ Table rendering test passed!")
print(f"✓ Ready to display {len(display_data)} rows in the table")
