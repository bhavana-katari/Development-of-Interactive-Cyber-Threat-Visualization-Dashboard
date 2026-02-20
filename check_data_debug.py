import sys
from app import get_combined_history, analytics_processor
from datetime import datetime
import json

print("--- Testing get_combined_history() ---")
data = get_combined_history(limit=5)
print(f"Total records found: {len(data)}")
for i, rec in enumerate(data):
    print(f"Record #{i+1}: {json.dumps(rec)}")

print("\n--- Testing individual_threats deque ---")
with analytics_processor.data_lock:
    raw = list(analytics_processor.individual_threats)
print(f"Items in individual_threats: {len(raw)}")
if raw:
    print(f"Last raw item keys: {raw[-1].keys()}")
    print(f"Last raw item: {json.dumps(raw[-1])}")
