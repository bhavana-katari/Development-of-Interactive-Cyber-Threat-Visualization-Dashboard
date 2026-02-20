from app import get_combined_history
import json

print("=== DEBUG: Testing data from get_combined_history ===\n")

data = get_combined_history(5)
print(f"Total records: {len(data)}\n")

if data:
    print("First record structure:")
    for key, val in data[0].items():
        print(f"  {key}: {val}")
    
    print("\n\nAll 5 records (JSON format):")
    print(json.dumps(data[:5], indent=2, default=str))
else:
    print("NO DATA RETURNED!")
