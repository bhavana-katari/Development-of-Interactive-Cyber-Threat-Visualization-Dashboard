from app import get_combined_history

print("Testing data generation...")
data = get_combined_history(20)
print(f"\nTotal records: {len(data)}")

if data:
    print("\n--- First 5 records ---")
    for i, d in enumerate(data[:5], 1):
        print(f"\nRow {i}:")
        print(f"  Type: {d.get('type', 'N/A')}")
        print(f"  Severity: {d.get('severity', 'N/A')}")
        print(f"  Source IP: {d.get('source_ip', 'N/A')}")
        print(f"  Country: {d.get('country', 'N/A')}")
        print(f"  Status: {d.get('status', 'N/A')}")
        print(f"  Timestamp: {d.get('timestamp', 'N/A')}")
else:
    print("NO DATA RETURNED!")
