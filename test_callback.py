"""Test the render_threat_history_table callback function directly"""
from app import render_threat_history_table, get_combined_history
from datetime import datetime

print("=" * 80)
print("TESTING: render_threat_history_table callback")
print("=" * 80)

# Test 1: No search term
print("\n\n[TEST 1] Rendering table with NO search filter (n_intervals=0, search_value=None)")
try:
    result = render_threat_history_table(n_intervals=0, search_value=None)
    if result:
        print(f"✓ Callback returned content")
        print(f"  Result type: {type(result)}")
        if hasattr(result, 'children'):
            print(f"  Children count: {len(result.children) if hasattr(result.children, '__len__') else 'N/A'}")
    else:
        print(f"✗ Callback returned None or empty!")
except Exception as e:
    print(f"✗ ERROR: {e}")
    import traceback
    traceback.print_exc()

# Test 2: With search term
print("\n\n[TEST 2] Rendering table WITH search filter (search_value='Malware')")
try:
    result = render_threat_history_table(n_intervals=0, search_value="Malware")
    if result:
        print(f"✓ Callback returned content for 'Malware' search")
        print(f"  Result type: {type(result)}")
    else:
        print(f"✗ Callback returned None!")
except Exception as e:
    print(f"✗ ERROR: {e}")

# Test 3: Verify data source
print("\n\n[TEST 3] Verifying get_combined_history data source")
data = get_combined_history(limit=20)
print(f"✓ Data fetched: {len(data)} records")
if data:
    sample = data[0]
    print(f"  Sample record fields: {list(sample.keys())}")
    print(f"  Sample data: {sample}")

print("\n\n" + "=" * 80)
print("CALLBACK TEST COMPLETE")
print("=" * 80)
