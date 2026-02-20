import traceback
try:
    from app import get_combined_history, analytics_processor, global_data
    print("Import successful")
    
    with analytics_processor.data_lock:
        print(f"analytical_processor.individual_threats size: {len(analytics_processor.individual_threats)}")
    
    print(f"global_data['live_threats'] size: {len(global_data.get('live_threats', []))}")
    
    data = get_combined_history(limit=5)
    print(f"get_combined_history found {len(data)} items")
    if data:
        print(f"First item: {data[0]}")
except Exception as e:
    print("Caught Exception:")
    traceback.print_exc()
