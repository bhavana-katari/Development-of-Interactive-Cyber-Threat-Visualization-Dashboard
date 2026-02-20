#!/usr/bin/env python
"""Test script to verify threat history data generation"""

from app import get_combined_history

data = get_combined_history(limit=10)
print(f'✓ Records fetched: {len(data)}')

if data:
    print(f'\n📋 First record:')
    for key, value in data[0].items():
        print(f'  {key}: {value}')
    
    # Check all records
    required_fields = ['id', 'timestamp', 'type', 'severity', 'source_ip', 'country', 'status']
    all_have_fields = all(all(k in r for k in required_fields) for r in data)
    print(f'\n✓ All records have required fields: {all_have_fields}')
    
    # Show summary
    print(f'\n📊 Data Summary:')
    print(f'  Total records: {len(data)}')
    severities = set(r.get('severity') for r in data)
    print(f'  Severity levels: {severities}')
    types = set(r.get('type') for r in data)
    print(f'  Threat types: {types}')
else:
    print('❌ No data returned!')
