"""Test the html.Table implementation"""
from app import render_threat_history_table, get_combined_history

print("="*80)
print("TABLE RENDERING TEST - HTML.TABLE IMPLEMENTATION")
print("="*80)

# Get data
data = get_combined_history(limit=200)
print(f"\n[1] DATA: {len(data)} records available")

for i, rec in enumerate(data[:3], 1):
    print(f"\n  Record {i}:")
    print(f"    Type: {rec.get('type')}")
    print(f"    Severity: {rec.get('severity')}")
    print(f"    Source IP: {rec.get('source_ip')}")
    print(f"    Country: {rec.get('country')}")
    print(f"    Status: {rec.get('status')}")

# Test table rendering
print("\n[2] TABLE RENDERING")
table_result = render_threat_history_table(n_intervals=0, search_value=None)
print(f"    Component type: {type(table_result).__name__}")

# Check content
if hasattr(table_result, 'children'):
    print(f"    Children: {len(table_result.children)}")
    
    for child in table_result.children:
        if 'Table' in str(type(child)):
            print(f"    ✓ HTML Table found")
            if hasattr(child, 'children'):
                rows = child.children
                print(f"    ✓ Rows: {len(rows)} (1 header + {len(rows)-1} data rows)")
                
                # Check first data row (row 1, since row 0 is header)
                if len(rows) > 1:
                    first_data_row = rows[1]
                    if hasattr(first_data_row, 'children'):
                        print(f"    ✓ Cells in first row: {len(first_data_row.children)}")
                        
                        # Print cell contents
                        print(f"\n    FIRST ROW DATA:")
                        cell_labels = ["ID", "Timestamp", "Type", "Severity", "Source IP", "Country", "Status"]
                        for i, cell in enumerate(first_data_row.children):
                            content = cell.children if hasattr(cell, 'children') else 'EMPTY'
                            label = cell_labels[i] if i < len(cell_labels) else "Unknown"
                            print(f"      [{label}]: {content}")

print("\n" + "="*80)
print("✓ TABLE SHOULD NOW SHOW ALL DATA IN ALL COLUMNS")
print("="*80)
