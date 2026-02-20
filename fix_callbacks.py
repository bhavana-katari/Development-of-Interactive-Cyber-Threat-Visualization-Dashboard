#!/usr/bin/env python3
"""
Fix Threat History - Replace old callback with new working version
"""
import re

app_file = 'app.py'

# Read the file
with open(app_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Define old callback pattern (using regex for flexibility)
old_pattern = r'# Search / Filter Threat History\n@app\.callback\(\n    Output\(\'history-table-body\', \'children\'\),\n    \[Input\(\'history-search-input\', \'value\'\)\],\n    prevent_initial_call=False\n\)\ndef filter_history\(search_value\):.*?return \[html\.Tr\(html\.Td\(f"Error: \{str\(e\)\}", colSpan=7\)\)\]'

# Define new callbacks
new_callbacks = '''# THREAT HISTORY CALLBACKS - Real-time data display and analytics

@app.callback(
    Output('threat-history-store', 'data'),
    Input('threat-history-update', 'n_intervals'),
    prevent_initial_call=False
)
def update_threat_history_store(n):
    """Fetch fresh threat history data every 3 seconds"""
    try:
        data = get_combined_history(limit=200)
        return data if data else []
    except Exception as e:
        print(f"Error updating threat history: {e}")
        return []


@app.callback(
    Output('history-table-container', 'children'),
    [Input('threat-history-store', 'data'),
     Input('history-search-input', 'value')],
    prevent_initial_call=False
)
def display_and_filter_threat_history(stored_data, search_value):
    """Display threat history table with real network data"""
    try:
        source = stored_data if stored_data else get_combined_history(limit=200)
        
        if not source or len(source) == 0:
            return dbc.Alert(
                [html.H5("📊 Loading Data", className="alert-heading"),
                 html.P("Fetching threat history from network analysis...")],
                color="info"
            )
        
        # Search filter
        term = (search_value or "").strip().lower()
        filtered = []
        
        for item in source[:200]:
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
        
        if not display_data:
            return dbc.Alert(
                [html.H5("🔍 No Results", className="alert-heading"),
                 html.P(f"No records match search: {search_value}")],
                color="warning"
            )
        
        # Build table rows
        rows = []
        for idx, item in enumerate(display_data, 1):
            sev_cls = {
                "Critical": "threat-critical",
                "High": "threat-high",
                "Medium": "threat-medium",
                "Low": "threat-low"
            }.get(item["severity"], "")
            
            stat_cls = {
                "Blocked": "text-success",
                "Resolved": "text-info",
                "Investigated": "text-warning",
                "Active": "text-danger",
                "Observed": "text-muted"
            }.get(item["status"], "text-muted")
            
            rows.append(html.Tr([
                html.Td(f"#{idx}", style={"color": "#00ff88", "fontWeight": "bold"}),
                html.Td(item["timestamp"], style={"fontSize": "12px"}),
                html.Td(html.Strong(item["type"]), style={"color": "#ffaa00"}),
                html.Td(html.Span(item["severity"], className=sev_cls)),
                html.Td(item["source_ip"], style={"fontFamily": "monospace", "fontSize": "11px"}),
                html.Td(item["country"]),
                html.Td(html.Span(item["status"], className=stat_cls))
            ]))
        
        table = dbc.Table(
            [
                html.Thead(
                    html.Tr([
                        html.Th("#"), html.Th("Timestamp"), html.Th("Type"),
                        html.Th("Severity"), html.Th("Source IP"), html.Th("Country"), html.Th("Status")
                    ], style={"backgroundColor": "#0a3a1a", "borderColor": "#00ff88"}),
                    style={"borderColor": "#00ff88"}
                ),
                html.Tbody(rows, style={"backgroundColor": "#111"})
            ],
            striped=True,
            hover=True,
            responsive=True
        )
        
        footer = html.Div(
            f"📊 {len(display_data)} of {len(source)} threat records",
            style={"marginTop": "10px", "fontSize": "12px", "color": "#888"}
        )
        
        return html.Div([table, footer])
        
    except Exception as e:
        return dbc.Alert(f"Error: {str(e)}", color="danger")'''

# Use simple string replacement on exact markers
search_start = '# Search / Filter Threat History'
search_end = 'return [html.Tr(html.Td(f"Error: {str(e)}", colSpan=7))]'

if search_start in content and search_end in content:
    start_idx = content.find(search_start)
    end_idx = content.find(search_end, start_idx) + len(search_end)
    
    # Replace
    new_content = content[:start_idx] + new_callbacks + '\n\n' + content[end_idx:]
    
    # Write back
    with open(app_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("✓ Callback replaced successfully!")
else:
    print("✗ Could not find callback markers in app.py")
    print(f"  Start marker found: {search_start in content}")
    print(f"  End marker found: {search_end in content}")

