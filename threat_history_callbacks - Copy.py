# Threat History Callbacks Module
# This file contains all callbacks for the threat history page

from dash import callback, Input, Output, State
from dash import html, dbc
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from app import get_combined_history, global_data, app
from datetime import datetime


def register_threat_history_callbacks(app):
    """Register all threat history page callbacks"""
    
    # Update history data store every 3 seconds
    @app.callback(
        Output('threat-history-store', 'data'),
        Input('threat-history-update', 'n_intervals'),
        prevent_initial_call=False
    )
    def update_history_store(n):
        """Fetch fresh threat data and store it"""
        try:
            data = get_combined_history(limit=200)
            return data if data else []
        except Exception as e:
            print(f"Error updating history store: {e}")
            return []
    
    
    # Display threat history table with filtering
    @app.callback(
        Output('history-table-container', 'children'),
        [Input('threat-history-store', 'data'),
         Input('history-search-input', 'value')],
        prevent_initial_call=False
    )
    def display_threat_history_table(stored_data, search_value):
        """Display threat history with search filtering"""
        try:
            # Get data
            source = stored_data if stored_data else get_combined_history(limit=200)
            
            if not source:
                return dbc.Alert(
                    [html.H5("📊 Loading Data", className="alert-heading"),
                     html.P("Waiting for threat database to populate...")],
                    color="info"
                )
            
            # Search filter
            term = (search_value or '').strip().lower()
            filtered = []
            
            for item in source[:200]:
                ts = item.get('timestamp', '')
                if isinstance(ts, datetime):
                    ts = ts.strftime('%Y-%m-%d %H:%M:%S')
                
                ttype = str(item.get('type', 'Unknown'))
                severity = str(item.get('severity', 'Unknown'))
                src_ip = str(item.get('source_ip', ''))
                country = str(item.get('country', 'Unknown'))
                status = str(item.get('status', 'Unknown'))
                
                searchable = f"{ts} {ttype} {severity} {src_ip} {country} {status}".lower()
                if term and term not in searchable:
                    continue
                
                filtered.append({
                    'timestamp': ts,
                    'type': ttype,
                    'severity': severity,
                    'source_ip': src_ip,
                    'country': country,
                    'status': status
                })
            
            # Show first 20
            display_data = filtered[:20]
            
            if not display_data:
                return dbc.Alert(
                    [html.H5("🔍 No Matches", className="alert-heading"),
                     html.P(f"No records match '{search_value}'")],
                    color="warning"
                )
            
            # Build table
            rows = []
            for idx, item in enumerate(display_data, 1):
                sev_cls = {
                    'Critical': 'threat-critical',
                    'High': 'threat-high',
                    'Medium': 'threat-medium',
                    'Low': 'threat-low'
                }.get(item['severity'], '')
                
                stat_cls = {
                    'Blocked': 'text-success',
                    'Resolved': 'text-info',
                    'Investigated': 'text-warning',
                    'Active': 'text-danger',
                    'Observed': 'text-muted'
                }.get(item['status'], 'text-muted')
                
                rows.append(html.Tr([
                    html.Td(f"#{idx}", style={'color': '#00ff88', 'fontWeight': 'bold'}),
                    html.Td(item['timestamp'], style={'fontSize': '11px'}),
                    html.Td(html.Strong(item['type']), style={'color': '#ffaa00'}),
                    html.Td(html.Span(item['severity'], className=sev_cls)),
                    html.Td(item['source_ip'], style={'fontFamily': 'monospace', 'fontSize': '10px'}),
                    html.Td(item['country']),
                    html.Td(html.Span(item['status'], className=stat_cls))
                ]))
            
            table = dbc.Table(
                [html.Thead(html.Tr([
                    html.Th("ID"), html.Th("Timestamp"), html.Th("Type"),
                    html.Th("Severity"), html.Th("Source IP"), html.Th("Country"), html.Th("Status")
                ])), html.Tbody(rows)],
                striped=True, hover=True, responsive=True
            )
            
            footer = html.Div(
                f"📊 {len(display_data)} of {len(source)} records",
                style={'marginTop': '10px', 'fontSize': '12px', 'color': '#888'}
            )
            
            return html.Div([table, footer])
            
        except Exception as e:
            return dbc.Alert(f"Error: {str(e)}", color="danger")
    
    
    # Analyze history with charts
    @app.callback(
        Output('analyze-output', 'children'),
        Input('btn-analyze-history', 'n_clicks'),
        prevent_initial_call=True
    )
    def create_analysis_report(n_clicks):
        """Generate comprehensive analysis report with charts"""
        if not n_clicks:
            return None
        
        try:
            data = get_combined_history(limit=100)
            
            if not data or len(data) == 0:
                return dbc.Alert(
                    [html.H5("ℹ️ Insufficient Data"),
                     html.P("Need at least some threat records to analyze")],
                    color="info"
                )
            
            df = pd.DataFrame(data)
            
            # Ensure columns
            for col in ['severity', 'type', 'status', 'country', 'source_ip']:
                if col not in df.columns:
                    df[col] = 'Unknown'
            
            # Statistics
            total = len(df)
            unique_sources = df['source_ip'].nunique()
            severity_counts = df['severity'].value_counts()
            type_counts = df['type'].value_counts()
            country_counts = df['country'].value_counts().head(8)
            
            # Chart 1: Severity Bar
            fig1 = go.Figure(data=[
                go.Bar(x=severity_counts.index, y=severity_counts.values,
                       marker_color=['#ff4444', '#ff6600', '#ffaa00', '#00ff88'][:len(severity_counts)])
            ])
            fig1.update_layout(
                title='Threats by Severity',
                xaxis_title='Severity', yaxis_title='Count',
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(30,30,30,0.5)',
                font=dict(color='white'), height=300, showlegend=False
            )
            
            # Chart 2: Threat Types Pie
            fig2 = go.Figure(data=[
                go.Pie(labels=type_counts.head(8).index, values=type_counts.head(8).values)
            ])
            fig2.update_layout(
                title='Threat Types',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'), height=300
            )
            
            # Chart 3: Top Countries
            fig3 = go.Figure(data=[
                go.Bar(y=country_counts.index, x=country_counts.values, orientation='h',
                       marker_color='#00ccff')
            ])
            fig3.update_layout(
                title='Top Attack Sources',
                xaxis_title='Count', yaxis_title='Country',
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(30,30,30,0.5)',
                font=dict(color='white'), height=300, showlegend=False
            )
            
            # Chart 4: Status Distribution
            status_counts = df['status'].value_counts()
            fig4 = go.Figure(data=[
                go.Pie(labels=status_counts.index, values=status_counts.values, hole=0.35)
            ])
            fig4.update_layout(
                title='Threat Status',
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white'), height=300
            )
            
            return dbc.Card([
                dbc.CardHeader(html.H5(f"📈 Threat Analysis Report ({total} Records)", 
                                       className='text-success mb-0')),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([html.Div([
                            html.P('Total Threats', className='text-muted small'),
                            html.H4(str(total), className='text-danger')
                        ], style={'textAlign': 'center'})], md=3),
                        dbc.Col([html.Div([
                            html.P('Unique Sources', className='text-muted small'),
                            html.H4(str(unique_sources), className='text-warning')
                        ], style={'textAlign': 'center'})], md=3),
                        dbc.Col([html.Div([
                            html.P('Top Type', className='text-muted small'),
                            html.H4(type_counts.index[0] if len(type_counts) > 0 else 'N/A', 
                                   className='text-info', style={'fontSize': '16px'})
                        ], style={'textAlign': 'center'})], md=3),
                        dbc.Col([html.Div([
                            html.P('Top Country', className='text-muted small'),
                            html.H4(country_counts.index[0] if len(country_counts) > 0 else 'N/A',
                                   className='text-success')
                        ], style={'textAlign': 'center'})], md=3),
                    ], className='mb-4'),
                    
                    dbc.Row([
                        dbc.Col([html.Div(id='chart-sev', children=[])], md=6),
                        dbc.Col([html.Div(id='chart-type', children=[])], md=6),
                    ]),
                    dbc.Row([
                        dbc.Col([html.Div(id='chart-country', children=[])], md=6),
                        dbc.Col([html.Div(id='chart-status', children=[])], md=6),
                    ])
                ])
            ], style={'backgroundColor': '#1a1a1a', 'borderColor': '#00ff88'})
            
        except Exception as e:
            print(f"Error in analysis: {e}")
            return dbc.Alert(f"Analysis Error: {str(e)}", color="danger")


