# cyber-threat-dashboard/dashboard_home.py
from dash import html, dcc
import dash_bootstrap_components as dbc
import random
import plotly.graph_objects as go

def layout():
    stats = {
        'active_threats': random.randint(15, 25),
        'blocked': random.randint(45, 55),
        'critical_alerts': random.randint(8, 12),
        'total_scanned': random.randint(70, 80),
        'devices': random.randint(90, 100),
        'vulnerabilities': random.randint(3, 6),
        'open_ports': random.randint(35, 40)
    }
    
    return html.Div([
        # Network Scanner Card
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader([
                        html.H4("Advanced Network Scanner", style={'color': '#00ff88', 'margin': '0'}),
                        html.P("Deep packet inspection and vulnerability assessment", 
                              style={'color': '#aaa', 'fontSize': '12px', 'margin': '0'})
                    ]),
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                html.Div([
                                    html.P("Active Devices", style={'color': '#ccc', 'fontSize': '14px'}),
                                    html.H2(f"{stats['devices']}", style={'color': '#fff'})
                                ], style={'textAlign': 'center'})
                            ]),
                            dbc.Col([
                                html.Div([
                                    html.P("Vulnerabilities", style={'color': '#ccc', 'fontSize': '14px'}),
                                    html.H2(f"{stats['vulnerabilities']}", style={'color': '#ff4444'})
                                ], style={'textAlign': 'center'})
                            ]),
                            dbc.Col([
                                html.Div([
                                    html.P("Open Ports", style={'color': '#ccc', 'fontSize': '14px'}),
                                    html.H2(f"{stats['open_ports']}", style={'color': '#ffaa00'})
                                ], style={'textAlign': 'center'})
                            ]),
                        ])
                    ])
                ], style={'backgroundColor': '#1a1a1a', 'border': '1px solid #333'})
            ], width=6),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader([
                        html.H4("Live Threat Feed", style={'color': '#00ff88', 'margin': '0'})
                    ]),
                    dbc.CardBody([
                        html.Div([
                            html.Div([
                                html.Span("🟥 High", style={'color': '#ff4444', 'float': 'right'}),
                                html.P("SQL Injection Attempt", style={'color': '#fff', 'margin': '0'}),
                                html.P("From: 185.220.101.45 (Russia)", 
                                      style={'color': '#aaa', 'fontSize': '12px', 'margin': '0'}),
                                html.Hr(style={'borderColor': '#333', 'margin': '10px 0'})
                            ]),
                            
                            html.Div([
                                html.Span("🟧 Medium", style={'color': '#ffaa00', 'float': 'right'}),
                                html.P("Phishing Campaign", style={'color': '#fff', 'margin': '0'}),
                                html.P("From: 110.21.98.188 (Vietnam)", 
                                      style={'color': '#aaa', 'fontSize': '12px', 'margin': '0'}),
                                html.Hr(style={'borderColor': '#333', 'margin': '10px 0'})
                            ]),
                        ])
                    ])
                ], style={'backgroundColor': '#1a1a1a', 'border': '1px solid #333'})
            ], width=6),
        ], style={'margin': '20px'}),
        
        # Graph
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader([
                        html.H4("Threat Activity", style={'color': '#00ff88', 'margin': '0'})
                    ]),
                    dbc.CardBody([
                        dcc.Graph(
                            figure={
                                'data': [
                                    {'x': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
                                     'y': [random.randint(10, 30) for _ in range(5)],
                                     'type': 'bar',
                                     'name': 'High',
                                     'marker': {'color': '#ff4444'}}
                                ],
                                'layout': {
                                    'paper_bgcolor': 'rgba(0,0,0,0)',
                                    'plot_bgcolor': 'rgba(0,0,0,0)',
                                    'font': {'color': '#fff'}
                                }
                            },
                            style={'height': '300px'}
                        )
                    ])
                ], style={'backgroundColor': '#1a1a1a', 'border': '1px solid #333'})
            ], width=12),
        ], style={'margin': '20px'}),
    ], style={'marginLeft': '280px', 'padding': '20px'})