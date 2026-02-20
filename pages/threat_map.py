# cyber-threat-dashboard/pages/threat_map.py
import dash
from dash import html, dcc
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
import random
from datetime import datetime

# Sample threat data for the map (like your screenshots)
def get_threat_data():
    threats = [
        {
            'country': 'Seychelles',
            'threat_type': 'Botnet',
            'coordinates': (-4.6796, 55.4920),  # Approx Seychelles
            'ip': '79.214.241.82',
            'time': '8:28:30 PM',
            'severity': 'High'
        },
        {
            'country': 'Switzerland',
            'threat_type': 'Session Hijacking',
            'coordinates': (46.8182, 8.2275),  # Switzerland
            'ip': '14.71.101.148',
            'time': '8:28:28 PM',
            'severity': 'Critical'
        },
        {
            'country': 'Vietnam',
            'threat_type': 'Ransomware',
            'coordinates': (14.0583, 108.2772),  # Vietnam
            'ip': '110.21.98.188',
            'time': '8:28:26 PM',
            'severity': 'High'
        },
        {
            'country': 'Norway',
            'threat_type': 'Zero-Day',
            'coordinates': (60.4720, 8.4689),  # Norway
            'ip': '205.69.92.164',
            'time': '8:28:24 PM',
            'severity': 'Critical'
        },
        {
            'country': 'Malaysia',
            'threat_type': 'Phishing',
            'coordinates': (4.2105, 101.9758),  # Malaysia
            'ip': '31.116.229.7',
            'time': '8:28:22 PM',
            'severity': 'Medium'
        },
        {
            'country': 'France',
            'threat_type': 'XSS',
            'coordinates': (46.6034, 1.8883),  # France
            'ip': '20.163.0.5',
            'time': '8:28:20 PM',
            'severity': 'Medium'
        },
        {
            'country': 'Fiji',
            'threat_type': 'Rootkit',
            'coordinates': (-17.7134, 178.0650),  # Fiji
            'ip': '106.89.106.217',
            'time': '8:28:18 PM',
            'severity': 'High'
        },
        {
            'country': 'Morocco',
            'threat_type': 'XSS',
            'coordinates': (31.7917, -7.0926),  # Morocco
            'ip': '221.35.3.6',
            'time': '8:28:14 PM',
            'severity': 'Medium'
        }
    ]
    return threats

# Create the threat map
def create_threat_map():
    threats = get_threat_data()
    
    # Create map figure
    fig = go.Figure()
    
    # Add threat points to map
    for threat in threats:
        # Color based on severity
        color = '#ff4444' if threat['severity'] in ['High', 'Critical'] else '#ffaa00' if threat['severity'] == 'Medium' else '#00ff88'
        
        fig.add_trace(go.Scattergeo(
            lon=[threat['coordinates'][1]],
            lat=[threat['coordinates'][0]],
            text=f"{threat['country']}<br>{threat['threat_type']}<br>{threat['ip']}",
            mode='markers',
            marker=dict(
                size=15,
                color=color,
                line=dict(width=2, color='white')
            ),
            name=threat['country']
        ))
    
    # Update map layout
    fig.update_layout(
        title_text='Live Attack Origins - Global Threat Map',
        showlegend=False,
        geo=dict(
            showland=True,
            landcolor='rgb(40, 40, 40)',
            subunitcolor='rgb(100, 100, 100)',
            countrycolor='rgb(100, 100, 100)',
            showlakes=False,
            lakecolor='rgb(40, 40, 40)',
            showsubunits=True,
            showcountries=True,
            resolution=50,
            projection=dict(type='natural earth'),
            coastlinecolor='rgb(100, 100, 100)',
            bgcolor='rgba(0,0,0,0)'
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='white'),
        height=600
    )
    
    return fig

# Threat list component (like your screenshot)
def create_threat_list():
    threats = get_threat_data()
    
    threat_cards = []
    for threat in threats:
        # Determine icon based on threat type
        if 'Botnet' in threat['threat_type']:
            icon = '🟣'
        elif 'Ransomware' in threat['threat_type']:
            icon = '🔴'
        elif 'Phishing' in threat['threat_type']:
            icon = '🟡'
        elif 'Zero-Day' in threat['threat_type']:
            icon = '⚫'
        else:
            icon = '⚪'
        
        card = dbc.Card([
            dbc.CardBody([
                html.Div([
                    html.Div([
                        html.H5(f"{icon} {threat['country']}", 
                               style={'color': '#00ff88', 'marginBottom': '5px'}),
                        html.P(threat['threat_type'], 
                              style={'color': '#ffffff', 'fontWeight': 'bold', 'marginBottom': '5px'}),
                        html.P(f"📍 {threat['coordinates'][0]:.4f}°, {threat['coordinates'][1]:.4f}°",
                              style={'color': '#aaa', 'fontSize': '12px', 'marginBottom': '2px'}),
                        html.P(f"🌐 {threat['ip']}",
                              style={'color': '#aaa', 'fontSize': '12px', 'marginBottom': '2px'}),
                        html.P(f"🕒 {threat['time']}",
                              style={'color': '#aaa', 'fontSize': '12px', 'marginBottom': '10px'}),
                        dbc.Button("View on Map", 
                                  color="primary", 
                                  size="sm",
                                  style={'width': '100%'})
                    ])
                ])
            ])
        ], style={
            'backgroundColor': '#1a1a1a',
            'border': '1px solid #333',
            'marginBottom': '15px'
        })
        
        threat_cards.append(card)
    
    return threat_cards

# Layout for threat map page
def layout():
    return html.Div([
        # Page header
        html.Div([
            html.H1("Live Attack Origins - Click to View", 
                   style={'color': 'white', 'textAlign': 'center', 'margin': '20px 0'}),
            html.P("Real-time global threat intelligence visualization",
                  style={'color': '#aaa', 'textAlign': 'center', 'marginBottom': '30px'})
        ]),
        
        # Two column layout: Map and Threat List
        dbc.Row([
            # Left column: Map (2/3 width)
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        dcc.Graph(
                            id='threat-map',
                            figure=create_threat_map(),
                            style={'height': '650px'}
                        ),
                        html.Div([
                            html.P("🌍 Click on any attack point for details", 
                                  style={'color': '#aaa', 'textAlign': 'center', 'marginTop': '10px'})
                        ])
                    ])
                ], style={'backgroundColor': '#1a1a1a', 'border': '1px solid #333'})
            ], width=8),
            
            # Right column: Threat List (1/3 width)
            dbc.Col([
                html.Div([
                    html.H4("Active Threats", style={'color': '#00ff88', 'marginBottom': '20px'}),
                    html.Div(create_threat_list())
                ])
            ], width=4)
        ], style={'margin': '0 20px'}),
        
        # Stats row at bottom
        html.Div([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        html.H3("24", style={'color': '#ff4444', 'textAlign': 'center'}),
                        html.P("Active Attacks", style={'color': '#aaa', 'textAlign': 'center'})
                    ], style={'padding': '20px', 'backgroundColor': '#1a1a1a', 'borderRadius': '8px'})
                ]),
                dbc.Col([
                    html.Div([
                        html.H3("8", style={'color': '#ffaa00', 'textAlign': 'center'}),
                        html.P("Countries Targeted", style={'color': '#aaa', 'textAlign': 'center'})
                    ], style={'padding': '20px', 'backgroundColor': '#1a1a1a', 'borderRadius': '8px'})
                ]),
                dbc.Col([
                    html.Div([
                        html.H3("6", style={'color': '#00ff88', 'textAlign': 'center'}),
                        html.P("Threat Types", style={'color': '#aaa', 'textAlign': 'center'})
                    ], style={'padding': '20px', 'backgroundColor': '#1a1a1a', 'borderRadius': '8px'})
                ]),
                dbc.Col([
                    html.Div([
                        html.H3("94%", style={'color': '#4488ff', 'textAlign': 'center'}),
                        html.P("Block Rate", style={'color': '#aaa', 'textAlign': 'center'})
                    ], style={'padding': '20px', 'backgroundColor': '#1a1a1a', 'borderRadius': '8px'})
                ]),
            ], style={'marginTop': '30px', 'marginBottom': '30px'})
        ], style={'padding': '0 20px'})
    ], style={'marginLeft': '280px', 'padding': '20px'})