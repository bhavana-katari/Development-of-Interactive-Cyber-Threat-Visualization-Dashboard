#!/usr/bin/env python3
"""Add the Analyze History callback"""

app_file = 'app.py'

with open(app_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find where to insert (before analyze_history already exists, so find and replace it)
old_analyze ='# Analyze History callback - summarizes threat history and returns comprehensive reports + charts'

new_analyze_callback = '''# Analyze History callback - generates comprehensive threat intelligence reports with charts

@app.callback(
    Output('analyze-output', 'children'),
    Input('btn-analyze-history', 'n_clicks'),
    prevent_initial_call=True
)
def analyze_threat_history(n_clicks):
    """Generate comprehensive threat analysis report with 5 charts based on 100 records"""
    if not n_clicks:
        return None
    
    try:
        data = get_combined_history(limit=100)
        
        if not data or len(data) == 0:
            return dbc.Alert(
                [html.H5("ℹ️ No Data", className="alert-heading"),
                 html.P("Need threat data to generate analysis")],
                color="warning"
            )
        
        df = pd.DataFrame(data)
        
        # Ensure all required columns exist
        for col in ["severity", "type", "status", "country", "source_ip"]:
            if col not in df.columns:
                df[col] = "Unknown"
        
        # Calculate statistics
        total = len(df)
        unique_sources = df["source_ip"].nunique()
        severity_counts = df["severity"].value_counts()
        type_counts = df["type"].value_counts()
        country_counts = df["country"].value_counts().head(8)
        status_counts = df["status"].value_counts()
        
        # Chart 1: Severity Distribution (Bar Chart)
        fig1 = go.Figure(data=[
            go.Bar(
                x=severity_counts.index,
                y=severity_counts.values,
                marker_color=["#ff4444", "#ff6600", "#ffaa00", "#00ff88"][:len(severity_counts)],
                name="Number of Threats"
            )
        ])
        fig1.update_layout(
            title="Threats by Severity Level",
            xaxis_title="Severity",
            yaxis_title="Number of Threats",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,30,30,0.5)",
            font=dict(color="white", size=12),
            height=300,
            showlegend=False,
            margin=dict(l=50, r=30, t=50, b=50)
        )
        
        # Chart 2: Threat Types (Pie Chart)
        fig2 = go.Figure(data=[
            go.Pie(
                labels=type_counts.head(8).index,
                values=type_counts.head(8).values,
                textposition="auto"
            )
        ])
        fig2.update_layout(
            title="Threat Type Distribution (Top 8)",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white", size=12),
            height=300,
            margin=dict(l=30, r=30, t=50, b=30)
        )
        
        # Chart 3: Top Countries (Horizontal Bar)
        fig3 = go.Figure(data=[
            go.Bar(
                y=country_counts.index,
                x=country_counts.values,
                orientation="h",
                marker_color="#00ccff",
                name="Attack Count"
            )
        ])
        fig3.update_layout(
            title="Top Attack Sources by Country",
            xaxis_title="Number of Attacks",
            yaxis_title="Country",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(30,30,30,0.5)",
            font=dict(color="white", size=12),
            height=300,
            showlegend=False,
            margin=dict(l=80, r=30, t=50, b=50)
        )
        
        # Chart 4: Threat Status (Donut Chart)
        fig4 = go.Figure(data=[
            go.Pie(
                labels=status_counts.index,
                values=status_counts.values,
                hole=0.3,
                textposition="auto"
            )
        ])
        fig4.update_layout(
            title="Threat Status Distribution",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white", size=12),
            height=300,
            margin=dict(l=30, r=30, t=50, b=30)
        )
        
        # Chart 5: Severity Timeline (if we have timestamps)
        if "timestamp" in df.columns:
            df_copy = df.copy()
            df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"], errors="coerce")
            df_copy = df_copy.dropna(subset=["timestamp"])
            
            threat_timeline = df_copy.groupby(df_copy["timestamp"].dt.floor("H")).size()
            
            fig5 = go.Figure(data=[
                go.Scatter(
                    x=threat_timeline.index,
                    y=threat_timeline.values,
                    mode="lines+markers",
                    line=dict(color="#ffaa00", width=3),
                    marker=dict(size=8),
                    fill="tozeroy"
                )
            ])
            fig5.update_layout(
                title="Threat Incidents Over Time (Hourly)",
                xaxis_title="Time",
                yaxis_title="Number of Threats",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(30,30,30,0.5)",
                font=dict(color="white", size=12),
                height=300,
                showlegend=False,
                margin=dict(l=50, r=30, t=50, b=50)
            )
        else:
            fig5 = go.Figure()
            fig5.add_annotation(text="No timestamp data available", showarrow=False)
        
        # Build comprehensive report card
        return dbc.Card([
            dbc.CardHeader(
                html.H5(f"📊 Threat Intelligence Report - {total} Records Analyzed",
                       className="text-success mb-0", style={"fontWeight": "bold"})
            ),
            dbc.CardBody([
                # Summary Statistics Row
                dbc.Row([
                    dbc.Col([
                        html.Div([
                            html.P("Total Threats", className="text-muted small", style={"letterSpacing": "1px"}),
                            html.H2(str(total), className="text-danger fw-bold")
                        ], style={"textAlign": "center", "padding": "15px"})
                    ], md=3),
                    
                    dbc.Col([
                        html.Div([
                            html.P("Unique Sources", className="text-muted small", style={"letterSpacing": "1px"}),
                            html.H2(str(unique_sources), className="text-warning fw-bold")
                        ], style={"textAlign": "center", "padding": "15px"})
                    ], md=3),
                    
                    dbc.Col([
                        html.Div([
                            html.P("Most Common Type", className="text-muted small", style={"letterSpacing": "1px"}),
                            html.H3(str(type_counts.index[0]) if len(type_counts) > 0 else "N/A",
                                   className="text-info fw-bold", style={"fontSize": "18px"})
                        ], style={"textAlign": "center", "padding": "15px"})
                    ], md=3),
                    
                    dbc.Col([
                        html.Div([
                            html.P("Top Country", className="text-muted small", style={"letterSpacing": "1px"}),
                            html.H3(str(country_counts.index[0]) if len(country_counts) > 0 else "N/A",
                                   className="text-success fw-bold")
                        ], style={"textAlign": "center", "padding": "15px"})
                    ], md=3),
                ], className="mb-4", style={"borderBottom": "1px solid #333", "paddingBottom": "20px"}),
                
                # Charts Row 1
                dbc.Row([
                    dbc.Col([dcc.Graph(figure=fig1, config={"displayModeBar": False})], md=6),
                    dbc.Col([dcc.Graph(figure=fig2, config={"displayModeBar": False})], md=6),
                ], className="mb-3"),
                
                # Charts Row 2
                dbc.Row([
                    dbc.Col([dcc.Graph(figure=fig3, config={"displayModeBar": False})], md=6),
                    dbc.Col([dcc.Graph(figure=fig4, config={"displayModeBar": False})], md=6),
                ], className="mb-3"),
                
                # Charts Row 3
                dbc.Row([
                    dbc.Col([dcc.Graph(figure=fig5, config={"displayModeBar": False})], md=12),
                ]),
            ], style={"backgroundColor": "#111111"}),
        ], style={"backgroundColor": "#1a1a1a", "borderColor": "#00ff88", "border": "2px solid #00ff88"})
        
    except Exception as e:
        print(f"Error in analyze_history: {e}")
        import traceback
        traceback.print_exc()
        return dbc.Alert(
            [html.H5("❌ Analysis Error", className="alert-heading"),
             html.P(str(e))],
            color="danger"
        )'''

if old_analyze in content:
    # Find the start of the old function
    old_start_idx = content.find(old_analyze)
    # Find the next comment or end of function
    next_boundary = content.find('\n# ', old_start_idx + 1)
    if next_boundary == -1:
        next_boundary = content.find('\n\n# ', old_start_idx + 1)
    
    if next_boundary > 0:
        new_content = content[:old_start_idx] + new_analyze_callback + '\n\n' + content[next_boundary:]
      
        with open(app_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print("✓ Analyze History callback updated successfully!")
    else:
        print("✗ Could not find callback boundary")
else:
    print("✗ Could not find old analyze callback")

