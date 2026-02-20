# Professional Analytics Processor for Real Network Data
# Real-time analytics with multiple visualization engines

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
import plotly.graph_objects as go
import plotly.express as px
from threading import Lock


class NetworkAnalyticsProcessor:
    """Process and analyze real network data for dashboard visualization"""
    
    def __init__(self):
        self.data_lock = Lock()
        self.bandwidth_history = deque(maxlen=100)  # Keep last 100 samples
        self.threat_history = deque(maxlen=200) # Aggregated snapshots
        self.individual_threats = deque(maxlen=300) # Raw individual events
        self.connection_history = deque(maxlen=500)
        self.packet_loss_history = deque(maxlen=100)
        self.latency_history = deque(maxlen=100)
        self.threat_types = defaultdict(int)
        self.top_threats_by_country = defaultdict(int)
        
    def process_network_stats(self, network_info):
        """Process raw network statistics"""
        try:
            if not network_info or 'stats' not in network_info:
                return None
            
            stats = network_info['stats']
            timestamp = datetime.now()
            
            processed = {
                'timestamp': timestamp,
                'bytes_sent': stats.get('bytes_sent', 0),
                'bytes_recv': stats.get('bytes_recv', 0),
                'packets_sent': stats.get('packets_sent', 0),
                'packets_recv': stats.get('packets_recv', 0),
                'errors': stats.get('error_in', 0) + stats.get('error_out', 0),
                'drops': stats.get('drop_in', 0) + stats.get('drop_out', 0),
                'speed_sent': stats.get('speed_sent', 0),
                'speed_recv': stats.get('speed_recv', 0),
                'total_connections': len(network_info.get('connections', []))
            }
            
            with self.data_lock:
                self.bandwidth_history.append(processed)
            
            return processed
        
        except Exception as e:
            print(f"Error processing network stats: {e}")
            return None
    
    def process_threat_data(self, threats):
        """Process threat intelligence data"""
        try:
            if not threats:
                return None
            
            threat_stats = {
                'total': len(threats),
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'active': 0,
                'mitigated': 0,
                'blocked': 0,
                'by_type': defaultdict(int),
                'by_country': defaultdict(int),
                'timestamp': datetime.now()
            }
            
            for threat in threats:
                severity = threat.get('severity', 'Low')
                status = threat.get('status', 'Active')
                threat_type = threat.get('type', 'Unknown')
                source = threat.get('source', 'Unknown')
                
                # Count by severity
                if severity == 'Critical':
                    threat_stats['critical'] += 1
                elif severity == 'High':
                    threat_stats['high'] += 1
                elif severity == 'Medium':
                    threat_stats['medium'] += 1
                else:
                    threat_stats['low'] += 1
                
                # Count by status
                if status == 'Active':
                    threat_stats['active'] += 1
                elif status == 'Mitigated':
                    threat_stats['mitigated'] += 1
                elif status == 'Blocked':
                    threat_stats['blocked'] += 1
                
                # Count by type
                threat_stats['by_type'][threat_type] += 1
                self.threat_types[threat_type] += 1
                
                # Count by country
                threat_stats['by_country'][source] += 1
                self.top_threats_by_country[source] += 1
            
            with self.data_lock:
                self.threat_history.append(threat_stats)
                # Store individual events for the chronological history table
                if threats:
                    # If it's a list, only append the items if they are unique or new
                    # For simplicity, we'll append all and the caller should pass only what's new
                    for threat in threats:
                        self.individual_threats.append(threat)
            
            return threat_stats
        
        except Exception as e:
            print(f"Error processing threat data: {e}")
            return None
    
    def get_bandwidth_trends(self, limit=50):
        """Get bandwidth trend data for visualization"""
        try:
            with self.data_lock:
                data = list(self.bandwidth_history)[-limit:]
            
            if not data:
                return None
            
            df = pd.DataFrame([
                {
                    'time': item['timestamp'],
                    'sent_mbps': (item.get('speed_sent', 0) * 8) / 1_000_000,  # bytes/sec -> Mbps
                    'recv_mbps': (item.get('speed_recv', 0) * 8) / 1_000_000,
                    'total_mbps': ((item.get('speed_sent', 0) + item.get('speed_recv', 0)) * 8) / 1_000_000
                }
                for item in data
            ])
            
            return df
        
        except Exception as e:
            print(f"Error getting bandwidth trends: {e}")
            return None
    
    def get_threat_timeline(self, limit=100):
        """Get threat history timeline"""
        try:
            with self.data_lock:
                data = list(self.threat_history)[-limit:]
            
            if not data:
                return None
            
            df = pd.DataFrame([
                {
                    'time': item['timestamp'].strftime('%H:%M:%S'),
                    'critical': item['critical'],
                    'high': item['high'],
                    'medium': item['medium'],
                    'low': item['low'],
                    'total': item['total']
                }
                for item in data
            ])
            
            return df
        
        except Exception as e:
            print(f"Error getting threat timeline: {e}")
            return None
    
    def get_threat_distribution(self):
        """Get threat type distribution"""
        try:
            if not self.threat_types:
                return None
            
            sorted_types = sorted(self.threat_types.items(), key=lambda x: x[1], reverse=True)
            return {threat_type: count for threat_type, count in sorted_types[:10]}
        
        except Exception as e:
            print(f"Error getting threat distribution: {e}")
            return None
    
    def get_top_threat_sources(self, limit=10):
        """Get top threat source countries"""
        try:
            sorted_sources = sorted(
                self.top_threats_by_country.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return {source: count for source, count in sorted_sources[:limit]}
        
        except Exception as e:
            print(f"Error getting top sources: {e}")
            return None
    
    def get_summary_statistics(self):
        """Get overall summary statistics"""
        try:
            total_bandwidth_gb = 0
            total_threats = 0
            total_blocked = 0
            
            with self.data_lock:
                if self.bandwidth_history:
                    latest_bw = list(self.bandwidth_history)[-1]
                    total_bandwidth_gb = latest_bw['bytes_sent'] / (1024**3) + latest_bw['bytes_recv'] / (1024**3)
                
                if self.threat_history:
                    latest_threat = list(self.threat_history)[-1]
                    total_threats = latest_threat['total']
                    total_blocked = latest_threat['blocked'] + latest_threat['mitigated']
            
            block_rate = int((total_blocked / max(total_threats, 1)) * 100)
            
            return {
                'total_bandwidth_gb': round(total_bandwidth_gb, 2),
                'total_threats': total_threats,
                'total_blocked': total_blocked,
                'block_rate': block_rate,
                'unique_threat_types': len(self.threat_types),
                'unique_sources': len(self.top_threats_by_country),
                'avg_packets_per_threat': 0  # Placeholder
            }
        
        except Exception as e:
            print(f"Error getting summary statistics: {e}")
            return {}


# Global analytics processor instance
analytics_processor = NetworkAnalyticsProcessor()


def create_bandwidth_chart(network_data, bandwidth_history):
    """Create real-time bandwidth utilization chart"""
    try:
        df = analytics_processor.get_bandwidth_trends(limit=50)
        
        if df is None or df.empty:
            # Return empty chart
            fig = go.Figure()
            fig.add_annotation(text="No bandwidth data available", xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            fig.update_layout(
                paper_bgcolor='#0a0a0a',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            return fig
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['sent_mbps'],
            name='Upload (Mbps)',
            mode='lines+markers',
            line=dict(color='#00ff88', width=2),
            marker=dict(size=4),
            fill='tozeroy',
            fillcolor='rgba(0, 255, 136, 0.2)'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['recv_mbps'],
            name='Download (Mbps)',
            mode='lines+markers',
            line=dict(color='#ff6b35', width=2),
            marker=dict(size=4),
            fill='tozeroy',
            fillcolor='rgba(255, 107, 53, 0.2)'
        ))
        
        fig.update_layout(
            title='Real-Time Bandwidth Utilization',
            paper_bgcolor='#0a0a0a',
            plot_bgcolor='rgba(0,0,0,0.3)',
            font=dict(color='white', size=12),
            hovermode='x unified',
            xaxis=dict(showgrid=True, gridcolor='#333', type='date', tickformat='%H:%M:%S'),
            yaxis=dict(showgrid=True, gridcolor='#333', title='Speed (Mbps)'),
            legend=dict(bgcolor='rgba(0,0,0,0.5)', font=dict(size=11)),
            height=400,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating bandwidth chart: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig


def create_threat_timeline_chart(threats_data):
    """Create threat timeline with severity breakdown"""
    try:
        df = analytics_processor.get_threat_timeline(limit=50)
        
        if df is None or df.empty:
            fig = go.Figure()
            fig.add_annotation(text="No threat data available", xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            fig.update_layout(
                paper_bgcolor='#0a0a0a',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='white')
            )
            return fig
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['critical'],
            name='Critical',
            mode='lines+markers',
            line=dict(color='#ff2e2e', width=2),
            marker=dict(size=5),
            stackgroup='one'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['high'],
            name='High',
            mode='lines+markers',
            line=dict(color='#ff6b35', width=2),
            marker=dict(size=5),
            stackgroup='one'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['medium'],
            name='Medium',
            mode='lines+markers',
            line=dict(color='#ffa500', width=2),
            marker=dict(size=5),
            stackgroup='one'
        ))
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['low'],
            name='Low',
            mode='lines+markers',
            line=dict(color='#ffdd57', width=2),
            marker=dict(size=5),
            stackgroup='one'
        ))
        
        fig.update_layout(
            title='Threat Timeline by Severity',
            paper_bgcolor='#0a0a0a',
            plot_bgcolor='rgba(0,0,0,0.3)',
            font=dict(color='white', size=12),
            hovermode='x unified',
            xaxis=dict(showgrid=True, gridcolor='#333'),
            yaxis=dict(showgrid=True, gridcolor='#333', title='Threat Count'),
            legend=dict(bgcolor='rgba(0,0,0,0.5)', font=dict(size=11)),
            height=400,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating threat timeline: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig


def create_threat_distribution_chart():
    """Create threat type distribution pie chart"""
    try:
        threat_dist = analytics_processor.get_threat_distribution()
        
        if not threat_dist:
            fig = go.Figure()
            fig.add_annotation(text="No threat distribution data", xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            fig.update_layout(paper_bgcolor='#0a0a0a', font=dict(color='white'))
            return fig
        
        threat_types = list(threat_dist.keys())
        threat_counts = list(threat_dist.values())
        
        fig = go.Figure(data=[go.Pie(
            labels=threat_types,
            values=threat_counts,
            marker=dict(
                colors=['#ff2e2e', '#ff6b35', '#ffa500', '#ffdd57', '#00ff88', '#0088ff',
                       '#00ff88', '#ff2e2e', '#ff6b35', '#ffa500']
            ),
            textposition='auto',
            textinfo='label+percent+value'
        )])
        
        fig.update_layout(
            title='Threat Type Distribution',
            paper_bgcolor='#0a0a0a',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white', size=12),
            legend=dict(bgcolor='rgba(0,0,0,0.5)', font=dict(size=10)),
            height=400
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating threat distribution: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig


def create_top_sources_chart():
    """Create top threat sources bar chart"""
    try:
        top_sources = analytics_processor.get_top_threat_sources(limit=10)
        
        if not top_sources:
            fig = go.Figure()
            fig.add_annotation(text="No source data available", xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            fig.update_layout(paper_bgcolor='#0a0a0a', font=dict(color='white'))
            return fig
        
        countries = list(top_sources.keys())
        counts = list(top_sources.values())
        
        fig = go.Figure(data=[go.Bar(
            x=countries,
            y=counts,
            marker=dict(
                color=counts,
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Threats", tickcolor='white')
            ),
            text=counts,
            textposition='auto',
        )])
        
        fig.update_layout(
            title='Top 10 Threat Sources by Country',
            paper_bgcolor='#0a0a0a',
            plot_bgcolor='rgba(0,0,0,0.3)',
            font=dict(color='white', size=12),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor='#333', title='Threat Count'),
            height=400,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating top sources chart: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig


def create_packet_analysis_chart(network_info):
    """Create packet analysis visualization"""
    try:
        if not network_info or 'stats' not in network_info:
            fig = go.Figure()
            fig.add_annotation(text="No packet data", xref="paper", yref="paper",
                             x=0.5, y=0.5, showarrow=False)
            fig.update_layout(paper_bgcolor='#0a0a0a', font=dict(color='white'))
            return fig
        
        stats = network_info['stats']
        
        categories = ['Sent', 'Received', 'Errors', 'Dropped']
        values = [
            stats.get('packets_sent', 0),
            stats.get('packets_recv', 0),
            stats.get('error_in', 0) + stats.get('error_out', 0),
            stats.get('drop_in', 0) + stats.get('drop_out', 0)
        ]
        
        colors = ['#00ff88', '#0088ff', '#ff6b35', '#ff2e2e']
        
        fig = go.Figure(data=[go.Bar(
            x=categories,
            y=values,
            marker=dict(color=colors),
            text=[f"{v:,}" for v in values],
            textposition='auto',
        )])
        
        fig.update_layout(
            title='Packet Statistics Analysis',
            paper_bgcolor='#0a0a0a',
            plot_bgcolor='rgba(0,0,0,0.3)',
            font=dict(color='white', size=12),
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=True, gridcolor='#333', title='Count'),
            height=350,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating packet chart: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig


def create_security_score_gauge():
    """Create security score gauge chart"""
    try:
        summary = analytics_processor.get_summary_statistics()
        block_rate = summary.get('block_rate', 0)
        
        # Calculate security score (0-100)
        # Higher block rate = higher security score
        security_score = max(0, min(100, block_rate + 10))
        
        fig = go.Figure(data=[go.Indicator(
            mode="gauge+number+delta",
            value=security_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            delta={'reference': 80},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': '#00ff88'},
                'steps': [
                    {'range': [0, 40], 'color': 'rgba(255, 46, 46, 0.2)'},
                    {'range': [40, 70], 'color': 'rgba(255, 107, 53, 0.2)'},
                    {'range': [70, 100], 'color': 'rgba(0, 255, 136, 0.2)'}
                ],
                'threshold': {
                    'line': {'color': 'white', 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            },
            title={'text': "Network Security Score"}
        )])
        
        fig.update_layout(
            paper_bgcolor='#0a0a0a',
            font=dict(color='white', size=12),
            height=350,
            margin=dict(l=40, r=40, t=80, b=40)
        )
        
        return fig
    
    except Exception as e:
        print(f"Error creating security gauge: {e}")
        fig = go.Figure()
        fig.add_annotation(text=f"Error: {str(e)[:30]}", xref="paper", yref="paper",
                         x=0.5, y=0.5, showarrow=False, font=dict(color='#ff4444'))
        return fig
