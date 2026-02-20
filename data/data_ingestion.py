# cyber-threat-dashboard/data/data_connector.py
import requests
import json
import pandas as pd
from datetime import datetime, timedelta
import random
from config import RAPIDAPI_CONFIG, USE_SAMPLE_DATA

class ThreatDataConnector:
    def __init__(self):
        self.headers = {
            'x-rapidapi-key': RAPIDAPI_CONFIG['key'],
            'x-rapidapi-host': RAPIDAPI_CONFIG['host']
        }
        
    def get_real_threats(self):
        """Get real threat data from API"""
        if USE_SAMPLE_DATA:
            print("⚠️ Using sample data (no API key configured)")
            return self.get_sample_data()
        
        try:
            # Try to get real data from API
            response = requests.get(
                RAPIDAPI_CONFIG['url'],
                headers=self.headers,
                params={'limit': 50}  # Get last 50 attacks
            )
            
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Got {len(data)} real threats from API")
                return data
            else:
                print(f"⚠️ API Error: {response.status_code}, using sample data")
                return self.get_sample_data()
                
        except Exception as e:
            print(f"❌ API Connection failed: {e}, using sample data")
            return self.get_sample_data()
    
    def get_sample_data(self):
        """Generate realistic sample threat data"""
        threats = []
        threat_types = ['Botnet', 'Ransomware', 'Phishing', 'DDoS', 'Malware', 
                       'SQL Injection', 'XSS', 'Zero-Day', 'Credential Theft']
        
        countries = ['United States', 'China', 'Russia', 'Germany', 'India', 
                    'Brazil', 'UK', 'France', 'Japan', 'Australia']
        
        # Generate 50 sample threats
        for i in range(50):
            threat = {
                'id': i,
                'type': random.choice(threat_types),
                'source_country': random.choice(countries),
                'target_country': random.choice(countries),
                'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
                'source_ip': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
                'target_ip': f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
                'status': random.choice(['Active', 'Blocked', 'Investigating'])
            }
            threats.append(threat)
        
        print(f"📊 Generated {len(threats)} sample threats")
        return threats
    
    def get_dashboard_stats(self):
        """Get statistics for dashboard (real or sample)"""
        threats = self.get_real_threats()
        
        # Calculate stats from threats
        active_threats = len([t for t in threats if t.get('status') == 'Active'])
        blocked_threats = len([t for t in threats if t.get('status') == 'Blocked'])
        critical_alerts = len([t for t in threats if t.get('severity') in ['High', 'Critical']])
        total_scanned = len(threats)
        
        return {
            'active_threats': active_threats,
            'blocked': blocked_threats,
            'critical_alerts': critical_alerts,
            'total_scanned': total_scanned,
            'threats': threats  # Include all threats for other components
        }