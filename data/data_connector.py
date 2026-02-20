# cyber-threat-dashboard/data/data_connector.py
import random
from datetime import datetime, timedelta

class ThreatDataConnector:
    def __init__(self):
        print("✅ Data connector initialized")
    
    def get_sample_data(self):
        """Generate simple sample data"""
        threats = []
        threat_types = ['Botnet', 'Ransomware', 'Phishing']
        
        for i in range(10):
            threat = {
                'id': i,
                'type': random.choice(threat_types),
                'source_country': 'Country ' + str(i),
                'severity': 'Medium',
                'timestamp': datetime.now().isoformat()
            }
            threats.append(threat)
        
        return threats
    
    def get_dashboard_stats(self):
        """Get simple stats"""
        threats = self.get_sample_data()
        
        return {
            'active_threats': random.randint(10, 30),
            'blocked': random.randint(40, 60),
            'critical_alerts': random.randint(5, 15),
            'total_scanned': random.randint(60, 80),
            'threats': threats
        }