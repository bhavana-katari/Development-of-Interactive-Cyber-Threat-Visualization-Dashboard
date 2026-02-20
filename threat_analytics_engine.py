# Professional Threat Tracking & Analytics Module
# Enterprise-grade cyber threat monitoring and analysis

import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum
import statistics


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


class ThreatStatus(Enum):
    """Threat status"""
    ACTIVE = "Active"
    MITIGATED = "Mitigated"
    BLOCKED = "Blocked"
    INVESTIGATING = "Investigating"


class CyberThreatAnalytics:
    """Professional threat analytics engine"""
    
    def __init__(self):
        self.threat_timeline = []
        self.threat_statistics = {}
        self.threat_trends = defaultdict(list)
        self.blocked_attacks = 0
        self.total_attacks = 0
        
    def process_threat(self, threat_data):
        """Process and analyze threat data"""
        try:
            threat_entry = {
                'id': threat_data.get('id'),
                'timestamp': threat_data.get('timestamp'),
                'source': threat_data.get('source', 'Unknown'),
                'type': threat_data.get('type', 'Unknown'),
                'severity': threat_data.get('severity', 'Low'),
                'status': threat_data.get('status', 'Active'),
                'lat': threat_data.get('lat', 0),
                'lon': threat_data.get('lon', 0),
                'target': threat_data.get('target', 'Internal Network'),
                'processed_at': datetime.now().isoformat()
            }
            
            self.threat_timeline.append(threat_entry)
            self.total_attacks += 1
            
            if threat_entry['status'] == 'Mitigated' or threat_entry['status'] == 'Blocked':
                self.blocked_attacks += 1
            
            return threat_entry
        
        except Exception as e:
            print(f"Error processing threat: {str(e)}")
            return None
    
    def get_threat_statistics(self, threats_data):
        """Calculate comprehensive threat statistics"""
        try:
            if not threats_data:
                return self._get_default_statistics()
            
            stats = {
                'total_threats': len(threats_data),
                'critical_threats': len([t for t in threats_data if t.get('severity') == 'Critical']),
                'high_threats': len([t for t in threats_data if t.get('severity') == 'High']),
                'medium_threats': len([t for t in threats_data if t.get('severity') == 'Medium']),
                'low_threats': len([t for t in threats_data if t.get('severity') == 'Low']),
                'active_threats': len([t for t in threats_data if t.get('status') == 'Active']),
                'mitigated_threats': len([t for t in threats_data if t.get('status') == 'Mitigated']),
                'blocked_threats': len([t for t in threats_data if t.get('status') == 'Blocked']),
                'block_rate': self._calculate_block_rate(threats_data),
                'threat_types': self._get_threat_types(threats_data),
                'top_sources': self._get_top_sources(threats_data, limit=5),
                'threat_level': self._calculate_threat_level(threats_data),
                'risk_score': self._calculate_risk_score(threats_data),
                'mitigation_rate': self._calculate_mitigation_rate(threats_data)
            }
            
            return stats
        
        except Exception as e:
            print(f"Error calculating statistics: {str(e)}")
            return self._get_default_statistics()
    
    def _get_default_statistics(self):
        """Return default empty statistics"""
        return {
            'total_threats': 0,
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'low_threats': 0,
            'active_threats': 0,
            'mitigated_threats': 0,
            'blocked_threats': 0,
            'block_rate': 0,
            'threat_types': {},
            'top_sources': [],
            'threat_level': 'LOW',
            'risk_score': 0,
            'mitigation_rate': 0
        }
    
    def _calculate_block_rate(self, threats_data):
        """Calculate percentage of blocked threats"""
        if not threats_data:
            return 0
        blocked = len([t for t in threats_data if t.get('status') in ['Blocked', 'Mitigated']])
        return int((blocked / len(threats_data)) * 100)
    
    def _calculate_mitigation_rate(self, threats_data):
        """Calculate mitigation success rate"""
        if not threats_data:
            return 0
        mitigated = len([t for t in threats_data if t.get('status') in ['Mitigated', 'Blocked']])
        return int((mitigated / len(threats_data)) * 100)
    
    def _get_threat_types(self, threats_data):
        """Get threat type distribution"""
        types = {}
        for threat in threats_data:
            threat_type = threat.get('type', 'Unknown')
            types[threat_type] = types.get(threat_type, 0) + 1
        return types
    
    def _get_top_sources(self, threats_data, limit=5):
        """Get top threat sources"""
        sources = {}
        for threat in threats_data:
            source = threat.get('source', 'Unknown')
            sources[source] = sources.get(source, 0) + 1
        
        sorted_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)
        return [{'source': src, 'count': count} for src, count in sorted_sources[:limit]]
    
    def _calculate_threat_level(self, threats_data):
        """Calculate overall threat level"""
        if not threats_data:
            return 'LOW'
        
        critical = len([t for t in threats_data if t.get('severity') == 'Critical'])
        high = len([t for t in threats_data if t.get('severity') == 'High'])
        total = len(threats_data)
        
        if critical >= 5:
            return 'CRITICAL'
        elif critical >= 2 or high >= 8:
            return 'HIGH'
        elif critical >= 1 or high >= 5:
            return 'ELEVATED'
        elif total >= 8:
            return 'MODERATE'
        elif total > 0:
            return 'LOW'
        else:
            return 'SECURE'
    
    def _calculate_risk_score(self, threats_data):
        """Calculate overall risk score (0-100)"""
        if not threats_data:
            return 0
        
        score = 0
        severity_weights = {
            'Critical': 25,
            'High': 15,
            'Medium': 8,
            'Low': 2
        }
        
        for threat in threats_data[:15]:  # Weight first 15 threats
            score += severity_weights.get(threat.get('severity', 'Low'), 2)
        
        # Apply mitigation factor
        active = len([t for t in threats_data if t.get('status') == 'Active'])
        active_factor = (active / len(threats_data)) if threats_data else 0
        
        final_score = int(score * active_factor)
        return min(final_score, 100)  # Cap at 100
    
    def get_threat_timeline_summary(self):
        """Get formatted threat timeline"""
        return self.threat_timeline[-10:]  # Return last 10 threats
    
    def generate_threat_report(self, threats_data):
        """Generate comprehensive threat report"""
        try:
            stats = self.get_threat_statistics(threats_data)
            
            report = {
                'report_timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_threats': stats['total_threats'],
                    'threat_level': stats['threat_level'],
                    'risk_score': stats['risk_score'],
                    'mitigation_rate': f"{stats['mitigation_rate']}%",
                    'block_rate': f"{stats['block_rate']}%"
                },
                'severity_breakdown': {
                    'critical': stats['critical_threats'],
                    'high': stats['high_threats'],
                    'medium': stats['medium_threats'],
                    'low': stats['low_threats']
                },
                'status_breakdown': {
                    'active': stats['active_threats'],
                    'mitigated': stats['mitigated_threats'],
                    'blocked': stats['blocked_threats']
                },
                'threat_types': stats['threat_types'],
                'top_sources': stats['top_sources'],
                'recommendations': self._generate_recommendations(stats)
            }
            
            return report
        
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return {}
    
    def _generate_recommendations(self, stats):
        """Generate security recommendations"""
        recommendations = []
        
        if stats['threat_level'] in ['CRITICAL', 'HIGH']:
            recommendations.append({
                'severity': 'URGENT',
                'action': 'Escalate to incident response team immediately',
                'reason': f"High threat level detected: {stats['threat_level']}"
            })
        
        if stats['block_rate'] < 80:
            recommendations.append({
                'severity': 'HIGH',
                'action': 'Review and strengthen firewall rules',
                'reason': f"Block rate below optimal threshold: {stats['block_rate']}%"
            })
        
        critical_sources = list(set([t['source'] for t in stats.get('top_sources', [])[:3]]))
        if critical_sources:
            recommendations.append({
                'severity': 'MEDIUM',
                'action': f"Monitor and potentially blacklist sources: {', '.join(critical_sources)}",
                'reason': 'These sources are showing repeated attack patterns'
            })
        
        if 'DDoS' in str(stats['threat_types']):
            recommendations.append({
                'severity': 'MEDIUM',
                'action': 'Activate DDoS mitigation protocols',
                'reason': 'DDoS attack detected in threat feed'
            })
        
        return recommendations


# Global threat analytics instance
threat_analytics = CyberThreatAnalytics()


def get_threat_summary(threats_data):
    """Get quick threat summary"""
    stats = threat_analytics.get_threat_statistics(threats_data)
    
    summary = f"""
    THREAT INTELLIGENCE SUMMARY
    ════════════════════════════════════════════════
    Total Threats:     {stats['total_threats']}
    Threat Level:      {stats['threat_level']}
    Risk Score:        {stats['risk_score']}/100
    
    SEVERITY BREAKDOWN
    ────────────────────────────────────────────────
    • Critical:        {stats['critical_threats']}
    • High:            {stats['high_threats']}
    • Medium:          {stats['medium_threats']}
    • Low:             {stats['low_threats']}
    
    STATUS BREAKDOWN
    ────────────────────────────────────────────────
    • Active:          {stats['active_threats']}
    • Mitigated:       {stats['mitigated_threats']}
    • Blocked:         {stats['blocked_threats']}
    
    PERFORMANCE METRICS
    ────────────────────────────────────────────────
    • Block Rate:      {stats['block_rate']}%
    • Mitigation Rate: {stats['mitigation_rate']}%
    """
    
    return summary
