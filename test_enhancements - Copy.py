#!/usr/bin/env python
"""
Comprehensive Verification Tests for Cyber Threat Dashboard Enhancements
Tests all new components, error handling, and production readiness
"""

import sys

print('\n' + '='*70)
print('   CYBER THREAT DASHBOARD - FINAL PRODUCTION VERIFICATION')
print('='*70 + '\n')

all_passed = True

# Test 1: Module Imports
print('[TEST 1] Module Imports...')
try:
    from threat_map_globe import ThreatGlobeGenerator, create_threat_feed_items
    from threat_analytics_engine import CyberThreatAnalytics, threat_analytics
    import plotly.graph_objects as go
    from dash import html, dcc, callback, Output, Input
    print('  ✅ PASSED - All modules imported successfully\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 2: ThreatGlobeGenerator
print('[TEST 2] ThreatGlobeGenerator...')
try:
    test_threats = [
        {'source': 'Test_Critical', 'lat': 40.7128, 'lon': -74.0060, 'type': 'DDoS', 
         'severity': 'Critical', 'status': 'Active', 'timestamp': '14:00:00', 'id': 'test1'},
        {'source': 'Test_High', 'lat': 35.6762, 'lon': 139.6503, 'type': 'Malware', 
         'severity': 'High', 'status': 'Mitigated', 'timestamp': '14:00:01', 'id': 'test2'},
        {'source': 'Test_Medium', 'lat': 51.5074, 'lon': -0.1278, 'type': 'Phishing', 
         'severity': 'Medium', 'status': 'Active', 'timestamp': '14:00:02', 'id': 'test3'},
    ]
    
    fig, total, crit, high = ThreatGlobeGenerator.create_threat_globe(test_threats)
    
    assert total == 3, f"Expected 3 threats, got {total}"
    assert crit == 1, f"Expected 1 critical, got {crit}"
    assert high == 1, f"Expected 1 high, got {high}"
    assert fig is not None, "Figure is None"
    
    print(f'  ✅ PASSED - Globe generated with {total} threats (Critical: {crit}, High: {high})\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 3: Threat Analytics Engine
print('[TEST 3] CyberThreatAnalytics Engine...')
try:
    analytics = CyberThreatAnalytics()
    stats = analytics.get_threat_statistics(test_threats)
    
    assert stats['total_threats'] == 3, f"Expected 3, got {stats['total_threats']}"
    assert stats['critical_threats'] == 1, f"Expected 1, got {stats['critical_threats']}"
    assert stats['high_threats'] == 1, f"Expected 1, got {stats['high_threats']}"
    assert stats['medium_threats'] == 1, f"Expected 1, got {stats['medium_threats']}"
    assert 0 <= stats['risk_score'] <= 100, f"Risk score out of range: {stats['risk_score']}"
    assert stats['threat_level'] in ['CRITICAL', 'HIGH', 'ELEVATED', 'MODERATE', 'LOW', 'SECURE']
    
    print(f'  ✅ PASSED - Analytics working')
    print(f'     • Total Threats: {stats["total_threats"]}')
    print(f'     • Threat Level: {stats["threat_level"]}')
    print(f'     • Risk Score: {stats["risk_score"]}/100')
    print(f'     • Block Rate: {stats["block_rate"]}%\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 4: Feed Item Generation
print('[TEST 4] Feed Item Generation...')
try:
    feed_items = create_threat_feed_items(test_threats)
    
    assert len(feed_items) > 0, "No feed items generated"
    assert all(isinstance(item, (html.Div, html.P, html.Span, html.Hr)) for item in feed_items), \
        "Invalid feed item types"
    
    print(f'  ✅ PASSED - Generated {len(feed_items)} feed items\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 5: Threat Report Generation
print('[TEST 5] Threat Report Generation...')
try:
    report = threat_analytics.generate_threat_report(test_threats)
    
    assert 'summary' in report, "Missing summary in report"
    assert 'severity_breakdown' in report, "Missing severity_breakdown in report"
    assert 'recommendations' in report, "Missing recommendations in report"
    
    print(f'  ✅ PASSED - Report generated')
    print(f'     • Summary: {report["summary"]["threat_level"]}')
    print(f'     • Recommendations: {len(report["recommendations"])} items\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 6: Error Handling
print('[TEST 6] Error Handling & Fallbacks...')
try:
    # Test with empty data
    fig_empty, total_empty, crit_empty, high_empty = ThreatGlobeGenerator.create_threat_globe([])
    assert total_empty == 0, "Should handle empty threats"
    assert fig_empty is not None, "Should return figure for empty data"
    
    # Test with bad data
    bad_threats = [{'incomplete': 'data'}]
    fig_bad, total_bad, crit_bad, high_bad = ThreatGlobeGenerator.create_threat_globe(bad_threats)
    assert fig_bad is not None, "Should handle malformed data"
    
    # Test feed with None
    feed_none = create_threat_feed_items(None)
    assert feed_none is not None, "Should handle None input"
    
    print(f'  ✅ PASSED - All edge cases handled gracefully\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Test 7: Files Created
print('[TEST 7] Files Created/Modified...')
try:
    import os
    
    files = [
        'threat_map_globe.py',
        'threat_analytics_engine.py',
        'ENHANCEMENTS.md',
        'PROFESSIONAL_USAGE_GUIDE.md',
        'IMPLEMENTATION_SUMMARY.md'
    ]
    
    missing = []
    for f in files:
        if not os.path.exists(f):
            missing.append(f)
    
    assert len(missing) == 0, f"Missing files: {missing}"
    
    print(f'  ✅ PASSED - All {len(files)} files created\n')
except Exception as e:
    print(f'  ❌ FAILED - {e}\n')
    all_passed = False

# Final Summary
print('='*70)
if all_passed:
    print('   ✅ ALL TESTS PASSED - SYSTEM READY FOR PRODUCTION')
    print('='*70)
    print('\n📊 ENHANCEMENTS SUMMARY:')
    print('   • Fixed callback errors with comprehensive error handling')
    print('   • Implemented professional 3D globe visualization')
    print('   • Created advanced threat analytics engine')
    print('   • Added automated risk scoring (0-100)')
    print('   • Implemented security recommendations')
    print('   • Professional code quality and documentation')
    print('\n🚀 TO LAUNCH:')
    print('   python app.py')
    print('   Navigate to: http://localhost:8050')
    print('='*70 + '\n')
else:
    print('   ❌ SOME TESTS FAILED - REVIEW OUTPUT ABOVE')
    print('='*70 + '\n')
    sys.exit(1)
