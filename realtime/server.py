# cyber-threat-dashboard/realtime/server.py
import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_socketio import SocketIO, emit
import random
from datetime import datetime
import threading
import time

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Sample threat types (like your screenshots)
THREAT_TYPES = [
    'Botnet', 'Ransomware', 'Phishing', 'DDoS', 'Malware',
    'SQL Injection', 'XSS', 'Zero-Day', 'Credential Theft',
    'Session Hijacking', 'Rootkit', 'Cryptojacking'
]

COUNTRIES = [
    ('United States', (37.0902, -95.7129)),
    ('China', (35.8617, 104.1954)),
    ('Russia', (61.5240, 105.3188)),
    ('Germany', (51.1657, 10.4515)),
    ('India', (20.5937, 78.9629)),
    ('Brazil', (-14.2350, -51.9253)),
    ('UK', (55.3781, -3.4360)),
    ('France', (46.6034, 1.8883)),
    ('Japan', (36.2048, 138.2529)),
    ('Australia', (-25.2744, 133.7751)),
    ('Seychelles', (-4.6796, 55.4920)),
    ('Switzerland', (46.8182, 8.2275)),
    ('Vietnam', (14.0583, 108.2772)),
    ('Norway', (60.4720, 8.4689)),
    ('Malaysia', (4.2105, 101.9758)),
    ('Morocco', (31.7917, -7.0926)),
    ('Fiji', (-17.7134, 178.0650))
]

# Store active threats
active_threats = []

def generate_random_threat():
    """Generate a realistic threat like your screenshots"""
    country, coords = random.choice(COUNTRIES)
    threat_type = random.choice(THREAT_TYPES)
    
    # Generate realistic IP
    ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    
    # Determine severity based on threat type
    if threat_type in ['Ransomware', 'Zero-Day', 'SQL Injection']:
        severity = 'Critical'
        color = '#ff4444'
    elif threat_type in ['Botnet', 'Rootkit', 'Cryptojacking']:
        severity = 'High'
        color = '#ff6600'
    else:
        severity = 'Medium'
        color = '#ffaa00'
    
    threat = {
        'id': len(active_threats) + 1,
        'country': country,
        'coordinates': coords,
        'threat_type': threat_type,
        'severity': severity,
        'color': color,
        'ip': ip,
        'timestamp': datetime.now().strftime('%I:%M:%S %p'),
        'duration': f"{random.randint(1, 120)}m"
    }
    
    # Keep only last 50 threats
    active_threats.append(threat)
    if len(active_threats) > 50:
        active_threats.pop(0)
    
    return threat

def threat_generator():
    """Background thread to generate threats"""
    while True:
        time.sleep(random.uniform(2, 8))  # Random interval 2-8 seconds
        threat = generate_random_threat()
        
        # Broadcast to all connected clients
        socketio.emit('new_threat', threat)
        print(f"📡 New threat: {threat['threat_type']} from {threat['country']}")

def stats_generator():
    """Send dashboard stats every 5 seconds"""
    while True:
        time.sleep(5)
        stats = {
            'active_threats': len([t for t in active_threats if t['severity'] in ['High', 'Critical']]),
            'blocked': random.randint(40, 60),
            'critical_alerts': len([t for t in active_threats if t['severity'] == 'Critical']),
            'total_scanned': len(active_threats) + random.randint(20, 40),
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }
        socketio.emit('stats_update', stats)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('✅ Client connected')
    emit('connected', {'message': 'Connected to CyberShield Real-time Feed'})

@socketio.on('disconnect')
def handle_disconnect():
    print('❌ Client disconnected')

# Start background threads
threading.Thread(target=threat_generator, daemon=True).start()
threading.Thread(target=stats_generator, daemon=True).start()

if __name__ == '__main__':
    print("🚀 Starting Real-time Threat Server on port 5001")
    print("📡 WebSocket URL: ws://localhost:5001")
    socketio.run(app, port=5001, debug=False)