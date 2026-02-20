import sqlite3
import os

db_path = "test_threat_intel.db"
if os.path.exists(db_path):
    os.remove(db_path)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            type TEXT,
            severity TEXT,
            source_ip TEXT,
            country TEXT,
            status TEXT
        )
    ''')
    
    # Simulate seeding
    sample_data = [
        ('2026-02-18 10:00:00', 'SQL Injection', 'Critical', '1.1.1.1', 'USA', 'Blocked'),
        ('2026-02-18 10:05:00', 'Phishing', 'High', '2.2.2.2', 'China', 'Investigating')
    ]
    cursor.executemany('''
        INSERT INTO threat_incidents (timestamp, type, severity, source_ip, country, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', sample_data)
    
    conn.commit()
    
    cursor.execute("SELECT COUNT(*) FROM threat_incidents")
    count = cursor.fetchone()[0]
    
    print(f"VERIFICATION SUCCESS: Created DB and found {count} records.")
    conn.close()
finally:
    if os.path.exists(db_path):
        os.remove(db_path)
