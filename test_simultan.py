#!/usr/bin/env python
# Test alert untuk serangan simultan

from core.database import DatabaseManager
from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from datetime import datetime, timedelta

print("=" * 60)
print("TEST SERANGAN SIMULTAN")
print("=" * 60)

# Set threshold ke 2 untuk test
db = DatabaseManager()
db.update_threshold('suspicious_request', 2, 'test')

# Simulasi serangan dari IP yang sama
test_attacks = [
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},  # total 3
    {'src_ip': '10.0.0.50', 'attack_type': 'suspicious_request', 'count': 1}  # IP lain, total 1
]

# Simpan ke database (simulasi)
for att in test_attacks:
    attack_data = {
        'timestamp': datetime.now() - timedelta(minutes=2),
        'attack_type': att['attack_type'],
        'src_ip': att['src_ip'],
        'dst_ip': '192.168.1.1',
        'severity': 'medium',
        'count': att['count'],
        'raw_data': 'Test'
    }
    db.save_attack_log(attack_data)

# Jalankan analyzer
es = ElasticConnector()
analyzer = AttackAnalyzer(es)
alerts = analyzer.check_thresholds(minutes=5)

print(f"\n📊 Alert dihasilkan: {len(alerts)}")
for alert in alerts:
    print(f"  🚨 {alert['type']} dari {alert['ip']}: {alert['count']} >= {alert['threshold']}")

db.close()
print("=" * 60)
