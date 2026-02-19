#!/usr/bin/env python
# Script debug untuk mencari tahu kenapa alert tidak muncul

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from datetime import datetime, timedelta

print("=" * 70)
print("DEBUG ALERT - MENCARI TAHU KENAPA ALERT TIDAK MUNCUL")
print("=" * 70)

# 1. CEK KONEKSI DATABASE
db = DatabaseManager()
print(f"\n📊 1. KONEKSI DATABASE: ✅ OK")

# 2. CEK THRESHOLD DI DATABASE
thresholds = db.get_thresholds()
print(f"\n📊 2. THRESHOLD SAAT INI:")
for k, v in thresholds.items():
    print(f"   {k}: {v}")

# 3. SIMULASI TAMBAH SERANGAN
print(f"\n📝 3. MENAMBAHKAN SERANGAN TEST...")

test_attacks = [
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},  # total 3
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},  # total 4
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},  # total 5
    {'src_ip': '10.0.0.50', 'attack_type': 'suspicious_request', 'count': 1}
]

for att in test_attacks:
    attack_data = {
        'timestamp': datetime.now() - timedelta(minutes=2),
        'attack_type': att['attack_type'],
        'src_ip': att['src_ip'],
        'dst_ip': '192.168.1.1',
        'severity': 'medium',
        'count': att['count'],
        'raw_data': 'Test alert debugging'
    }
    db.save_attack_log(attack_data)
    print(f"   ✅ {att['src_ip']} - {att['attack_type']} ditambahkan")

print(f"\n🔍 4. MENGAMBIL DATA DARI DATABASE LANGSUNG...")
from core.models import AttackLog
recent = db.db.query(AttackLog).order_by(AttackLog.timestamp.desc()).limit(10).all()
print(f"   Total data di attack_logs: {len(recent)}")
for r in recent[:5]:
    print(f"   • {r.timestamp}: {r.src_ip} - {r.attack_type} ({r.count})")

# 5. TEST ANALYZER DENGAN DATABASE
print(f"\n🔍 5. MENJALANKAN ANALYZER DARI DATABASE...")

# Buat analyzer tanpa Elasticsearch (gunakan data dari database)
es = ElasticConnector()
analyzer = AttackAnalyzer(es)

# TAPI kita perlu mensimulasi data dari Elasticsearch
# Untuk test, kita akan panggil analyze_period dan lihat hasilnya
attacks = analyzer.analyze_period(minutes=10)  # Ambil 10 menit terakhir

print(f"   Hasil analyze_period(): {len(attacks)} serangan ditemukan")
for a in attacks:
    print(f"   • {a['src_ip']} - {a['attack_type']}: {a['count']}x")

# 6. CEK THRESHOLD MANUAL
print(f"\n🔍 6. CEK THRESHOLD MANUAL:")
threshold_val = thresholds.get('suspicious_request', 999999)
print(f"   Threshold suspicious_request: {threshold_val}")

# Hitung manual per IP dari attacks
ip_counter = {}
for a in attacks:
    if a['attack_type'] == 'suspicious_request':
        ip = a['src_ip']
        ip_counter[ip] = ip_counter.get(ip, 0) + a['count']

print(f"\n   Hasil hitung manual per IP:")
for ip, count in ip_counter.items():
    print(f"   • {ip}: {count} serangan")
    if count >= threshold_val:
        print(f"     ⚠️ MELEBIHI THRESHOLD! ({count} >= {threshold_val})")
    else:
        print(f"     ✓ Normal ({count} < {threshold_val})")

# 7. JALANKAN CHECK_THRESHOLDS
print(f"\n🔍 7. MENJALANKAN CHECK_THRESHOLDS():")
alerts = analyzer.check_thresholds(minutes=10)
print(f"   Alert dihasilkan: {len(alerts)}")

for alert in alerts:
    print(f"   🚨 {alert['type']} dari {alert['ip']}: {alert['count']} >= {alert['threshold']}")

# 8. CEK TABEL ALERTS
print(f"\n📊 8. CEK TABEL ALERTS:")
alerts_db = db.get_recent_alerts(limit=10)
print(f"   Total alert di database: {len(alerts_db)}")
for a in alerts_db:
    print(f"   • {a.timestamp}: {a.alert_type} - {a.attack_count} attempts")

db.close()
print("=" * 70)
