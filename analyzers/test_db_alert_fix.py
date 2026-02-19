#!/usr/bin/env python
# TEST ALERT LANGSUNG DARI DATABASE - FIXED

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from datetime import datetime, timedelta
from core.models import AttackLog
import time

print("=" * 70)
print("TEST ALERT LANGSUNG DARI DATABASE - FIXED")
print("=" * 70)

db = DatabaseManager()

# 1. HAPUS DATA LAMA (optional, untuk bersih-bersih)
print("🧹 Membersihkan data test lama...")
db.db.query(AttackLog).filter(AttackLog.raw_data == "Test alert debugging").delete()
db.db.commit()

# 2. CEK THRESHOLD
thresholds = db.get_thresholds()
print(f"📊 Threshold: {thresholds}")

# 3. TAMBAH DATA TEST dengan timestamp SEKARANG
print(f"\n📝 Menambahkan data test dengan timestamp NOW...")

now = datetime.now()
test_attacks = [
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},
    {'src_ip': '192.168.1.100', 'attack_type': 'suspicious_request', 'count': 1},  # total 5
    {'src_ip': '10.0.0.50', 'attack_type': 'suspicious_request', 'count': 1}
]

for i, att in enumerate(test_attacks):
    attack_data = {
        'timestamp': now - timedelta(seconds=30*i),  # masing-masing beda 30 detik
        'attack_type': att['attack_type'],
        'src_ip': att['src_ip'],
        'dst_ip': '192.168.1.1',
        'severity': 'medium',
        'count': att['count'],
        'raw_data': 'Test alert debugging'
    }
    db.save_attack_log(attack_data)
    print(f"   ✅ {att['src_ip']} - {att['attack_type']} ditambahkan (t-{30*i} detik)")

# 4. VERIFIKASI DATA MASUK
total = db.db.query(AttackLog).filter(AttackLog.raw_data == "Test alert debugging").count()
print(f"\n✅ Total data test di database: {total}")

# 5. AMBIL DATA 5 MENIT TERAKHIR
time_threshold = datetime.now() - timedelta(minutes=5)
attacks_db = db.db.query(AttackLog).filter(
    AttackLog.timestamp >= time_threshold,
    AttackLog.raw_data == "Test alert debugging"
).all()

print(f"\n📊 Data di database 5 menit terakhir: {len(attacks_db)}")

# 6. HITUNG MANUAL PER IP
ip_count = {}
for att in attacks_db:
    ip = att.src_ip
    atype = att.attack_type
    key = f"{ip}_{atype}"
    if key in ip_count:
        ip_count[key] += att.count
    else:
        ip_count[key] = att.count

print(f"\n🔍 Hitung manual:")
alerts_created = []

for key, count in ip_count.items():
    # Split hanya untuk 2 bagian pertama
    parts = key.split('_')
    ip = parts[0]
    atype = '_'.join(parts[1:])  # Gabungkan kembali sisanya

    threshold = thresholds.get(atype, 999999)
    print(f"  {ip} - {atype}: {count}x (threshold {threshold})")

    if count >= threshold:
        print(f"    ⚠️ ALERT! {count} >= {threshold}")

        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': atype,
            'message': f"TEST ALERT: {atype} from {ip} ({count} attempts)",
            'severity': 'high',
            'attack_count': count,
            'threshold': threshold
        }
        db.save_alert(alert_data)
        alerts_created.append(alert_data)
    else:
        print(f"    ✓ Normal ({count} < {threshold})")

print(f"\n📊 Total alert dibuat: {len(alerts_created)}")

# 7. CEK TABEL ALERTS
alerts_db = db.get_recent_alerts(limit=10)
print(f"\n📊 Alert di database sekarang: {len(alerts_db)}")
for a in alerts_db:
    print(f"  • {a.timestamp}: {a.alert_type} - {a.attack_count} attempts (threshold {a.threshold})")

# 8. CLEANUP (HAPUS DATA TEST)
print(f"\n🧹 Membersihkan data test...")
db.db.query(AttackLog).filter(AttackLog.raw_data == "Test alert debugging").delete()
db.db.commit()
print(f"✅ Database dibersihkan")

db.close()
print("=" * 70)