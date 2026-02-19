#!/usr/bin/env python
# Test alert langsung dari database

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from datetime import datetime, timedelta
from core.models import AttackLog

print("=" * 70)
print("TEST ALERT LANGSUNG DARI DATABASE")
print("=" * 70)

db = DatabaseManager()
thresholds = db.get_thresholds()
print(f"📊 Threshold: {thresholds}")

# Ambil 5 menit terakhir dari database
time_threshold = datetime.now() - timedelta(minutes=5)
attacks_db = db.db.query(AttackLog).filter(
    AttackLog.timestamp >= time_threshold
).all()

print(f"\n📊 Data di database 5 menit terakhir: {len(attacks_db)}")

# Hitung per IP
ip_count = {}
for att in attacks_db:
    key = f"{att.src_ip}_{att.attack_type}"
    ip_count[key] = ip_count.get(key, 0) + att.count

print(f"\n🔍 Hitung manual:")
alerts = []
for key, count in ip_count.items():
    ip, atype = key.split('_')
    threshold = thresholds.get(atype, 999999)
    print(f"  {ip} - {atype}: {count}x (threshold {threshold})")
    
    if count >= threshold:
        print(f"    ⚠️ ALERT! {count} >= {threshold}")
        
        # Simpan alert ke database
        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': atype,
            'message': f"ALERT: {atype} from {ip} ({count} attempts)",
            'severity': 'high',
            'attack_count': count,
            'threshold': threshold
        }
        db.save_alert(alert_data)
        alerts.append(alert_data)
    else:
        print(f"    ✓ Normal ({count} < {threshold})")

print(f"\n📊 Total alert dibuat: {len(alerts)}")

# Cek tabel alerts
alerts_db = db.get_recent_alerts(limit=10)
print(f"\n📊 Alert di database sekarang: {len(alerts_db)}")
for a in alerts_db:
    print(f"  • {a.timestamp}: {a.alert_type} - {a.attack_count} attempts")

db.close()
print("=" * 70)
