#!/usr/bin/env python
# TEST ALERT FINAL - VERSION FIX

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from datetime import datetime
import asyncio
from telegram.ext import Application

print("=" * 60)
print("TEST ALERT FINAL")
print("=" * 60)

# 1. CEK THRESHOLD
db = DatabaseManager()
thresholds = db.get_thresholds()
print(f"\n📊 Threshold saat ini:")
for k, v in thresholds.items():
    print(f"  {k}: {v}")

# 2. CEK SERANGAN 5 MENIT TERAKHIR
es = ElasticConnector()
analyzer = AttackAnalyzer(es)
attacks = analyzer.analyze_period(minutes=5)
print(f"\n📊 Serangan 5 menit terakhir: {len(attacks)}")

# 3. HITUNG MANUAL
print(f"\n🔍 Detail serangan:")
for attack in attacks:
    ip = attack.get('src_ip', 'Unknown')
    atype = attack.get('attack_type', 'unknown')
    count = attack.get('count', 1)
    threshold = thresholds.get(atype, 999999)
    
    print(f"  {ip} - {atype}: {count} attempts")
    if count > threshold:
        print(f"    ⚠️ MELEBIHI THRESHOLD ({count} > {threshold})")
    else:
        print(f"    ✓ Normal ({count} <= {threshold})")

# 4. JALANKAN CHECK THRESHOLDS
print(f"\n🔍 Menjalankan check_thresholds()...")
alerts = analyzer.check_thresholds(minutes=5)
print(f"✅ Alert dihasilkan: {len(alerts)}")

for alert in alerts:
    print(f"  🚨 {alert['type']} dari {alert['ip']}: {alert['count']} > {alert['threshold']}")

# 5. CEK DATABASE
print(f"\n📊 Alert di database:")
alerts_db = db.get_recent_alerts(limit=10)
print(f"  Total: {len(alerts_db)}")

for a in alerts_db:
    print(f"  • {a.timestamp}: {a.alert_type} - {a.attack_count} attempts (threshold {a.threshold})")

# 6. JIKA TIDAK ADA ALERT, PAKSA DENGAN SIMULASI
if len(alerts) == 0 and len(attacks) > 0:
    print(f"\n⚠️ TIDAK ADA ALERT MESKIPUN ADA SERANGAN!")
    print(f"   Kemungkinan: ada bug di logika check_thresholds")
    
    # Buat alert manual langsung ke database
    print(f"\n🔄 Membuat alert manual untuk test...")
    
    for attack in attacks:
        ip = attack.get('src_ip', 'Unknown')
        atype = attack.get('attack_type', 'unknown')
        count = attack.get('count', 1)
        threshold = thresholds.get(atype, 999999)
        
        alert_data = {
            'timestamp': datetime.now(),
            'alert_type': atype,
            'message': f"TEST MANUAL: {atype} from {ip} ({count} attempts)",
            'severity': attack.get('severity', 'medium'),
            'attack_count': count,
            'threshold': threshold
        }
        
        db.save_alert(alert_data)
        print(f"  ✅ Alert manual ditambahkan: {atype} dari {ip}")

# 7. CEK DATABASE LAGI
print(f"\n📊 Alert di database (setelah simulasi):")
alerts_db = db.get_recent_alerts(limit=10)
print(f"  Total: {len(alerts_db)}")

for a in alerts_db:
    print(f"  • {a.timestamp}: {a.alert_type} - {a.attack_count} attempts")

db.close()
print("=" * 60)
