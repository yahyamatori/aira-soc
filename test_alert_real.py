#!/usr/bin/env python
# Test alert dengan simulasi serangan real

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
import asyncio
from telegram.ext import Application
from schedulers.monitor_scheduler import check_attacks_job

print("=" * 60)
print("TEST ALERT REAL")
print("=" * 60)

# 1. CEK THRESHOLD
db = DatabaseManager()
thresholds = db.get_thresholds()
print(f"📊 Threshold: {thresholds}")

# 2. JALANKAN CHECK THRESHOLDS MANUAL
es = ElasticConnector()
analyzer = AttackAnalyzer(es)
alerts = analyzer.check_thresholds(minutes=5)
print(f"\n📊 Alert dari check_thresholds(): {len(alerts)}")

if alerts:
    print("\n🚨 ALERT DITEMUKAN!")
    for a in alerts:
        print(f"  • {a['ip']} - {a['type']}: {a['count']} >= {a['threshold']}")
        
        # Simulasi kirim ke Telegram
        print(f"    Akan dikirim ke Telegram: {a}")
else:
    print("\n✅ Tidak ada alert - sistem berjalan normal")

# 3. CEK DATABASE
alerts_db = db.get_recent_alerts(limit=10)
print(f"\n📊 Alert di database: {len(alerts_db)}")
for a in alerts_db:
    print(f"  • {a.timestamp}: {a.alert_type} - {a.message[:50]}...")

db.close()
print("=" * 60)
