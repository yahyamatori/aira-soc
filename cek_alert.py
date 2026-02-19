#!/usr/bin/env python
# Script untuk cek alert di database
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.database import DatabaseManager
from datetime import datetime, timedelta

print("=" * 60)
print("CEK ALERT DI DATABASE")
print("=" * 60)

db = DatabaseManager()

# Cek semua alert
alerts = db.get_recent_alerts(limit=50)
print(f"\n📊 Total Alert di Database: {len(alerts)}")

if alerts:
    print("\n📋 10 Alert Terbaru:")
    print("-" * 60)
    for i, alert in enumerate(alerts[:10], 1):
        print(f"{i}. {alert.timestamp} - {alert.alert_type}")
        print(f"   Severity: {alert.severity}")
        print(f"   Message: {alert.message[:100]}...")
        print(f"   Attack Count: {alert.attack_count}")
        print()

# Cek alert 1 jam terakhir
one_hour_ago = datetime.now() - timedelta(hours=1)
recent_alerts = [a for a in alerts if a.timestamp >= one_hour_ago]
print(f"\n⏱️  Alert 1 Jam Terakhir: {len(recent_alerts)}")

db.close()
print("=" * 60)
