import asyncio
from schedulers.monitor_scheduler import check_attacks_job
from telegram.ext import Application

async def test_scheduler():
    print("=" * 50)
    print("TEST SCHEDULER MANUAL")
    print("=" * 50)
    
    # Buat application dummy
    app = Application.builder().token("dummy").build()
    
    # Jalankan job
    print("🔍 Menjalankan check_attacks_job...")
    await check_attacks_job(app)
    print("✅ Selesai")
    
    # Cek database
    from core.database import DatabaseManager
    db = DatabaseManager()
    alerts = db.get_recent_alerts(limit=5)
    print(f"\n📊 Alert di database: {len(alerts)}")
    for alert in alerts:
        print(f"   - {alert.timestamp}: {alert.alert_type} ({alert.attack_count})")
    db.close()

# Jalankan
asyncio.run(test_scheduler())
exit()
