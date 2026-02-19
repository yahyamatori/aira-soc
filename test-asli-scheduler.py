import asyncio
from schedulers.monitor_scheduler import check_attacks_job
from telegram.ext import Application

async def run_scheduler():
    print("=" * 50)
    print("MENJALANKAN SCHEDULER MANUAL")
    print("=" * 50)
    
    app = Application.builder().token("dummy").build()
    await check_attacks_job(app)
    
    # Cek database setelah scheduler jalan
    from core.database import DatabaseManager
    db = DatabaseManager()
    alerts = db.get_recent_alerts(limit=10)
    print(f"\n📊 ALERT DI DATABASE: {len(alerts)}")
    for a in alerts:
        print(f"  - {a.timestamp}: {a.alert_type} ({a.attack_count}) dari threshold {a.threshold}")
    db.close()

asyncio.run(run_scheduler())
exit()
