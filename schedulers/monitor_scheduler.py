"""Scheduler untuk monitoring realtime dan alert"""
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import asyncio

from core.elastic_connector import ElasticConnector
from core.database import DatabaseManager
from analyzers.attack_analyzer import AttackAnalyzer
from telegram_bot.alerts import send_alert
from config.settings import MONITOR_INTERVAL

logger = logging.getLogger(__name__)

# Inisialisasi scheduler
scheduler = AsyncIOScheduler()
monitoring_job = None


async def check_attacks_job(application):
    """Job untuk mengecek serangan secara periodik"""
    try:
        logger.info("Running scheduled attack check...")

        # Koneksi ke Elasticsearch
        es = ElasticConnector()
        if not es.test_connection():
            logger.warning("Elasticsearch tidak tersedia")
            return

        # Analisis serangan
        analyzer = AttackAnalyzer(es)
        alerts = analyzer.check_thresholds(minutes=5)  # Cek 5 menit terakhir

        if alerts:
            logger.info(f"Found {len(alerts)} alerts to send")

            # Kirim alert ke Telegram
            for alert in alerts:
                await send_alert(application, alert)

                # Simpan ke database
                db = DatabaseManager()
                db.save_alert({
                    'timestamp': datetime.now(),
                    'alert_type': alert['type'],
                    'message': f"Alert: {alert['type']} from {alert['ip']}",
                    'severity': alert['severity'],
                    'attack_count': alert['count'],
                    'threshold': alert['threshold']
                })
                db.close()
        else:
            logger.debug("No alerts found")

    except Exception as e:
        logger.error(f"Error in check_attacks_job: {e}")


def start_scheduler(application):
    """Memulai scheduler untuk monitoring realtime"""
    global scheduler, monitoring_job

    if scheduler.running:
        logger.info("Scheduler already running")
        return

    # Tambahkan job untuk cek serangan setiap MONITOR_INTERVAL detik
    monitoring_job = scheduler.add_job(
        check_attacks_job,
        trigger=IntervalTrigger(seconds=MONITOR_INTERVAL),
        args=[application],
        id='check_attacks',
        replace_existing=True
    )

    # Mulai scheduler
    scheduler.start()
    logger.info(f"Scheduler started with interval {MONITOR_INTERVAL} seconds")


def stop_scheduler():
    """Menghentikan scheduler"""
    global scheduler

    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")


def get_scheduler_status():
    """Mendapatkan status scheduler"""
    return {
        'running': scheduler.running,
        'jobs': len(scheduler.get_jobs()),
        'next_run': monitoring_job.next_run_time if monitoring_job else None
    }

# Untuk testing manual


async def manual_check():
    """Fungsi untuk testing manual"""
    print("Running manual check...")
    es = ElasticConnector()
    analyzer = AttackAnalyzer(es)
    alerts = analyzer.check_thresholds(minutes=5)
    print(f"Found {len(alerts)} alerts")

if __name__ == "__main__":
    # Untuk testing
    asyncio.run(manual_check())
