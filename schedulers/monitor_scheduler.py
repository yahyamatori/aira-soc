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
        logger.info("🔍 Running scheduled attack check...")
        
        # Koneksi ke Elasticsearch
        es = ElasticConnector()
        if not es.test_connection():
            logger.warning("❌ Elasticsearch tidak tersedia")
            return
        
        # Analisis serangan 5 menit terakhir
        analyzer = AttackAnalyzer(es)
        
        # Simpan attack logs ke database (OTOMATIS)
        attacks = analyzer.analyze_period(minutes=5)
        if attacks:
            logger.info(f"📝 Found {len(attacks)} attacks to save")
            db = DatabaseManager()
            saved_count = db.save_attack_logs_bulk(attacks)
            logger.info(f"✅ Saved {saved_count} attack logs to database")
            db.close()
        
        # Cek threshold dan kirim alert
        alerts = analyzer.check_thresholds(minutes=5)
        
        if alerts:
            logger.info(f"🚨 Found {len(alerts)} alerts to send")
            
            db = DatabaseManager()
            for alert in alerts:
                # Kirim ke Telegram
                await send_alert(application, alert)
                
                # Simpan alert ke database
                db.save_alert({
                    'timestamp': datetime.now(),
                    'alert_type': alert['type'],
                    'message': f"Alert: {alert['type']} from {alert['ip']} ({alert['count']} attempts)",
                    'severity': alert['severity'],
                    'attack_count': alert['count'],
                    'threshold': alert['threshold']
                })
                logger.info(f"📝 Alert saved to database: {alert['type']} from {alert['ip']}")
            
            db.close()
        else:
            logger.debug("No alerts found in this check")
            
    except Exception as e:
        logger.error(f"Error in check_attacks_job: {e}")


def start_scheduler(application):
    """Memulai scheduler untuk monitoring realtime"""
    global scheduler, monitoring_job
    
    # Cek apakah scheduler sudah running
    if scheduler.running:
        logger.info("⚠️ Scheduler already running")
        return
    
    # Hapus job lama jika ada
    if monitoring_job:
        try:
            monitoring_job.remove()
        except:
            pass
    
    # Tambahkan job baru
    monitoring_job = scheduler.add_job(
        check_attacks_job,
        trigger=IntervalTrigger(seconds=MONITOR_INTERVAL),
        args=[application],
        id='check_attacks',
        replace_existing=True
    )
    
    # Mulai scheduler
    scheduler.start()
    logger.info(f"✅ Scheduler started with interval {MONITOR_INTERVAL} seconds")
    logger.info(f"📊 Akan cek alert setiap {MONITOR_INTERVAL} detik, melihat data 5 menit ke belakang")

def stop_scheduler():
    """Menghentikan scheduler"""
    global scheduler
    
    if scheduler.running:
        scheduler.shutdown()
        logger.info("🛑 Scheduler stopped")

def get_scheduler_status():
    """Mendapatkan status scheduler"""
    return {
        'running': scheduler.running,
        'jobs': len(scheduler.get_jobs()),
        'next_run': monitoring_job.next_run_time if monitoring_job else None
    }
