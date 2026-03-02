"""
Scheduler untuk monitoring realtime dan alert
- Berjalan OTOMATIS tanpa perlu trigger dari Telegram
- Telegram hanya digunakan untuk mengirim notifikasi (opsional)
"""
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime

from core.elastic_connector import ElasticConnector
from core.database import DatabaseManager
from analyzers.attack_analyzer import AttackAnalyzer
from config.settings import MONITOR_INTERVAL

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()
monitoring_job = None
_telegram_app = None


def set_telegram_app(application):
    global _telegram_app
    _telegram_app = application
    logger.info("Telegram app terdaftar")


async def check_attacks_job():
    """Main job yang dijalankan secara terjadwal untuk memeriksa serangan dan alerts"""
    logger.info("Running scheduled attack check...")
    
    # Gunakan satu DatabaseManager instance untuk semua operasi
    db = None
    
    try:
        # Step 1: Koneksi ke Elasticsearch
        try:
            es = ElasticConnector()
            if not es.test_connection():
                logger.warning("Elasticsearch tidak tersedia")
                return
        except Exception as e:
            logger.error(f"Gagal koneksi Elasticsearch: {e}")
            return

        analyzer = AttackAnalyzer(es)

        # Step 2: Analisa dan simpan attack logs (SEMUA serangan, tidak hanya yang exceed threshold)
        try:
            # Gunakan window 30 menit untuk menangkap lebih banyak serangan
            attacks = analyzer.analyze_period(minutes=30)
            if attacks:
                # Prepare attacks for database (remove hostname field like handler does)
                db_attacks = []
                for attack in attacks:
                    db_attack = {
                        'timestamp': attack['timestamp'],
                        'attack_type': attack['attack_type'],
                        'src_ip': attack['src_ip'],
                        'dst_ip': attack.get('dst_ip'),
                        'src_port': attack.get('src_port'),
                        'dst_port': attack.get('dst_port'),
                        'protocol': attack.get('protocol', 'tcp'),
                        'severity': attack['severity'],
                        'count': attack['count'],
                        'raw_data': attack.get('raw_data', '')
                    }
                    db_attacks.append(db_attack)
                
                db = DatabaseManager()
                saved_count = db.save_attack_logs_bulk(db_attacks)
                logger.info(f"{saved_count} attack logs tersimpan")
            else:
                logger.debug("Tidak ada attack patterns ditemukan dalam 30 menit")
        except Exception as e:
            logger.error(f"Error simpan attack logs: {e}")

        # Step 3: Check thresholds dan generate alerts (untuk alerting real-time)
        try:
            alerts = analyzer.check_thresholds(minutes=5)
            if not alerts:
                logger.debug("Tidak ada alert yang melebihi threshold")
                return

            # Initialize DB if not already done
            if db is None:
                db = DatabaseManager()
            
            # Simpan alerts ke database
            for alert in alerts:
                db.save_alert({
                    'timestamp':    datetime.now(),
                    'alert_type':   alert['type'],
                    'message':      f"Alert: {alert['type']} dari {alert['ip']} ({alert['count']} percobaan)",
                    'severity':     alert['severity'],
                    'attack_count': alert['count'],
                    'threshold':    alert['threshold']
                })
                logger.info(f"Alert tersimpan: {alert['type']} dari {alert['ip']}")
                
                # Kirim ke Telegram jika tersedia
                if _telegram_app:
                    try:
                        from telegram_bot.alerts import send_alert
                        await send_alert(_telegram_app, alert)
                    except Exception as e:
                        logger.error(f"Gagal kirim Telegram: {e}")
            
            logger.info(f"{len(alerts)} alerts diproses")
            
        except Exception as e:
            logger.error(f"Error proses alert: {e}")
            
    finally:
        # Always close database connection
        if db is not None:
            try:
                db.close()
            except Exception as e:
                logger.error(f"Error menutup database: {e}")


def start_scheduler(application=None):
    global scheduler, monitoring_job
    if application:
        set_telegram_app(application)
    if scheduler.running:
        logger.warning("Scheduler sudah berjalan")
        return
    monitoring_job = scheduler.add_job(
        check_attacks_job,
        trigger=IntervalTrigger(seconds=MONITOR_INTERVAL),
        id='check_attacks',
        replace_existing=True,
        next_run_time=datetime.now()
    )
    scheduler.start()
    logger.info(f"Scheduler berjalan – interval {MONITOR_INTERVAL}s")


def stop_scheduler():
    global scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler dihentikan")


def get_scheduler_status() -> dict:
    return {
        'running':          scheduler.running,
        'jobs':             len(scheduler.get_jobs()),
        'next_run':         monitoring_job.next_run_time if monitoring_job else None,
        'telegram_ready':   _telegram_app is not None,
        'interval_seconds': MONITOR_INTERVAL,
    }
