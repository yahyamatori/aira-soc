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
try:
    from config.settings import MONITOR_INTERVAL, DEBUG_MODE, TIMEZONE
except ImportError:
    MONITOR_INTERVAL = 300
    DEBUG_MODE = False
    TIMEZONE = 'Asia/Jakarta'

logger = logging.getLogger(__name__)

# Setup debug logging
if DEBUG_MODE:
    logging.getLogger().setLevel(logging.DEBUG)

scheduler = AsyncIOScheduler()
monitoring_job = None
_telegram_app = None


def set_telegram_app(application):
    global _telegram_app
    _telegram_app = application
    logger.info("Telegram app terdaftar untuk scheduler")


async def check_attacks_job():
    """
    Job utama: analisis log dan simpan serangan ke database,
    lalu kirim alert ke Telegram jika threshold exceeded
    """
    logger.info("🔍 Running scheduled attack check...")
    
    # Step 1: Test koneksi Elasticsearch
    try:
        es = ElasticConnector()
        if not es.test_connection():
            logger.warning("⚠️ Elasticsearch tidak tersedia, skip analysis")
            return
        logger.debug("✓ Elasticsearch connection OK")
    except Exception as e:
        logger.error(f"❌ Gagal koneksi Elasticsearch: {e}")
        return

    analyzer = AttackAnalyzer(es)

    # Step 2: Ambil dan analisis log dari Elasticsearch
    try:
        # Analisis serangan dalam 5 menit terakhir
        attacks = analyzer.analyze_period(minutes=5)
        logger.info(f"📊 Ditemukan {len(attacks)} attack patterns dalam 5 menit")
        
        if DEBUG_MODE:
            for attack in attacks[:5]:  # Show first 5
                logger.debug(f"   - {attack.get('attack_type')}: {attack.get('src_ip')} x{attack.get('count')}")

    except Exception as e:
        logger.error(f"❌ Error saat analisis attacks: {e}")
        return

    # Step 3: Simpan SEMUA serangan ke database (bukan hanya yang exceed threshold)
    if attacks:
        try:
            db = DatabaseManager()
            
            # Prepare attacks for database
            db_attacks = []
            for attack in attacks:
                # Handle timestamp - remove timezone for MySQL
                timestamp = attack.get('timestamp')
                if timestamp:
                    if hasattr(timestamp, 'tzinfo') and timestamp.tzinfo is not None:
                        timestamp = timestamp.replace(tzinfo=None)
                    elif isinstance(timestamp, str):
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            timestamp = dt.replace(tzinfo=None)
                        except:
                            timestamp = datetime.now()
                
                db_attack = {
                    'timestamp': timestamp,
                    'attack_type': attack.get('attack_type'),
                    'src_ip': attack.get('src_ip'),
                    'dst_ip': attack.get('dst_ip'),
                    'dst_port': attack.get('dst_port'),
                    'protocol': attack.get('protocol', 'tcp'),
                    'severity': attack.get('severity', 'medium'),
                    'count': attack.get('count', 1),
                    'raw_data': str(attack.get('raw_data', ''))[:500],
                    'hostname': attack.get('hostname')  # Server yang diserang
                }
                db_attacks.append(db_attack)
            
            saved_count = db.save_attack_logs_bulk(db_attacks)
            db.close()
            logger.info(f"💾 {saved_count} attack logs disimpan ke database")
            
        except Exception as e:
            logger.error(f"❌ Error simpan attack logs: {e}")

    # Step 4: Cek threshold dan generate alerts
    try:
        alerts = analyzer.check_thresholds(minutes=5)
        
        if alerts:
            logger.info(f"🚨 {len(alerts)} alerts melebihi threshold!")
            
            db = DatabaseManager()
            
            for alert in alerts:
                # Simpan alert ke database
                db.save_alert({
                    'timestamp': datetime.now(),
                    'alert_type': alert['type'],
                    'message': f"Alert: {alert['type']} dari {alert['ip']} ({alert['count']} percobaan)",
                    'severity': alert['severity'],
                    'attack_count': alert['count'],
                    'threshold': alert['threshold']
                })
                
                # Kirim ke Telegram jika app tersedia
                if _telegram_app:
                    try:
                        from telegram_bot.alerts import send_alert
                        await send_alert(_telegram_app, alert)
                        logger.info(f"📱 Alert dikirim ke Telegram: {alert['type']} dari {alert['ip']}")
                    except Exception as e:
                        logger.error(f"❌ Gagal kirim Telegram: {e}")
            
            db.close()
        else:
            logger.debug("✓ Tidak ada alert threshold yang exceeded")
            
    except Exception as e:
        logger.error(f"❌ Error proses alert: {e}")

    logger.info("✅ Scheduled check complete")


def start_scheduler(application=None):
    global scheduler, monitoring_job
    if application:
        set_telegram_app(application)
    if scheduler.running:
        logger.warning("Scheduler sudah berjalan!")
        return
    
    monitoring_job = scheduler.add_job(
        check_attacks_job,
        trigger=IntervalTrigger(seconds=MONITOR_INTERVAL),
        id='check_attacks',
        replace_existing=True,
        next_run_time=datetime.now()
    )
    scheduler.start()
    logger.info(f"✅ Scheduler dimulai – interval {MONITOR_INTERVAL}s ({MONITOR_INTERVAL//60} menit)")


def stop_scheduler():
    global scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("⏹ Scheduler dihentikan")


def get_scheduler_status() -> dict:
    return {
        'running': scheduler.running,
        'jobs': len(scheduler.get_jobs()),
        'next_run': monitoring_job.next_run_time if monitoring_job else None,
        'telegram_ready': _telegram_app is not None,
        'interval_seconds': MONITOR_INTERVAL,
    }

