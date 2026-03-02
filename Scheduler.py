"""
Scheduler untuk monitoring realtime dan alert
- Berjalan OTOMATIS tanpa perlu trigger dari Telegram
- Telegram hanya digunakan untuk mengirim notifikasi (opsional)
"""
import logging
import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime

from core.elastic_connector import ElasticConnector
from core.database import DatabaseManager
from analyzers.attack_analyzer import AttackAnalyzer
from config.settings import MONITOR_INTERVAL

logger = logging.getLogger(__name__)

# ─── State Global ────────────────────────────────────────────────────────────
scheduler = AsyncIOScheduler()
monitoring_job = None
_telegram_app = None          # Opsional – diisi setelah bot siap


# ─── Registrasi Telegram App ─────────────────────────────────────────────────
def set_telegram_app(application):
    """
    Daftarkan telegram application setelah bot siap.
    Scheduler tetap jalan meski fungsi ini belum dipanggil.
    """
    global _telegram_app
    _telegram_app = application
    logger.info("✅ Telegram app terdaftar – alert akan dikirim via Telegram")


# ─── Core Job ────────────────────────────────────────────────────────────────
async def check_attacks_job():
    """
    Job utama – dijalankan setiap MONITOR_INTERVAL detik.
    Tidak memerlukan parameter apapun sehingga bisa dipanggil
    oleh scheduler tanpa bergantung pada Telegram bot.
    """
    logger.info("🔍 [Scheduler] Running scheduled attack check...")

    # 1. Koneksi ke Elasticsearch
    try:
        es = ElasticConnector()
        if not es.test_connection():
            logger.warning("❌ Elasticsearch tidak tersedia, skip cycle ini")
            return
    except Exception as e:
        logger.error(f"❌ Gagal koneksi ke Elasticsearch: {e}")
        return

    analyzer = AttackAnalyzer(es)

    # ── 2. Simpan semua attack logs ke database ───────────────────────────────
    try:
        attacks = analyzer.analyze_period(minutes=5)   # lihat 5 menit ke belakang

        if attacks:
            logger.info(f"📝 Ditemukan {len(attacks)} attack pattern – menyimpan ke DB...")
            db = DatabaseManager()
            saved_count = db.save_attack_logs_bulk(attacks)
            db.close()
            logger.info(f"✅ {saved_count} attack logs tersimpan ke database")
        else:
            logger.debug("Tidak ada serangan ditemukan dalam 5 menit terakhir")

    except Exception as e:
        logger.error(f"Error saat menyimpan attack logs: {e}")

    # ── 3. Cek threshold dan kirim alert ─────────────────────────────────────
    try:
        alerts = analyzer.check_thresholds(minutes=5)

        if not alerts:
            logger.debug("Tidak ada alert yang perlu dikirim")
            return

        logger.info(f"🚨 {len(alerts)} alert melebihi threshold")

        db = DatabaseManager()
        for alert in alerts:
            # Simpan alert ke database (SELALU)
            db.save_alert({
                'timestamp':    datetime.now(),
                'alert_type':   alert['type'],
                'message':      (
                    f"Alert: {alert['type']} dari {alert['ip']} "
                    f"({alert['count']} percobaan) – host: {alert.get('hostname','Unknown')}"
                ),
                'severity':     alert['severity'],
                'attack_count': alert['count'],
                'threshold':    alert['threshold']
            })
            logger.info(f"📝 Alert tersimpan: {alert['type']} dari {alert['ip']}")

            # Kirim ke Telegram HANYA jika bot sudah terdaftar
            if _telegram_app:
                try:
                    from telegram_bot.alerts import send_alert
                    await send_alert(_telegram_app, alert)
                    logger.info(f"📤 Alert terkirim ke Telegram: {alert['type']} dari {alert['ip']}")
                except Exception as e:
                    logger.error(f"Gagal kirim alert Telegram: {e}")
            else:
                logger.warning(
                    f"⚠️  Telegram belum terdaftar – alert '{alert['type']}' "
                    f"dari {alert['ip']} hanya disimpan di DB"
                )

        db.close()

    except Exception as e:
        logger.error(f"Error saat memproses alert: {e}")


# ─── Start / Stop ─────────────────────────────────────────────────────────────
def start_scheduler(application=None):
    """
    Mulai scheduler.

    Cara pakai:
        # Di main.py / entry point – jalankan SEBELUM bot start
        start_scheduler()

        # Setelah bot Telegram siap, daftarkan application-nya
        # agar alert juga dikirim via Telegram
        start_scheduler(application)   # atau panggil set_telegram_app(app)
    """
    global scheduler, monitoring_job

    # Daftarkan telegram app jika disediakan
    if application:
        set_telegram_app(application)

    if scheduler.running:
        logger.info("⚠️  Scheduler sudah berjalan")
        # Tetap update telegram app jika baru diberikan
        return

    # Tambahkan job – check_attacks_job tidak butuh args
    monitoring_job = scheduler.add_job(
        check_attacks_job,
        trigger=IntervalTrigger(seconds=MONITOR_INTERVAL),
        id='check_attacks',
        replace_existing=True,
        next_run_time=datetime.now()   # langsung jalankan sekali saat start
    )

    scheduler.start()
    logger.info(
        f"✅ Scheduler berjalan – interval: {MONITOR_INTERVAL}s "
        f"({MONITOR_INTERVAL // 60} menit)"
    )
    logger.info("📊 Monitoring aktif – data attack akan disimpan otomatis setiap siklus")


def stop_scheduler():
    """Hentikan scheduler dengan bersih"""
    global scheduler
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("🛑 Scheduler dihentikan")


def get_scheduler_status() -> dict:
    """Status scheduler untuk endpoint health-check / perintah Telegram /status"""
    return {
        'running':          scheduler.running,
        'jobs':             len(scheduler.get_jobs()),
        'next_run':         monitoring_job.next_run_time if monitoring_job else None,
        'telegram_ready':   _telegram_app is not None,
        'interval_seconds': MONITOR_INTERVAL,
    }