import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CommandHandler, CallbackQueryHandler
from datetime import datetime, timedelta
from functools import wraps

from config.settings import ALLOWED_USER_IDS
from core.database import DatabaseManager
from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from utils.formatters import format_attack_summary, format_top_attackers, format_system_status

logger = logging.getLogger(__name__)

# Decorator untuk membatasi akses hanya untuk user yang diizinkan


def restricted(func):
    @wraps(func)
    async def wrapped(
            update: Update,
            context: ContextTypes.DEFAULT_TYPE,
            *args,
            **kwargs):
        user_id = update.effective_user.id
        if user_id not in ALLOWED_USER_IDS:
            logger.warning(f"Unauthorized access attempt by user {user_id}")
            await update.message.reply_text("⛔ Anda tidak diizinkan menggunakan bot ini.")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

# Command: /start


@restricted
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler untuk command /start"""
    user = update.effective_user
    welcome_msg = (
        f"👋 Halo {user.first_name}!\n\n"
        "Selamat datang di **SOC Telegram Bot**\n"
        "Sistem monitoring keamanan real-time dari Elasticsearch\n\n"
        "📋 **Commands:**\n"
        "/start - Menampilkan pesan ini\n"
        "/help - Bantuan dan daftar command\n"
        "/status - Cek status sistem\n"
        "/lihatlog [jumlah] - Lihat log terbaru (contoh: /lihatlog 10)\n"
        "/lihatattack [periode] - Lihat ringkasan serangan\n"
        "   • /lihatattack 1h - 1 jam terakhir\n"
        "   • /lihatattack 6h - 6 jam terakhir\n"
        "   • /lihatattack 24h - 24 jam terakhir\n"
        "/topattackers [limit] - Top IP penyerang\n"
        "/realtime - Aktifkan mode realtime (mendapat update setiap menit)\n"
        "/stop - Matikan mode realtime\n"
        "/setthreshold [type] [value] - Set threshold alert\n"
        "/thresholds - Lihat threshold saat ini\n"
    )
    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

# Command: /help


@restricted
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler untuk command /help"""
    help_msg = (
        "🔍 **Bantuan Penggunaan**\n\n"
        "**Perintah Dasar:**\n"
        "• /status - Cek koneksi ke Elasticsearch dan Database\n"
        "• /lihatlog 20 - Lihat 20 log terbaru\n\n"
        "**Analisis Serangan:**\n"
        "• /lihatattack 1h - Serangan 1 jam terakhir\n"
        "• /lihatattack 24h - Serangan hari ini\n"
        "• /topattackers 10 - Top 10 IP penyerang\n\n"
        "**Alert Thresholds:**\n"
        "• /thresholds - Lihat konfigurasi threshold\n"
        "• /setthreshold failed_login 50 - Set threshold failed login\n"
        "• /setthreshold port_scan 30 - Set threshold port scan\n\n"
        "**Mode Realtime:**\n"
        "• /realtime - Terima update setiap menit\n"
        "• /stop - Berhenti menerima update\n"
    )
    await update.message.reply_text(help_msg, parse_mode='Markdown')

# Command: /status


@restricted
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Cek status sistem"""
    status_msg = "🔍 **Cek Status Sistem**...\n"
    msg = await update.message.reply_text(status_msg)

    try:
        # Cek Database
        db = DatabaseManager()
        db_status = "✅ **Database:** Online"

        # Cek Elasticsearch
        es = ElasticConnector()
        es_online = es.test_connection()
        es_status = "✅ **Elasticsearch:** Online" if es_online else "❌ **Elasticsearch:** Offline"

        # Update system status
        db.update_system_status('elasticsearch', 'up' if es_online else 'down')
        db.update_system_status('database', 'up')

        # Get statistics
        stats = db.get_attack_summary(minutes=60)

        status_msg = (
            f"📊 **System Status**\n\n"
            f"{db_status}\n"
            f"{es_status}\n\n"
            f"**Statistics (1 jam terakhir):**\n"
            f"• Total serangan: {stats['total']}\n"
            f"• Alert aktif: {len(db.get_recent_alerts(limit=10))}\n"
        )

        db.close()
        await msg.edit_text(status_msg, parse_mode='Markdown')

    except Exception as e:
        await msg.edit_text(f"❌ Error cek status: {str(e)}")

# Command: /lihatlog


@restricted
async def lihatlog_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lihat log terbaru dari Elasticsearch"""
    # Parse jumlah log (default 5)
    limit = 5
    if context.args:
        try:
            limit = int(context.args[0])
            limit = min(limit, 50)  # Maksimal 50 log
        except:
            pass
    
    msg = await update.message.reply_text(f"🔍 Mengambil {limit} log terbaru...")
    
    try:
        es = ElasticConnector()
        logs = es.get_recent_logs(minutes=60, size=limit)
        
        if not logs:
            await msg.edit_text("📭 Tidak ada log dalam 1 jam terakhir.")
            return
        
        # Gunakan formatter yang baru
        from utils.formatters import format_log_list
        response = format_log_list(logs, limit)
        
        await msg.edit_text(response, parse_mode='Markdown')
        
    except Exception as e:
        await msg.edit_text(f"❌ Error mengambil log: {str(e)}")
        logger.error(f"Error in lihatlog: {e}", exc_info=True)

@restricted
async def lihatattack_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Lihat ringkasan serangan"""
    # Parse periode (default 1 jam)
    periode = "1h"
    if context.args:
        periode = context.args[0]
    
    # Konversi periode ke menit
    minutes = 60
    if periode.endswith('h'):
        minutes = int(periode[:-1]) * 60
    elif periode.endswith('m'):
        minutes = int(periode[:-1])
    else:
        try:
            minutes = int(periode) * 60
        except:
            minutes = 60
    
    minutes = min(minutes, 24 * 60)
    
    msg = await update.message.reply_text(f"🔍 Menganalisis serangan {periode} terakhir...")
    
    try:
        # Analisis dari Elasticsearch
        es = ElasticConnector()
        analyzer = AttackAnalyzer(es)
        
        # Ambil logs asli untuk informasi hostname
        original_logs = es.get_recent_logs(minutes=minutes, size=10000)
        
        # Deteksi serangan
        attacks = analyzer.analyze_period(minutes=minutes)
        
        # Simpan ke database
        db = DatabaseManager()
        if attacks:
            db.save_attack_logs_bulk(attacks)
        
        # Format response dengan original_logs untuk hostname
        from utils.formatters import format_attack_summary
        response = format_attack_summary(attacks, periode, original_logs)
        
        keyboard = [
            [
                InlineKeyboardButton("🔄 Refresh", callback_data=f"refresh_{periode}"),
                InlineKeyboardButton("📊 Top Attackers", callback_data=f"top_{periode}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await msg.edit_text(response, parse_mode='Markdown', reply_markup=reply_markup)
        db.close()
        
    except Exception as e:
        await msg.edit_text(f"❌ Error analisis: {str(e)}")
        logger.error(f"Error in lihatattack: {e}", exc_info=True)
# Command: /topattackers


@restricted
async def topattackers_command(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE):
    """Lihat top attackers"""
    # Parse limit (default 10)
    limit = 10
    if context.args:
        try:
            limit = int(context.args[0])
            limit = min(limit, 50)
        except BaseException:
            pass

    msg = await update.message.reply_text(f"🔍 Mencari top {limit} attackers...")

    try:
        es = ElasticConnector()
        top_ips = es.get_top_attackers(minutes=60, size=limit)

        if not top_ips:
            await msg.edit_text("📭 Tidak ada attacker terdeteksi dalam 1 jam terakhir.")
            return

        response = format_top_attackers(top_ips, limit)
        await msg.edit_text(response, parse_mode='Markdown')

    except Exception as e:
        await msg.edit_text(f"❌ Error: {str(e)}")

# Command: /thresholds


@restricted
async def thresholds_command(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE):
    """Lihat semua threshold yang aktif"""
    db = DatabaseManager()
    thresholds = db.get_thresholds()
    db.close()

    if not thresholds:
        await update.message.reply_text("📭 Tidak ada threshold terkonfigurasi.")
        return

    response = "⚙️ **Threshold Settings:**\n\n"
    for alert_type, value in thresholds.items():
        response += f"• `{alert_type}`: **{value}**\n"

    await update.message.reply_text(response, parse_mode='Markdown')

# Command: /setthreshold


@restricted
async def setthreshold_command(
        update: Update,
        context: ContextTypes.DEFAULT_TYPE):
    """Set threshold untuk alert type"""
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ Format: /setthreshold [type] [value]\n"
            "Contoh: /setthreshold failed_login 50"
        )
        return

    alert_type = context.args[0].lower()
    try:
        value = int(context.args[1])
    except BaseException:
        await update.message.reply_text("❌ Value harus angka")
        return

    db = DatabaseManager()
    success = db.update_threshold(
        alert_type, value, str(
            update.effective_user.id))
    db.close()

    if success:
        await update.message.reply_text(f"✅ Threshold `{alert_type}` diupdate menjadi **{value}**", parse_mode='Markdown')
    else:
        await update.message.reply_text(f"❌ Threshold type `{alert_type}` tidak ditemukan", parse_mode='Markdown')

# Handler untuk callback dari inline keyboard


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data.split('_')

    if data[0] == 'refresh':
        periode = data[1]
        minutes = 60 if periode == '1h' else int(periode[:-1]) * 60

        await query.edit_message_text(f"🔄 Refreshing data untuk {periode}...")

        try:
            es = ElasticConnector()
            analyzer = AttackAnalyzer(es)
            attacks = analyzer.analyze_period(minutes=minutes)
            response = format_attack_summary(attacks, periode)
            await query.edit_message_text(response, parse_mode='Markdown')
        except Exception as e:
            await query.edit_message_text(f"❌ Error: {str(e)}")

    elif data[0] == 'top':
        periode = data[1]
        await query.edit_message_text(f"📊 Mengambil top attackers untuk {periode}...")

# Handler untuk error


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")
    if update and update.message:
        await update.message.reply_text("❌ Terjadi error internal. Silakan coba lagi.")
