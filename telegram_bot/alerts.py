"""Module untuk mengirim alert ke Telegram"""
import logging
from telegram import Bot
from telegram.constants import ParseMode
from config.settings import ALLOWED_USER_IDS
from utils.formatters import format_alert_message

logger = logging.getLogger(__name__)


async def send_alert(application, alert_data: dict):
    """Mengirim alert ke semua user yang diizinkan"""
    try:
        bot = application.bot
        message = format_alert_message(alert_data)

        # Kirim ke semua user yang diizinkan
        for user_id in ALLOWED_USER_IDS:
            try:
                await bot.send_message(
                    chat_id=user_id,
                    text=message,
                    parse_mode=ParseMode.MARKDOWN
                )
                logger.info(f"Alert sent to user {user_id}")
            except Exception as e:
                logger.error(f"Failed to send alert to {user_id}: {e}")

    except Exception as e:
        logger.error(f"Error sending alert: {e}")


async def send_notification(
        application,
        message: str,
        parse_mode=ParseMode.MARKDOWN):
    """Mengirim notifikasi ke semua user yang diizinkan"""
    try:
        bot = application.bot

        for user_id in ALLOWED_USER_IDS:
            try:
                await bot.send_message(
                    chat_id=user_id,
                    text=message,
                    parse_mode=parse_mode
                )
            except Exception as e:
                logger.error(f"Failed to send notification to {user_id}: {e}")

    except Exception as e:
        logger.error(f"Error sending notification: {e}")
