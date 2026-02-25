#!/usr/bin/env python3
"""
SOC Telegram Bot - Main Entry Point
"""
import sys
import asyncio
import logging
from telegram.ext import Application, CommandHandler, CallbackQueryHandler
import os

from config.logging_config import setup_logging
from config.settings import TELEGRAM_BOT_TOKEN
from telegram_bot.handlers import (
    start_command, help_command, status_command,
    lihatlog_command, lihatattack_command, topattackers_command,
    thresholds_command, setthreshold_command,
    button_callback, error_handler
)
from schedulers.monitor_scheduler import start_scheduler, stop_scheduler
from core.database import DatabaseManager
from core.models import ThresholdConfig

# Setup logging
logger = setup_logging()


def init_default_thresholds():
    """Initialize default thresholds if not exist"""
    try:
        db = DatabaseManager()
        
        # Get current thresholds
        current_thresholds = db.get_thresholds()
        
        if not current_thresholds:
            logger.warning("⚠️ No thresholds found! Creating default thresholds...")
            
            # Default thresholds
            default_thresholds = [
                ThresholdConfig(
                    alert_type='failed_login',
                    threshold_value=10,  # Lebih sensitif
                    time_window=5,
                    severity='high',
                    description='Failed login attempts in 5 minutes'
                ),
                ThresholdConfig(
                    alert_type='port_scan',
                    threshold_value=20,  # Lebih sensitif
                    time_window=5,
                    severity='medium',
                    description='Port scan attempts in 5 minutes'
                ),
                ThresholdConfig(
                    alert_type='ddos',
                    threshold_value=100,  # Lebih sensitif
                    time_window=1,
                    severity='critical',
                    description='Requests per minute'
                ),
                ThresholdConfig(
                    alert_type='brute_force',
                    threshold_value=10,  # Lebih sensitif
                    time_window=5,
                    severity='high',
                    description='Brute force attempts in 5 minutes'
                ),
                ThresholdConfig(
                    alert_type='sql_injection',
                    threshold_value=5,
                    time_window=5,
                    severity='high',
                    description='SQL injection attempts'
                ),
                ThresholdConfig(
                    alert_type='xss',
                    threshold_value=5,
                    time_window=5,
                    severity='high',
                    description='XSS attempts'
                ),
                ThresholdConfig(
                    alert_type='suspicious_request',
                    threshold_value=10,
                    time_window=5,
                    severity='medium',
                    description='Suspicious requests (scanners/bots)'
                ),
                ThresholdConfig(
                    alert_type='scanner_activity',
                    threshold_value=10,
                    time_window=5,
                    severity='low',
                    description='Scanner activity detection'
                )
            ]
            
            for threshold in default_thresholds:
                db.db.add(threshold)
            
            db.db.commit()
            db.close()
            logger.info("✅ Default thresholds created successfully!")
            print("✅ DEFAULT THRESHOLDS CREATED!", file=sys.stderr)
        else:
            logger.info(f"✅ Thresholds already exist: {current_thresholds}")
            print(f"✅ THRESHOLDS: {current_thresholds}", file=sys.stderr)
            
        db.close()
        
    except Exception as e:
        logger.error(f"❌ Error initializing thresholds: {e}")
        print(f"❌ ERROR INIT THRESHOLDS: {e}", file=sys.stderr)


async def post_init(application: Application):
    """Fungsi yang dijalankan setelah bot inisialisasi"""
    print("🔥 POST_INIT DIPANGGIL!", file=sys.stderr)
    logger.info("Bot started successfully!")
    
    # Initialize default thresholds SEBELUM scheduler dimulai
    print("📊 Menginisialisasi thresholds...", file=sys.stderr)
    init_default_thresholds()
    
    # Start scheduler untuk monitoring realtime
    print("📞 Memanggil start_scheduler...", file=sys.stderr)
    start_scheduler(application)
    print("✅ start_scheduler selesai dipanggil", file=sys.stderr)
async def main():
    """Main function"""
    logger.info("Starting SOC Telegram Bot...")
    
    if not TELEGRAM_BOT_TOKEN:
        logger.error("TELEGRAM_BOT_TOKEN not set in .env file!")
        return
    
    # Create application
    application = Application.builder() \
        .token(TELEGRAM_BOT_TOKEN) \
        .post_init(post_init) \
        .build()
    
    # Add command handlers
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("lihatlog", lihatlog_command))
    application.add_handler(CommandHandler("lihatattack", lihatattack_command))
    application.add_handler(CommandHandler("topattackers", topattackers_command))
    application.add_handler(CommandHandler("thresholds", thresholds_command))
    application.add_handler(CommandHandler("setthreshold", setthreshold_command))
    
    # Add callback handler for inline buttons
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Add error handler
    application.add_error_handler(error_handler)
    
    logger.info("Starting bot polling...")
    
    # Run bot
    try:
        await application.initialize()
        await application.start()
        await application.updater.start_polling()
        
        # Keep running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Error in main loop: {e}")
    finally:
        # Stop scheduler
        stop_scheduler()
        
        # Stop bot
        await application.updater.stop()
        await application.stop()
        await application.shutdown()
        
        logger.info("Bot shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot terminated by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
