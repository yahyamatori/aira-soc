#!/usr/bin/env python3
"""
SOC Telegram Bot - Main Entry Point
"""

import asyncio
import logging
from telegram.ext import Application, CommandHandler, CallbackQueryHandler

from config.logging_config import setup_logging
from config.settings import TELEGRAM_BOT_TOKEN
from telegram_bot.handlers import (
    start_command, help_command, status_command,
    lihatlog_command, lihatattack_command, topattackers_command,
    thresholds_command, setthreshold_command,
    button_callback, error_handler
)
from schedulers.monitor_scheduler import start_scheduler, stop_scheduler

# Setup logging
logger = setup_logging()

async def post_init(application: Application):
    """Fungsi yang dijalankan setelah bot inisialisasi"""
    logger.info("Bot started successfully!")
    
    # Start scheduler untuk monitoring realtime
    start_scheduler(application)

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
