import asyncio
from schedulers.monitor_scheduler import check_attacks_job
from telegram.ext import Application
import logging

logging.basicConfig(level=logging.INFO)

async def test():
    print("🔍 Menjalankan check_attacks_job manual...")
    app = Application.builder().token("dummy").build()
    await check_attacks_job(app)
    print("✅ Selesai")

asyncio.run(test())
exit()

