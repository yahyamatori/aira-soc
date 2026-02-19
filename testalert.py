from schedulers.monitor_scheduler import start_scheduler
from telegram.ext import Application
import asyncio

async def test():
    app = Application.builder().token("dummy").build()
    print("Memanggil start_scheduler...")
    start_scheduler(app)
    print("Selesai")

asyncio.run(test())
exit()
