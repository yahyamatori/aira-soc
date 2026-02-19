#!/usr/bin/env python
# Script untuk test alert
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from schedulers.monitor_scheduler import check_attacks_job
import asyncio

async def test_alert():
    print("🔍 Menjalankan pengecekan alert manual...")
    
    # Buat application dummy untuk testing
    from telegram.ext import Application
    app = Application.builder().token("dummy").build()
    
    # Jalankan job pengecekan
    await check_attacks_job(app)
    
    print("✅ Pengecekan selesai. Cek database untuk melihat alert.")

# Jalankan
asyncio.run(test_alert())
