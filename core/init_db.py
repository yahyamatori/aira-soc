#!/usr/bin/env python
"""Script untuk inisialisasi database"""
from core.models import init_db
import logging

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    print("Initializing database...")
    init_db()
    print("Database initialized successfully!")
