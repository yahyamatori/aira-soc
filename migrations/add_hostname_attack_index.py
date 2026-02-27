#!/usr/bin/env python3
"""
Migration script untuk menambahkan index komposit 
(hostname, attack_type, timestamp) pada tabel attack_logs

Cara penggunaan:
1. Backup database terlebih dahulu!
2. Jalankan: python migrations/add_hostname_attack_index.py
3. Verifikasi index berhasil dibuat
"""

import sys
import os

# Add parent directory to path untuk import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from config.settings import DATABASE_URL
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def add_hostname_attack_index():
    """Tambah index komposit untuk hostname-based attack grouping"""
    
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as connection:
        try:
            # Check if index already exists
            check_query = text("""
                SELECT COUNT(*) as count 
                FROM INFORMATION_SCHEMA.STATISTICS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'attack_logs' 
                AND INDEX_NAME = 'idx_hostname_attack_timestamp'
            """)
            
            result = connection.execute(check_query)
            index_exists = result.fetchone()[0] > 0
            
            if index_exists:
                logger.info("Index 'idx_hostname_attack_timestamp' sudah ada, skip...")
                return True
            
            # Add composite index: hostname + attack_type + timestamp
            logger.info("Menambahkan index komposit (hostname, attack_type, timestamp)...")
            
            alter_query = text("""
                CREATE INDEX idx_hostname_attack_timestamp 
                ON attack_logs (hostname, attack_type, timestamp)
            """)
            
            connection.execute(alter_query)
            connection.commit()
            
            logger.info("✅ Index berhasil ditambahkan!")
            
            # Verify index creation
            verify_query = text("""
                SHOW INDEX FROM attack_logs 
                WHERE Key_name = 'idx_hostname_attack_timestamp'
            """)
            
            result = connection.execute(verify_query)
            indexes = result.fetchall()
            
            if indexes:
                logger.info(f"✅ Verifikasi: Index ditemukan dengan {len(indexes)} kolom")
                for idx in indexes:
                    logger.info(f"   - Column: {idx[4]}, Seq: {idx[3]}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saat menambahkan index: {e}")
            connection.rollback()
            return False


def rollback_index():
    """Hapus index jika diperlukan (untuk rollback)"""
    
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as connection:
        try:
            logger.info("Menghapus index 'idx_hostname_attack_timestamp'...")
            
            drop_query = text("""
                DROP INDEX idx_hostname_attack_timestamp 
                ON attack_logs
            """)
            
            connection.execute(drop_query)
            connection.commit()
            
            logger.info("✅ Index berhasil dihapus!")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saat menghapus index: {e}")
            connection.rollback()
            return False


def show_current_indexes():
    """Tampilkan semua index yang ada di tabel attack_logs"""
    
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as connection:
        try:
            query = text("""
                SELECT INDEX_NAME, COLUMN_NAME, SEQ_IN_INDEX 
                FROM INFORMATION_SCHEMA.STATISTICS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'attack_logs'
                ORDER BY INDEX_NAME, SEQ_IN_INDEX
            """)
            
            result = connection.execute(query)
            indexes = result.fetchall()
            
            logger.info("📋 Index yang ada di tabel attack_logs:")
            current_index = None
            
            for idx in indexes:
                index_name, column_name, seq = idx
                if index_name != current_index:
                    logger.info(f"\n🔹 {index_name}:")
                    current_index = index_name
                logger.info(f"   Column {seq}: {column_name}")
                
        except Exception as e:
            logger.error(f"Error saat menampilkan index: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Migration untuk hostname-based attack index')
    parser.add_argument('--rollback', action='store_true', help='Hapus index (rollback)')
    parser.add_argument('--show', action='store_true', help='Tampilkan index yang ada')
    
    args = parser.parse_args()
    
    if args.rollback:
        rollback_index()
    elif args.show:
        show_current_indexes()
    else:
        # Default: add index
        print("🚀 Migration: Menambahkan index untuk hostname-based attack grouping")
        print("=" * 60)
        
        # Show current indexes first
        show_current_indexes()
        print("\n" + "=" * 60)
        
        # Add new index
        success = add_hostname_attack_index()
        
        if success:
            print("\n" + "=" * 60)
            print("✅ Migration berhasil!")
            print("\nIndex baru akan digunakan untuk query:")
            print("  - Get attacks by hostname")
            print("  - Group attacks by hostname + attack_type")
            print("  - Filter attacks per hostname dalam time range")
        else:
            print("\n❌ Migration gagal!")
            sys.exit(1)
