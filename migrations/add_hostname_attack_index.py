#!/usr/bin/env python3
"""
Migration script untuk menambahkan index komposit 
(hostname, attack_type, timestamp) pada tabel attack_logs

Cara penggunaan:
1. Backup database terlebih dahulu!
2. Jalankan: python migrations/add_hostname_attack_index.py
3. Verifikasi index berhasil dibuat

Jika SQLAlchemy tidak terinstall, script akan menampilkan SQL yang harus dijalankan manual.
"""

import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try to import SQLAlchemy, if not available use fallback
try:
    from sqlalchemy import create_engine, text
    from config.settings import DATABASE_URL
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    logger.warning("SQLAlchemy tidak terinstall. Menggunakan fallback mode.")
    # Try to get database config from environment or settings
    try:
        from config.settings import DATABASE_URL
    except ImportError:
        DATABASE_URL = None


def get_db_connection():
    """Get database connection using available method"""
    if SQLALCHEMY_AVAILABLE:
        engine = create_engine(DATABASE_URL)
        return engine.connect()
    else:
        # Fallback to mysql-connector or pymysql
        try:
            import mysql.connector
            # Parse DATABASE_URL (mysql://user:pass@host:port/dbname)
            import re
            match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', DATABASE_URL)
            if match:
                user, password, host, port, database = match.groups()
                conn = mysql.connector.connect(
                    host=host,
                    port=int(port),
                    user=user,
                    password=password,
                    database=database
                )
                return conn
        except ImportError:
            try:
                import pymysql
                import re
                match = re.match(r'mysql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', DATABASE_URL)
                if match:
                    user, password, host, port, database = match.groups()
                    conn = pymysql.connect(
                        host=host,
                        port=int(port),
                        user=user,
                        password=password,
                        database=database
                    )
                    return conn
            except ImportError:
                pass
        return None


def execute_query(connection, query, fetch=True):
    """Execute query using available method"""
    if SQLALCHEMY_AVAILABLE:
        from sqlalchemy import text
        result = connection.execute(text(query))
        if fetch:
            return result.fetchall()
        return None
    else:
        cursor = connection.cursor()
        cursor.execute(query)
        if fetch:
            result = cursor.fetchall()
            cursor.close()
            return result
        connection.commit()
        cursor.close()
        return None


def add_hostname_attack_index():
    """Tambah index komposit untuk hostname-based attack grouping"""
    
    if not SQLALCHEMY_AVAILABLE and DATABASE_URL is None:
        print_manual_sql()
        return False
    
    connection = get_db_connection()
    if connection is None:
        print_manual_sql()
        return False
    
    try:
        # Check if index already exists
        check_query = """
            SELECT COUNT(*) as count 
            FROM INFORMATION_SCHEMA.STATISTICS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'attack_logs' 
            AND INDEX_NAME = 'idx_hostname_attack_timestamp'
        """
        
        result = execute_query(connection, check_query)
        index_exists = result[0][0] > 0 if result else False
        
        if index_exists:
            logger.info("Index 'idx_hostname_attack_timestamp' sudah ada, skip...")
            return True
        
        # Add composite index: hostname + attack_type + timestamp
        logger.info("Menambahkan index komposit (hostname, attack_type, timestamp)...")
        
        alter_query = """
            CREATE INDEX idx_hostname_attack_timestamp 
            ON attack_logs (hostname, attack_type, timestamp)
        """
        
        execute_query(connection, alter_query, fetch=False)
        
        if not SQLALCHEMY_AVAILABLE:
            connection.commit()
        
        logger.info("✅ Index berhasil ditambahkan!")
        
        # Verify index creation
        verify_query = """
            SHOW INDEX FROM attack_logs 
            WHERE Key_name = 'idx_hostname_attack_timestamp'
        """
        
        indexes = execute_query(connection, verify_query)
        
        if indexes:
            logger.info(f"✅ Verifikasi: Index ditemukan dengan {len(indexes)} kolom")
            for idx in indexes:
                # MySQL SHOW INDEX returns: Table, Non_unique, Key_name, Seq_in_index, Column_name, ...
                column_name = idx[4] if len(idx) > 4 else 'unknown'
                seq_in_index = idx[3] if len(idx) > 3 else 'unknown'
                logger.info(f"   - Column: {column_name}, Seq: {seq_in_index}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error saat menambahkan index: {e}")
        if not SQLALCHEMY_AVAILABLE:
            try:
                connection.rollback()
            except:
                pass
        return False
    finally:
        if not SQLALCHEMY_AVAILABLE and connection:
            connection.close()


def rollback_index():
    """Hapus index jika diperlukan (untuk rollback)"""
    
    if not SQLALCHEMY_AVAILABLE and DATABASE_URL is None:
        print_manual_sql_rollback()
        return False
    
    connection = get_db_connection()
    if connection is None:
        print_manual_sql_rollback()
        return False
    
    try:
        logger.info("Menghapus index 'idx_hostname_attack_timestamp'...")
        
        drop_query = """
            DROP INDEX idx_hostname_attack_timestamp 
            ON attack_logs
        """
        
        execute_query(connection, drop_query, fetch=False)
        
        if not SQLALCHEMY_AVAILABLE:
            connection.commit()
        
        logger.info("✅ Index berhasil dihapus!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error saat menghapus index: {e}")
        if not SQLALCHEMY_AVAILABLE:
            try:
                connection.rollback()
            except:
                pass
        return False
    finally:
        if not SQLALCHEMY_AVAILABLE and connection:
            connection.close()


def show_current_indexes():
    """Tampilkan semua index yang ada di tabel attack_logs"""
    
    if not SQLALCHEMY_AVAILABLE and DATABASE_URL is None:
        logger.error("Database connection tidak tersedia. Tidak bisa menampilkan index.")
        return
    
    connection = get_db_connection()
    if connection is None:
        logger.error("Database connection tidak tersedia. Tidak bisa menampilkan index.")
        return
    
    try:
        query = """
            SELECT INDEX_NAME, COLUMN_NAME, SEQ_IN_INDEX 
            FROM INFORMATION_SCHEMA.STATISTICS 
            WHERE TABLE_SCHEMA = DATABASE() 
            AND TABLE_NAME = 'attack_logs'
            ORDER BY INDEX_NAME, SEQ_IN_INDEX
        """
        
        indexes = execute_query(connection, query)
        
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
    finally:
        if not SQLALCHEMY_AVAILABLE and connection:
            connection.close()


def print_manual_sql():
    """Print SQL statements for manual execution"""
    print("\n" + "=" * 70)
    print("⚠️  SQLAlchemy tidak terinstall!")
    print("=" * 70)
    print("\nJalankan SQL berikut secara manual di MySQL:")
    print("\n" + "-" * 70)
    print("-- Cek apakah index sudah ada:")
    print("SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS")
    print("WHERE TABLE_SCHEMA = DATABASE()")
    print("AND TABLE_NAME = 'attack_logs'")
    print("AND INDEX_NAME = 'idx_hostname_attack_timestamp';")
    print("\n-- Tambah index (jika belum ada):")
    print("CREATE INDEX idx_hostname_attack_timestamp")
    print("ON attack_logs (hostname, attack_type, timestamp);")
    print("-" * 70 + "\n")


def print_manual_sql_rollback():
    """Print SQL statements for rollback"""
    print("\n" + "=" * 70)
    print("⚠️  SQLAlchemy tidak terinstall!")
    print("=" * 70)
    print("\nJalankan SQL berikut secara manual untuk rollback:")
    print("\n" + "-" * 70)
    print("DROP INDEX idx_hostname_attack_timestamp ON attack_logs;")
    print("-" * 70 + "\n")


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
