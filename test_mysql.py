#!/usr/bin/env python
"""Simple MySQL connection test"""
import sys
import os

# Tambahkan current directory ke Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from config.settings import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Pastikan file config/settings.py ada dan benar")
    sys.exit(1)

try:
    import pymysql
    print("✅ PyMySQL imported successfully")
except ImportError as e:
    print(f"❌ PyMySQL not installed: {e}")
    print("Jalankan: pip install pymysql cryptography")
    sys.exit(1)

def test_connection():
    """Test MySQL connection"""
    print(f"\n🔍 Testing MySQL Connection:")
    print(f"   Host: {DB_HOST}")
    print(f"   Port: {DB_PORT}")
    print(f"   User: {DB_USER}")
    print(f"   Database: {DB_NAME}")
    print("-" * 40)
    
    try:
        connection = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            port=DB_PORT,
            connect_timeout=5
        )
        print("✅ Connection successful!")
        
        # Test query
        with connection.cursor() as cursor:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            print(f"📊 MySQL Version: {version[0]}")
            
            # Cek database
            cursor.execute("SELECT DATABASE()")
            db_name = cursor.fetchone()
            print(f"📊 Current Database: {db_name[0]}")
            
        connection.close()
        return True
        
    except pymysql.err.OperationalError as e:
        print(f"❌ Connection failed: {e}")
        if "Access denied" in str(e):
            print("\n💡 Tips: Periksa password MySQL di file .env")
        elif "Unknown database" in str(e):
            print(f"\n💡 Tips: Database '{DB_NAME}' tidak ditemukan")
            print(f"   Buat dengan: mysql -u {DB_USER} -p -e \"CREATE DATABASE {DB_NAME};\"")
        else:
            print(f"\n💡 Tips: Pastikan MySQL running: sudo systemctl status mysql")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("MySQL Connection Test")
    print("=" * 50)
    
    success = test_connection()
    
    if success:
        print("\n✅ Test passed! Database siap digunakan.")
    else:
        print("\n❌ Test failed! Perbaiki error di atas.")
        sys.exit(1)
