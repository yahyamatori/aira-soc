#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from datetime import datetime, timedelta
import json

print("=" * 60)
print("TEST DETEKSI SERANGAN")
print("=" * 60)

# 1. Cek koneksi Elasticsearch
es = ElasticConnector()
print(f"\n1. Koneksi Elasticsearch: {'✅ OK' if es.test_connection() else '❌ GAGAL'}")

# 2. Cek index pattern
print(f"\n2. Index Pattern: {es.index_pattern}")

# 3. Coba ambil logs langsung tanpa filter
print("\n3. Mengambil sample logs (5 menit terakhir)...")
try:
    logs = es.get_recent_logs(minutes=5, size=50)
    print(f"   Ditemukan {len(logs)} logs")
    
    if logs:
        print("\n   Sample log pertama:")
        log = logs[0]
        print(f"   - Timestamp: {log.get('@timestamp', 'N/A')}")
        print(f"   - Message: {log.get('message', 'N/A')[:100]}")
        
        # Cek field yang tersedia
        print(f"\n   Field yang tersedia: {list(log.keys())[:10]}")
except Exception as e:
    print(f"   ❌ Error: {e}")

# 4. Test analyzer langsung
print("\n4. Menjalankan analyzer...")
analyzer = AttackAnalyzer(es)
attacks = analyzer.analyze_period(minutes=30)

print(f"\n5. Hasil analisis 30 menit terakhir:")
print(f"   Total serangan terdeteksi: {len(attacks)}")

if attacks:
    print("\n   Detail serangan:")
    for i, attack in enumerate(attacks[:5]):
        print(f"   {i+1}. {attack['attack_type']} dari {attack['src_ip']} (count: {attack['count']})")
else:
    print("   ❌ TIDAK ADA SERANGAN TERDETEKSI!")

# 5. Cek query pattern untuk IP mencurigakan
print("\n6. Mencari IP yang mencurigakan di logs:")
suspicious_ips = ['45.91.64.6', '185.12.59.118', '185.189.182.234', '104.23.223.14', '77.83.39.58']

for ip in suspicious_ips:
    try:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-1h"}}},
                        {"match": {"message": ip}}
                    ]
                }
            }
        }
        result = es.es.search(index=es.index_pattern, body=query)
        count = result['hits']['total']['value']
        if count > 0:
            print(f"   ✅ IP {ip}: {count} log ditemukan")
            
            # Tampilkan sample
            if count > 0 and result['hits']['hits']:
                sample = result['hits']['hits'][0]['_source']
                msg = sample.get('message', '')
                print(f"      Sample: {msg[:100]}")
        else:
            print(f"   ❌ IP {ip}: TIDAK DITEMUKAN")
    except Exception as e:
        print(f"   ❌ Error query {ip}: {e}")

print("\n" + "=" * 60)
