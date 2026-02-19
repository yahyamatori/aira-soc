from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer
from pprint import pprint

# 1. Test koneksi ke Elasticsearch
es = ElasticConnector()
print("Test Connection:", es.test_connection())

# 2. Lihat index pattern yang digunakan
print("\n--- Mencari log Filebeat Apache ---")

# 3. Ambil sample logs (tanpa filter)
all_logs = es.get_recent_logs(minutes=60, size=5)
print(f"Total logs ditemukan (semua index): {len(all_logs)}")

# 4. Coba query langsung dengan berbagai kemungkinan field
queries = [
    {"query": {"match": {"event.dataset": "apache.access"}}},
    {"query": {"match": {"event.dataset": "apache2.access"}}},
    {"query": {"match": {"fileset.name": "apache"}}},
    {"query": {"match": {"service.type": "apache"}}},
    {"query": {"match": {"process.name": "apache2"}}}
]

for i, q in enumerate(queries, 1):
    try:
        result = es.es.search(index=es.index_pattern, body=q, size=1)
        if result['hits']['total']['value'] > 0:
            print(f"\n✅ Query {i} menghasilkan {result['hits']['total']['value']} logs")
            # Tampilkan sample
            if result['hits']['hits']:
                sample = result['hits']['hits'][0]['_source']
                print("Sample fields:", list(sample.keys())[:10])
    except Exception as e:
        print(f"Query {i} error: {e}")

# 5. Lihat struktur log yang ada
print("\n--- Struktur Log ---")
if all_logs:
    sample_log = all_logs[0]
    print("Field yang tersedia:")
    for key in list(sample_log.keys())[:15]:  # Tampilkan 15 field pertama
        print(f"  - {key}: {type(sample_log[key]).__name__}")
    
    # Cek apakah ada field Apache
    apache_fields = [f for f in sample_log.keys() if 'apache' in f.lower()]
    if apache_fields:
        print("\n✅ Field Apache ditemukan:", apache_fields)

# 6. Test analyzer
analyzer = AttackAnalyzer(es)
attacks = analyzer.analyze_period(minutes=60)
print(f"\n--- Hasil Analisis Serangan ---")
print(f"Total serangan terdeteksi: {len(attacks)}")
if attacks:
    print("\nContoh serangan:")
    for i, attack in enumerate(attacks[:3]):
        print(f"  {i+1}. {attack['attack_type']} dari {attack['src_ip']} (count: {attack['count']})")

exit()
