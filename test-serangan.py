from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer

es = ElasticConnector()
analyzer = AttackAnalyzer(es)

# Cek serangan 5 menit terakhir
attacks = analyzer.analyze_period(minutes=5)

print(f"Total serangan 5 menit: {len(attacks)}")

# Cek per IP
ip_count = {}
for attack in attacks:
    ip = attack['src_ip']
    count = attack['count']
    ip_count[ip] = ip_count.get(ip, 0) + count

print("\nIP dengan serangan terbanyak:")
for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:10]:
    print(f"  {ip}: {count}")
    
    # Cek apakah melebihi threshold
    if count >= 5:
        print(f"    ⚠️ MELEBIHI THRESHOLD suspicious_request (5)")
    if count >= 10:
        print(f"    🚨 MELEBIHI THRESHOLD scanner_activity (10)")

exit()
