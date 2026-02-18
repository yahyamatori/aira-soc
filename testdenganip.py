from core.elastic_connector import ElasticConnector
from analyzers.attack_analyzer import AttackAnalyzer

es = ElasticConnector()
analyzer = AttackAnalyzer(es)

# Coba analisis untuk IP 45.91.64.6
attacks = analyzer.analyze_period(minutes=120)
for attack in attacks:
    if attack['src_ip'] == '45.91.64.6':
        print(f"✅ DETECTED: {attack}")
    else:
        print(f"IP {attack['src_ip']} terdeteksi sebagai {attack['attack_type']}")

exit()
