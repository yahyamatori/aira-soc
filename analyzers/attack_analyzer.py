import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import re

logger = logging.getLogger(__name__)

class AttackAnalyzer:
    """Kelas untuk menganalisis serangan dari log Elasticsearch"""

    def __init__(self, elastic_connector):
        self.es = elastic_connector

        # Pola-pola untuk deteksi serangan
        self.patterns = {
            'failed_login': [
                r'failed login',
                r'authentication failed',
                r'invalid password',
                r'login incorrect',
                r'Access denied for user',
                r'HTTP/1.1" 401',
                r'HTTP/1.1" 403'
            ],
            'brute_force': [
                r'brute force',
                r'multiple failed',
                r'repeated login',
                r'too many attempts'
            ],
            'port_scan': [
                r'port scan',
                r'syn scan',
                r'nmap',
                r'multiple ports'
            ],
            'ddos': [
                r'ddos',
                r'flood',
                r'high traffic',
                r'multiple requests',
                r'too many requests'
            ],
            'sql_injection': [
                r'union.*select',
                r'select.*from',
                r'1=1',
                r'--',
                r'DROP TABLE',
                r'SELECT.*FROM',
                r'information_schema',
                r'0x[0-9a-f]+'
            ],
            'xss': [
                r'<script>',
                r'onerror=',
                r'javascript:',
                r'alert\(',
                r'onload=',
                r'<iframe',
                r'<img src='
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%252e%252e%252f'
            ],
            'command_injection': [
                r';\s*ls\s',
                r';\s*cat\s',
                r';\s*wget\s',
                r';\s*curl\s',
                r'\|\s*sh\s',
                r'\|\s*bash\s'
            ],
            'suspicious_request': [
                r'\.env',
                r'wp-admin',
                r'setup-config',
                r'owa/',
                r'zgrab',
                r'aaa[0-9]',
                r'\\x[0-9a-f]{2}',
                r'[^\x20-\x7E]'
            ],
            'scanner_activity': [
                r'zgrab',
                r'scanner',
                r'bot',
                r'crawler',
                r'nmap',
                r'masscan'
            ]
        }

    def analyze_period(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Analisis serangan dalam periode waktu tertentu"""
        try:
            # Ambil logs dari Elasticsearch
            logs = self.es.get_recent_logs(minutes=minutes, size=10000)

            if not logs:
                return []

            attacks = []

            for log in logs:
                # Ekstrak informasi dasar
                attack_data = self._extract_attack_info(log)
                if attack_data:
                    attacks.append(attack_data)

            # Aggregasi serangan per IP dan tipe
            aggregated = self._aggregate_attacks(attacks)

            logger.info(f"Analyzed {len(logs)} logs, found {len(aggregated)} attack patterns")
            return aggregated

        except Exception as e:
            logger.error(f"Error in analyze_period: {e}")
            return []

    def _extract_attack_info(self, log: Dict) -> Dict[str, Any]:
        """Ekstrak informasi serangan dari satu log"""
        try:
            # Ambil field yang relevan
            message = log.get('message', '').lower()
            timestamp = log.get('@timestamp', datetime.now().isoformat())

            # Parse timestamp
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.now()

            # Ekstrak IP
            src_ip = self._extract_ip(log, 'source.ip') or \
                    self._extract_ip(log, 'client.ip') or \
                    self._extract_ip(log, 'src_ip') or \
                    self._extract_ip_from_message(message)

            dst_ip = self._extract_ip(log, 'destination.ip') or \
                    self._extract_ip(log, 'server.ip') or \
                    self._extract_ip(log, 'dst_ip')

            # Ekstrak port
            src_port = log.get('source.port') or log.get('src_port') or self._extract_port(message, 'src')
            dst_port = log.get('destination.port') or log.get('dst_port') or self._extract_port(message, 'dst')

            # Deteksi tipe serangan
            attack_type, severity = self._detect_attack_type(message)

            if not attack_type or not src_ip:
                return None

            # === AMBIL HOSTNAME DARI BERBAGAI SUMBER ===
            hostname = None
            
            # PRIORITAS 1: agent.hostname (dari log Anda)
            if 'agent.hostname' in log:
                hostname = log['agent.hostname']
            elif 'agent' in log and isinstance(log['agent'], dict):
                hostname = log['agent'].get('hostname')
            
            # PRIORITAS 2: host.name
            if not hostname and 'host.name' in log:
                hostname = log['host.name']
            elif not hostname and 'host' in log and isinstance(log['host'], dict):
                hostname = log['host'].get('name') or log['host'].get('hostname')
            
            # PRIORITAS 3: host.hostname
            if not hostname and 'host.hostname' in log:
                hostname = log['host.hostname']

            # RETURN field untuk database + hostname (dengan prefix)
            return {
                # Field untuk database
                'timestamp': timestamp,
                'attack_type': attack_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': log.get('network.protocol', 'tcp'),
                'severity': severity,
                'count': 1,
                'raw_data': str(log)[:500],
                
                # TAMBAHKAN HOSTNAME UNTUK FORMATTER (tidak disimpan ke DB)
                'hostname': hostname or 'Unknown'
            }
        except Exception as e:
            logger.debug(f"Error extracting attack info: {e}")
            return None

    def _extract_host_info(self, log: Dict) -> Dict:
        """
        Ekstrak informasi host/server - FUNGSI TERPISAH UNTUK FORMETTERS
        Fungsi ini DIPANGGIL oleh formatters, bukan untuk database
        """
        host_info = {
            'hostname': None,
            'host_ip': None,
            'agent_hostname': None,
            'full_info': 'Unknown Server'
        }
        
        # Cek agent.hostname (dari log Anda)
        if 'agent.hostname' in log:
            host_info['agent_hostname'] = log['agent.hostname']
            host_info['hostname'] = log['agent.hostname']
        
        # Cek host.name
        if 'host.name' in log:
            host_info['hostname'] = log['host.name']
        elif 'host' in log and isinstance(log['host'], dict):
            host_info['hostname'] = log['host'].get('name') or log['host'].get('hostname')
            if 'ip' in log['host']:
                ip_field = log['host']['ip']
                if isinstance(ip_field, list):
                    host_info['host_ip'] = ip_field[0] if ip_field else None
                else:
                    host_info['host_ip'] = ip_field
        
        # Cek host.ip
        if not host_info['host_ip'] and 'host.ip' in log:
            host_info['host_ip'] = log['host.ip']
            if isinstance(host_info['host_ip'], list):
                host_info['host_ip'] = host_info['host_ip'][0] if host_info['host_ip'] else None
        
        # Format full info
        if host_info['hostname']:
            if host_info['host_ip']:
                host_info['full_info'] = f"{host_info['hostname']} ({host_info['host_ip']})"
            else:
                host_info['full_info'] = host_info['hostname']
        elif host_info['agent_hostname']:
            host_info['full_info'] = host_info['agent_hostname']
        
        return host_info

    def _extract_ip(self, log: Dict, field: str) -> str:
        """Ekstrak IP dari field tertentu"""
        parts = field.split('.')
        value = log
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value if isinstance(value, str) else None

    def _extract_ip_from_message(self, message: str) -> str:
        """Ekstrak IP dari pesan log menggunakan regex"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None

    def _extract_port(self, message: str, port_type: str = 'src') -> int:
        """Ekstrak port dari pesan"""
        patterns = [
            rf'{port_type}[:=]?(\d{{1,5}})',
            r'port[=:](\d{1,5})',
            r':(\d{1,5})\b'
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                if 0 < port < 65536:
                    return port

        return None

    def _detect_attack_type(self, message: str) -> tuple:
        """Deteksi tipe serangan dari pesan log"""
        message_lower = message.lower()

        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, message_lower, re.IGNORECASE):
                    severity = self._determine_severity(attack_type, message)
                    return attack_type, severity

        return None, None

    def _determine_severity(self, attack_type: str, message: str) -> str:
        """Tentukan tingkat keparahan serangan"""
        severity_map = {
            'failed_login': 'medium',
            'brute_force': 'high',
            'port_scan': 'medium',
            'ddos': 'critical',
            'sql_injection': 'high',
            'xss': 'high',
            'path_traversal': 'high',
            'command_injection': 'critical',
            'suspicious_request': 'medium',
            'scanner_activity': 'low'
        }

        base_severity = severity_map.get(attack_type, 'medium')

        critical_indicators = [
            'root', 'admin', 'success', 'bypass',
            'multiple', 'massive', 'automated',
            '200', 'ok', 'successful'
        ]

        if any(ind in message.lower() for ind in critical_indicators):
            if base_severity == 'medium':
                return 'high'
            elif base_severity == 'high':
                return 'critical'

        return base_severity

    def _aggregate_attacks(self, attacks: List[Dict]) -> List[Dict]:
        """Aggregasi serangan per IP dan tipe dalam window waktu"""
        if not attacks:
            return []

        aggregated = {}

        for attack in attacks:
            key = f"{attack['src_ip']}_{attack['attack_type']}"

            if key not in aggregated:
                aggregated[key] = attack.copy()
            else:
                aggregated[key]['count'] += 1
                if attack['timestamp'] > aggregated[key]['timestamp']:
                    aggregated[key]['timestamp'] = attack['timestamp']

        return list(aggregated.values())

    def check_thresholds(self, minutes: int = 5) -> List[Dict]:
        """Cek apakah ada serangan yang melebihi threshold"""
        attacks = self.analyze_period(minutes=minutes)

        from core.database import DatabaseManager
        db = DatabaseManager()
        thresholds = db.get_thresholds()
        db.close()

        alerts = []

        for attack in attacks:
            threshold = thresholds.get(attack['attack_type'], 999999)
            if attack['count'] > threshold:
                alerts.append({
                    'type': attack['attack_type'],
                    'ip': attack['src_ip'],
                    'count': attack['count'],
                    'threshold': threshold,
                    'severity': attack['severity'],
                    'timestamp': attack['timestamp']
                })

        return alerts

    def get_server_stats(self, minutes: int = 60) -> Dict:
        """Mendapatkan statistik per server"""
        attacks = self.analyze_period(minutes=minutes)
        
        server_stats = {}
        
        for attack in attacks:
            # Gunakan dst_ip sebagai fallback
            server_key = attack.get('dst_ip', 'Unknown')
            if server_key not in server_stats:
                server_stats[server_key] = {
                    'total': 0,
                    'attackers': set(),
                    'by_type': {}
                }
            
            server_stats[server_key]['total'] += attack['count']
            server_stats[server_key]['attackers'].add(attack['src_ip'])
            
            attack_type = attack['attack_type']
            server_stats[server_key]['by_type'][attack_type] = \
                server_stats[server_key]['by_type'].get(attack_type, 0) + attack['count']
        
        return server_stats
