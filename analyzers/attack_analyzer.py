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
                r'Access denied for user'
            ],
            'brute_force': [
                r'brute force',
                r'multiple failed',
                r'repeated login'
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
                r'multiple requests'
            ],
            'sql_injection': [
                r'union.*select',
                r'select.*from',
                r'1=1',
                r'--',
                r'DROP TABLE',
                r'SELECT.*FROM'
            ],
            'xss': [
                r'<script>',
                r'onerror=',
                r'javascript:',
                r'alert\('
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
            src_ip = self._extract_ip(log, 'src_ip') or self._extract_ip_from_message(message)
            dst_ip = self._extract_ip(log, 'dst_ip')
            
            # Ekstrak port
            src_port = log.get('src_port') or self._extract_port(message, 'src')
            dst_port = log.get('dst_port') or self._extract_port(message, 'dst')
            
            # Deteksi tipe serangan
            attack_type, severity = self._detect_attack_type(message)
            
            if not attack_type or not src_ip:
                return None
            
            return {
                'timestamp': timestamp,
                'attack_type': attack_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': log.get('protocol', 'tcp'),
                'severity': severity,
                'count': 1,
                'raw_data': str(log)[:500]  # Simpan sebagian raw data
            }
            
        except Exception as e:
            logger.debug(f"Error extracting attack info: {e}")
            return None
    
    def _extract_ip(self, log: Dict, field: str) -> str:
        """Ekstrak IP dari field tertentu"""
        # Coba berbagai kemungkinan field name
        possible_fields = [
            field,
            f'{field}_addr',
            f'remote_{field}',
            f'local_{field}',
            f'client_{field}'
        ]
        
        for f in possible_fields:
            if f in log:
                return log[f]
        
        return None
    
    def _extract_ip_from_message(self, message: str) -> str:
        """Ekstrak IP dari pesan log menggunakan regex"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        match = re.search(ip_pattern, message)
        return match.group(0) if match else None
    
    def _extract_port(self, message: str, port_type: str = 'src') -> int:
        """Ekstrak port dari pesan"""
        # Cari pola port: :8080, port=8080, dst_port=80, dll
        patterns = [
            rf'{port_type}[:=]?(\d{{1,5}})',  # src:8080 or src=8080
            r'port[=:](\d{1,5})',  # port=8080
            r':(\d{1,5})\b'  # :8080
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
                    # Tentukan severity berdasarkan tipe
                    severity = self._determine_severity(attack_type, message)
                    return attack_type, severity
        
        # Default jika tidak terdeteksi
        return None, None
    
    def _determine_severity(self, attack_type: str, message: str) -> str:
        """Tentukan tingkat keparahan serangan"""
        severity_map = {
            'failed_login': 'medium',
            'brute_force': 'high',
            'port_scan': 'medium',
            'ddos': 'critical',
            'sql_injection': 'high',
            'xss': 'high'
        }
        
        base_severity = severity_map.get(attack_type, 'medium')
        
        # Upgrade severity jika ada indikasi lanjutan
        critical_indicators = [
            'root', 'admin', 'success', 'bypass',
            'multiple', 'massive', 'automated'
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
        
        # Kelompokkan berdasarkan (src_ip, attack_type) dalam interval waktu
        aggregated = {}
        
        for attack in attacks:
            key = f"{attack['src_ip']}_{attack['attack_type']}"
            
            if key not in aggregated:
                aggregated[key] = attack.copy()
            else:
                # Increment count
                aggregated[key]['count'] += 1
                
                # Update last seen
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
