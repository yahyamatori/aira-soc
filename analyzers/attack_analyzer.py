import logging
import traceback
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
import re

try:
    from config.settings import DEBUG_MODE, TIMEZONE
except ImportError:
    DEBUG_MODE = False
    TIMEZONE = 'Asia/Jakarta'

logger = logging.getLogger(__name__)

# Setup debug
if DEBUG_MODE:
    logging.getLogger().setLevel(logging.DEBUG)


class AttackAnalyzer:
    """Kelas untuk menganalisis serangan dari log Elasticsearch"""

    def __init__(self, elastic_connector):
        self.es = elastic_connector

        # Pola-pola untuk deteksi serangan - LEBIH FLEKSIBEL
        self.patterns = {
            'failed_login': [
                r'failed',
                r'failure',
                r'failed login',
                r'authentication failed',
                r'invalid credentials',
                r'invalid password',
                r'login incorrect',
                r'access denied',
                r'401',
                r'403',
                r'unauthorized',
                r'wrong password',
                r'incorrect password',
                r'user not found',
                r'bad credentials'
            ],
            'brute_force': [
                r'brute force',
                r'brute-force',
                r'multiple failed',
                r'repeated login',
                r'too many attempts',
                r'max attempts',
                r'lockout',
                r'blocked'
            ],
            'port_scan': [
                r'port scan',
                r'syn scan',
                r'nmap',
                r'multiple ports',
                r'scan',
                r'connection refused',
                r'filtered',
                r'no route to host'
            ],
            'ddos': [
                r'ddos',
                r'dos',
                r'flood',
                r'high traffic',
                r'multiple requests',
                r'too many requests',
                r'request timeout',
                r'resource exhausted'
            ],
            'sql_injection': [
                r'union.*select',
                r'select.*from',
                r'1=1',
                r'--',
                r'drop table',
                r'information_schema',
                r'0x[0-9a-f]+',
                r'or 1=1',
                r"' or '",
                r'exec\(',
                r'execute\('
            ],
            'xss': [
                r'<script>',
                r'onerror=',
                r'javascript:',
                r'alert\(',
                r'onload=',
                r'<iframe',
                r'<img src=',
                r'eval\('
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\',
                r'%2e%2e%2f',
                r'%252e%252e%252f',
                r'\.\.%2f',
                r'etc/passwd',
                r'windows/system32'
            ],
            'command_injection': [
                r';\s*ls\s',
                r';\s*cat\s',
                r';\s*wget\s',
                r';\s*curl\s',
                r'\|\s*sh\s',
                r'\|\s*bash\s',
                r'`.*`',
                r'\$\(',
                r'\|\s*nc\s'
            ],
            'suspicious_request': [
                r'\.env',
                r'wp-admin',
                r'wp-login',
                r'setup-config',
                r'owa/',
                r'zgrab',
                r'aaa[0-9]',
                r'\\x[0-9a-f]{2}',
                r'[^\x20-\x7E]',
                r'.php$',
                r'\?cmd=',
                r'\?exec',
                r'phpmyadmin',
                r'admin.php'
            ],
            'scanner_activity': [
                r'zgrab',
                r'scanner',
                r'bot',
                r'crawler',
                r'nmap',
                r'masscan',
                r'nikto',
                r'gobuster',
                r'dirbuster'
            ]
        }

    def analyze_period(self, minutes: int = 60, from_db: bool = False) -> List[Dict[str, Any]]:
        """
        Analisis serangan dalam periode waktu tertentu
        from_db: Jika True, baca dari database (untuk testing)
        """
        if from_db:
            return self._analyze_period_from_db(minutes)
        else:
            return self._analyze_period_from_es(minutes)

    def _analyze_period_from_es(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Analisis serangan dari Elasticsearch"""
        try:
            # Ambil logs dari Elasticsearch - take more logs for better detection
            logs = self.es.get_recent_logs(minutes=minutes, size=5000)
            
            if DEBUG_MODE:
                logger.debug(f"📥 Retrieved {len(logs)} logs from Elasticsearch")

            if not logs:
                # Coba ambil error logs juga
                if DEBUG_MODE:
                    logger.debug("No regular logs, trying error logs...")
                logs = self.es.get_error_logs(minutes=minutes, size=1000)
                if DEBUG_MODE:
                    logger.debug(f"📥 Retrieved {len(logs)} error logs from Elasticsearch")

            if not logs:
                logger.info("No logs found in Elasticsearch for analysis")
                return []

            attacks = []

            for log in logs:
                attack_data = self._extract_attack_info(log)
                if attack_data:
                    attacks.append(attack_data)

            if DEBUG_MODE:
                logger.debug(f"🔍 Extracted {len(attacks)} potential attacks")

            # Aggregasi serangan per IP dan tipe
            aggregated = self._aggregate_attacks(attacks)

            logger.info(f"Analyzed {len(logs)} logs, found {len(aggregated)} unique attack patterns")
            return aggregated

        except Exception as e:
            logger.error(f"Error in analyze_period from ES: {e}")
            logger.error(traceback.format_exc())
            return []

    def _analyze_period_from_db(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Analisis serangan dari database (untuk testing)"""
        try:
            from core.database import DatabaseManager
            from core.models import AttackLog
            
            db = DatabaseManager()
            time_threshold = datetime.now() - timedelta(minutes=minutes)
            
            attacks_db = db.db.query(AttackLog).filter(
                AttackLog.timestamp >= time_threshold
            ).all()
            
            attacks = []
            for att in attacks_db:
                attack_data = {
                    'timestamp': att.timestamp,
                    'attack_type': att.attack_type,
                    'src_ip': att.src_ip,
                    'dst_ip': att.dst_ip,
                    'src_port': att.src_port,
                    'dst_port': att.dst_port,
                    'protocol': att.protocol,
                    'severity': att.severity,
                    'count': att.count,
                    'raw_data': att.raw_data,
                    'hostname': getattr(att, 'hostname', 'Database Test'),
                    'host_ip': getattr(att, 'host_ip', None)
                }
                attacks.append(attack_data)
            
            aggregated = self._aggregate_attacks(attacks)
            logger.info(f"Analyzed {len(attacks_db)} logs from DB, found {len(aggregated)} attack patterns")
            db.close()
            return aggregated
            
        except Exception as e:
            logger.error(f"Error in analyze_period_from_db: {e}")
            return []

    def _extract_attack_info(self, log: Dict) -> Dict[str, Any]:
        """Ekstrak informasi serangan dari satu log"""
        try:
            # Ambil field yang relevan dari log
            # Coba berbagai format field name
            message = ''
            if 'message' in log:
                message = str(log['message']).lower()
            elif 'msg' in log:
                message = str(log['msg']).lower()
            elif 'log' in log:
                message = str(log['log']).lower()
            
            # Combine all text fields for detection
            log_str = str(log).lower()
            log_str_original = str(log)  # Original case for protocol detection
            
            timestamp = log.get('@timestamp') or log.get('timestamp') or log.get('time') or datetime.now().isoformat()

            # Parse timestamp
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.now()

            # Ekstrak IP - coba berbagai field
            src_ip = self._extract_ip(log, 'source.ip') or \
                     self._extract_ip(log, 'client.ip') or \
                     self._extract_ip(log, 'src_ip') or \
                     self._extract_ip(log, 'src') or \
                     self._extract_ip_from_message(log_str)

            dst_ip = self._extract_ip(log, 'destination.ip') or \
                     self._extract_ip(log, 'server.ip') or \
                     self._extract_ip(log, 'dst_ip') or \
                     self._extract_ip(log, 'dst') or \
                     self._extract_ip(log, 'host.ip')

# Deteksi dst_port - Coba HTTP/HTTPS dulu sebelum regex pattern
            # Karena nginx logs tidak ada port, kita default ke 80 (HTTP)
            dst_port = self._detect_http_port(message, log_str_original)

            # Deteksi tipe serangan
            attack_type, severity = self._detect_attack_type(log_str)

            if not attack_type or not src_ip:
                return None

            # Ambil hostname server yang diserang
            hostname = None
            host_ip = None
            
            # Priority 1: agent.hostname
            if 'agent.hostname' in log:
                hostname = log['agent.hostname']
            elif 'agent' in log and isinstance(log['agent'], dict):
                hostname = log['agent'].get('hostname')
            
            # Priority 2: host.name
            if not hostname and 'host.name' in log:
                hostname = log['host.name']
            elif not hostname and 'host' in log and isinstance(log['host'], dict):
                host = log['host']
                hostname = host.get('name') or host.get('hostname')
                if 'ip' in host:
                    host_ip = host['ip']
                    if isinstance(host_ip, list):
                        host_ip = host_ip[0] if host_ip else None
            
            # Priority 3: host.hostname
            if not hostname and 'host.hostname' in log:
                hostname = log['host.hostname']
            
            # Priority 4: host.ip
            if not host_ip and 'host.ip' in log:
                host_ip = log['host.ip']
                if isinstance(host_ip, list):
                    host_ip = host_ip[0] if host_ip else None

            # Return attack data
            return {
                'timestamp': timestamp,
                'attack_type': attack_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': log.get('network.protocol') or log.get('protocol') or 'tcp',
                'severity': severity,
                'count': 1,
                'raw_data': str(log)[:500],
                'hostname': hostname or 'Unknown',
                'host_ip': host_ip
            }

        except Exception as e:
            logger.debug(f"Error extracting attack info: {e}")
            return None

    def _extract_ip(self, log: Dict, field: str) -> str:
        """Ekstrak IP dari field tertentu"""
        parts = field.split('.')
        value = log
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value if isinstance(value, str) and self._is_valid_ip(value) else None

    def _is_valid_ip(self, ip: str) -> bool:
        """Cek apakah string adalah IP yang valid"""
        if not ip:
            return False
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(p) <= 255 for p in parts)
        return False

    def _extract_ip_from_message(self, message: str) -> str:
        """Ekstrak IP dari pesan log"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, message)
        # Return first valid IP
        for match in matches:
            if self._is_valid_ip(match):
                return match
        return None

    def _extract_port(self, message: str, port_type: str = 'src') -> int:
        """Ekstrak port dari pesan"""
        patterns = [
            rf'{port_type}[_]?port[:=]?(\d{{1,5}})',
            rf'source.*port[:=]?(\d{{1,5}})',
            rf'dest(?:ination)?.*port[:=]?(\d{{1,5}})',
            r'port[=: ](\d{1,5})',
            r':(\d{1,5})\b'
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                port = int(match.group(1))
                if 0 < port < 65536:
                    return port

        return None

    def _detect_http_port(self, message_lower: str, message_original: str) -> int:
        """
        Deteksi dst_port dari HTTP/HTTPS dalam log message.
        
        Mengembalikan:
        - 443 untuk HTTPS
        - 80 untuk HTTP
        - None jika tidak terdeteksi
        """
        # Check for HTTPS indicators
        https_indicators = [
            'https://',
            ' ssl',
            ' tls',
            '443',
            ' https ',
            '"https',
        ]
        
        http_indicators = [
            'http://',
            ' http ',
            '"http',
        ]
        
        # Check in original message (case sensitive for URL protocols)
        for indicator in https_indicators:
            if indicator in message_original:
                if DEBUG_MODE:
                    logger.debug(f"Detected HTTPS, setting dst_port=443")
                return 443
        
        for indicator in http_indicators:
            if indicator in message_original:
                if DEBUG_MODE:
                    logger.debug(f"Detected HTTP, setting dst_port=80")
                return 80
        
        # Default: assume HTTP (port 80) for nginx access logs
        # This is a safe default since most web servers handle HTTP
        if DEBUG_MODE:
            logger.debug(f"No explicit protocol detected, defaulting to HTTP (port 80)")
        return 80

    def _detect_attack_type(self, log_text: str) -> tuple:
        """Deteksi tipe serangan dari log"""
        # Also check HTTP status codes
        if re.search(r'\b401\b', log_text) or re.search(r'\b403\b', log_text):
            return 'failed_login', 'medium'
        
        if re.search(r'\b(500|502|503|504)\b', log_text):
            return 'ddos', 'medium'
        
        # Check patterns
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_text, re.IGNORECASE):
                    severity = self._determine_severity(attack_type, log_text)
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

        # Tingkatkan severity jika ada indikator kritis
        critical_indicators = [
            'root', 'admin', 'success', 'bypass',
            'multiple', 'massive', 'automated',
            '200', 'ok', 'successful', 'executed',
            'database', 'drop', 'delete'
        ]

        if any(ind in message.lower() for ind in critical_indicators):
            if base_severity == 'medium':
                return 'high'
            elif base_severity == 'high':
                return 'critical'

        return base_severity

    def _aggregate_attacks(self, attacks: List[Dict]) -> List[Dict]:
        """Aggregasi serangan per IP dan tipe"""
        if not attacks:
            return []

        aggregated = {}

        for attack in attacks:
            key = f"{attack['src_ip']}_{attack['attack_type']}"

            if key not in aggregated:
                aggregated[key] = attack.copy()
            else:
                aggregated[key]['count'] += 1
                # Use latest timestamp
                if attack['timestamp'] > aggregated[key]['timestamp']:
                    aggregated[key]['timestamp'] = attack['timestamp']

        return list(aggregated.values())

    def check_thresholds(self, minutes: int = 5) -> List[Dict]:
        """Cek apakah ada serangan yang melebihi threshold"""
        # Ambil serangan dalam periode tertentu
        attacks = self.analyze_period(minutes=minutes)
        
        if not attacks:
            logger.debug("No attacks found in period")
            return []
        
        # Ambil threshold dari database
        from core.database import DatabaseManager
        db = DatabaseManager()
        thresholds = db.get_thresholds()
        db.close()
        
        # Default thresholds jika tidak ada di DB
        if not thresholds:
            logger.warning("Thresholds tidak ada di DB, menggunakan default")
            thresholds = {
                'failed_login': 10,
                'brute_force': 10,
                'port_scan': 20,
                'ddos': 100,
                'sql_injection': 5,
                'xss': 5,
                'path_traversal': 5,
                'command_injection': 5,
                'suspicious_request': 10,
                'scanner_activity': 10
            }
        
        if DEBUG_MODE:
            logger.debug(f"Thresholds: {thresholds}")
            logger.debug(f"Attacks: {len(attacks)}")
        
        alerts = []
        
        for attack in attacks:
            attack_type = attack.get('attack_type', 'unknown')
            attack_count = attack.get('count', 1)
            src_ip = attack.get('src_ip', 'Unknown')
            
            threshold = thresholds.get(attack_type, 999999)
            
            if attack_count >= threshold:
                logger.info(f"⚠️ ALERT: {attack_type} from {src_ip} ({attack_count} >= {threshold})")
                
                hostname = attack.get('hostname', 'Unknown')
                host_ip = attack.get('host_ip')
                
                alert = {
                    'type': attack_type,
                    'ip': src_ip,
                    'count': attack_count,
                    'threshold': threshold,
                    'severity': attack.get('severity', 'medium'),
                    'timestamp': attack.get('timestamp', datetime.now()),
                    'hostname': hostname,
                    'host_ip': host_ip,
                    'dst_ip': attack.get('dst_ip'),
                    'attack_type': attack_type
                }
                alerts.append(alert)
        
        logger.info(f"Total alerts: {len(alerts)}")
        return alerts
