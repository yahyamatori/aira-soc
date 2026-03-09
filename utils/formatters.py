from datetime import datetime
from typing import List, Dict, Any, Optional
import re
from collections import defaultdict

try:
    from config.settings import TIMEZONE
except ImportError:
    TIMEZONE = 'Asia/Jakarta'


def format_timestamp(ts) -> str:
    """
    Format timestamp dengan konsisten untuk timezone yang dikonfigurasi.
    Mengkonversi dari UTC (Elasticsearch) ke timezone server.
    """
    if not ts:
        return 'N/A'
    
    try:
        # Jika string, konversi ke datetime
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        
        # Jika timezone-aware, konversi ke timezone yang dikonfigurasi
        if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
            # Konversi dari UTC ke timezone lokal
            try:
                import pytz
                local_tz = pytz.timezone(TIMEZONE)
                ts = ts.astimezone(local_tz)
            except:
                pass  # Gunakan UTC jika gagal
        
        # Format output
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    except:
        return str(ts)[:19] if len(str(ts)) > 19 else str(ts)


def escape_markdown(text: str) -> str:
    """Escape karakter khusus Markdown untuk Telegram"""
    if not isinstance(text, str):
        text = str(text)
    
    text = text.replace('\\', '\\\\')
    text = text.replace('_', '\\_')
    text = text.replace('*', '\\*')
    text = text.replace('[', '\\[')
    text = text.replace(']', '\\]')
    text = text.replace('(', '\\(')
    text = text.replace(')', '\\)')
    text = text.replace('~', '\\~')
    text = text.replace('`', '\\`')
    text = text.replace('>', '\\>')
    text = text.replace('#', '\\#')
    text = text.replace('+', '\\+')
    text = text.replace('-', '\\-')
    text = text.replace('=', '\\=')
    text = text.replace('|', '\\|')
    text = text.replace('{', '\\{')
    text = text.replace('}', '\\}')
    text = text.replace('.', '\\.')
    text = text.replace('!', '\\!')
    
    return text


def get_attack_description(attack_type: str) -> str:
    """Mendapatkan deskripsi singkat untuk setiap jenis serangan"""
    descriptions = {
        'failed_login': '🔑 Failed Login - Percobaan login gagal berulang',
        'brute_force': '🔨 Brute Force - Serangan tebak password',
        'port_scan': '🔍 Port Scan - Pemindaian port untuk mencari celah',
        'ddos': '🌊 DDoS - Serangan banjir traffic',
        'sql_injection': '💉 SQL Injection - Manipulasi database via input',
        'xss': '📝 XSS - Cross-site scripting injection',
        'path_traversal': '📂 Path Traversal - Akses file di luar direktori',
        'command_injection': '⌨️ Command Injection - Eksekusi perintah sistem',
        'suspicious_request': '⚠️ Suspicious Request - Permintaan mencurigakan (scanner/bot)',
        'scanner_activity': '🕵️ Scanner Activity - Aktivitas scanner keamanan',
        'unknown': '❓ Unknown - Serangan tidak dikenal'
    }
    return descriptions.get(attack_type, f'⚠️ {attack_type.replace("_", " ").title()}')


def get_server_info(attack: Dict[str, Any]) -> Dict:
    """
    Mendapatkan informasi lengkap server yang diserang
    """
    server_info = {
        'hostname': 'Unknown',
        'host_ip': None,
        'full_info': 'Unknown Server'
    }
    
    # Ambil hostname dari attack data
    if 'hostname' in attack and attack['hostname'] and attack['hostname'] != 'Unknown':
        server_info['hostname'] = attack['hostname']
    
    # Ambil host_ip dari attack data
    if 'host_ip' in attack and attack['host_ip']:
        server_info['host_ip'] = attack['host_ip']
    
    # Format full info
    if server_info['hostname'] != 'Unknown':
        if server_info['host_ip']:
            if isinstance(server_info['host_ip'], list):
                ip_str = server_info['host_ip'][0] if server_info['host_ip'] else ''
            else:
                ip_str = str(server_info['host_ip'])
            
            if ip_str and ip_str != 'None':
                server_info['full_info'] = f"{server_info['hostname']} ({ip_str})"
            else:
                server_info['full_info'] = server_info['hostname']
        else:
            server_info['full_info'] = server_info['hostname']
    
    return server_info


def format_log_list(logs: List[Dict], limit: int = 5) -> str:
    """Format daftar log untuk ditampilkan di Telegram"""
    if not logs:
        return "📭 Tidak ada log dalam periode tersebut."
    
    response = f"📋 **{min(len(logs), limit)} Log Terbaru:**\n\n"
    
    for i, log in enumerate(logs[:limit], 1):
        timestamp = log.get('@timestamp', 'N/A')
        if isinstance(timestamp, str) and len(timestamp) > 19:
            timestamp = timestamp[:19]
        
        message = log.get('message', 'No message')
        if len(message) > 100:
            message = message[:97] + "..."
        
        safe_message = escape_markdown(message)
        safe_timestamp = escape_markdown(timestamp)
        
        response += f"{i}. `{safe_timestamp}` - {safe_message}\n"
        
        if len(response) > 3500:
            response += "\n...(dipotong, terlalu panjang)"
            break
    
    return response


def format_attack_summary(attacks: List[Dict[str, Any]], periode: str, original_logs: List[Dict] = None) -> str:
    """Format ringkasan serangan dengan informasi semua server"""
    if not attacks:
        return f"📭 Tidak ada serangan terdeteksi dalam {periode} terakhir."

    # Build a lookup for original logs to get hostname/host_ip
    log_lookup = {}
    if original_logs:
        for log in original_logs:
            # Use src_ip + timestamp as key for matching
            src_ip = log.get('source.ip') or log.get('client.ip') or log.get('src_ip')
            timestamp = log.get('@timestamp') or log.get('timestamp')
            if src_ip and timestamp:
                key = f"{src_ip}_{str(timestamp)[:19]}"
                log_lookup[key] = log

    total_attacks = len(attacks)

    # Kelompokkan data
    by_type = {}
    by_type_detail = defaultdict(lambda: {'count': 0, 'description': ''})
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    by_server = defaultdict(lambda: {
        'total': 0,
        'attackers': set(),
        'by_type': defaultdict(int),
        'by_severity': defaultdict(int)
    })
    
    # Untuk tracking attacker per server
    attacker_server_map = defaultdict(lambda: defaultdict(int))

    for attack in attacks:
        attack_type = attack.get('attack_type', 'unknown')
        severity = attack.get('severity', 'medium')
        count = attack.get('count', 1)
        src_ip = attack.get('src_ip', 'Unknown')
        
        # Dapatkan informasi server dari attack
        server_info = get_server_info(attack)
        server_key = server_info['full_info']
        
        # Update statistik per server
        by_server[server_key]['total'] += count
        by_server[server_key]['attackers'].add(src_ip)
        by_server[server_key]['by_type'][attack_type] += count
        by_server[server_key]['by_severity'][severity] += count
        
        # Map attacker ke server
        attacker_server_map[src_ip][server_key] += count
        
        # Update statistik global
        by_type[attack_type] = by_type.get(attack_type, 0) + count
        by_type_detail[attack_type]['count'] += count
        by_type_detail[attack_type]['description'] = get_attack_description(attack_type)
        by_severity[severity] = by_severity.get(severity, 0) + count

    # Format response
    response = f"📊 **Analisis Serangan - {periode} Terakhir**\n\n"
    response += f"**Total:** {total_attacks} serangan terdeteksi\n\n"

    # Tampilkan SEMUA server yang diserang
    if by_server:
        response += "**🎯 Server yang Diserang:**\n"
        for server, stats in sorted(by_server.items(), key=lambda x: x[1]['total'], reverse=True):
            attacker_count = len(stats['attackers'])
            response += f"• `{escape_markdown(server)}`\n"
            response += f"  ├ Total: {stats['total']} serangan\n"
            response += f"  └ Attacker: {attacker_count} IP berbeda\n"
            
            if attacker_count > 0:
                server_attackers = []
                for attacker, targets in attacker_server_map.items():
                    if server in targets:
                        server_attackers.append((attacker, targets[server]))
                
                server_attackers.sort(key=lambda x: x[1], reverse=True)
                if server_attackers:
                    response += "     Top Attacker:\n"
                    for attacker, cnt in server_attackers[:2]:
                        response += f"     • `{escape_markdown(attacker)}`: {cnt}x\n"
            response += "\n"
    else:
        response += "⚠️ Tidak ada informasi server\n\n"

    # Tampilkan berdasarkan severity
    response += "**📊 Berdasarkan Severity:**\n"
    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}
    for severity, count in by_severity.items():
        if count > 0:
            emoji = severity_emoji.get(severity, '⚪')
            response += f"{emoji} {severity.title()}: {count}\n"
    response += "\n"

    # Tampilkan berdasarkan tipe
    response += "**🛡️ Jenis Serangan:**\n"
    type_emoji = {
        'failed_login': '🔑',
        'brute_force': '🔨',
        'port_scan': '🔍',
        'ddos': '🌊',
        'sql_injection': '💉',
        'xss': '📝',
        'suspicious_request': '⚠️',
        'scanner_activity': '🕵️',
        'path_traversal': '📂',
        'command_injection': '⌨️'
    }
    
    sorted_types = sorted(by_type_detail.items(), key=lambda x: x[1]['count'], reverse=True)
    for attack_type, data in sorted_types:
        emoji = type_emoji.get(attack_type, '⚠️')
        description = data['description']
        count = data['count']
        response += f"{emoji} **{count}x** {description}\n"
    response += "\n"

    # Tambahkan 10 serangan terbaru
    recent = sorted(attacks, key=lambda x: x.get('timestamp', ''), reverse=True)[:10]
    if recent:
        response += "**⏱️ Serangan Terbaru:**\n"
        for attack in recent:
            time = attack.get('timestamp', '')
            if isinstance(time, datetime):
                time = time.strftime('%H:%M:%S')
            else:
                time = str(time)[11:19] if len(str(time)) > 19 else str(time)

            src_ip = escape_markdown(attack.get('src_ip', 'Unknown'))
            server_info = get_server_info(attack)
            target = escape_markdown(server_info['full_info'])
            attack_type = attack.get('attack_type', 'unknown')
            count = attack.get('count', 1)
            
            type_emoji_map = {
                'failed_login': '🔑',
                'brute_force': '🔨',
                'port_scan': '🔍',
                'ddos': '🌊',
                'sql_injection': '💉',
                'xss': '📝',
                'suspicious_request': '⚠️',
                'scanner_activity': '🕵️',
                'path_traversal': '📂',
                'command_injection': '⌨️'
            }
            emoji = type_emoji_map.get(attack_type, '⚠️')
            
            response += f"• {time} - `{src_ip}` → `{target}` {emoji} x{count}\n"

    return response


def format_top_attackers(attackers: List[Dict[str, Any]], limit: int = 10) -> str:
    """Format daftar top attackers dengan target server"""
    if not attackers:
        return "📭 Tidak ada attacker terdeteksi."

    response = f"🔝 **Top {min(len(attackers), limit)} Attackers**\n\n"

    for i, attacker in enumerate(attackers[:limit], 1):
        ip = escape_markdown(attacker.get('ip', attacker.get('src_ip', 'Unknown')))
        count = attacker.get('count', attacker.get('total', 1))
        
        targets = attacker.get('targets', [])
        
        suspicious = ""
        if count > 100:
            suspicious = " ⚠️**HIGH**"
        elif count > 50:
            suspicious = " 👀"

        response += f"{i}. `{ip}` - {count} attempts{suspicious}\n"
        
        if targets:
            response += "   Menyerang:\n"
            for target in targets[:3]:
                response += f"   • `{escape_markdown(target)}`\n"
            if len(targets) > 3:
                response += f"   • ... dan {len(targets) - 3} server lain\n"
        response += "\n"

    return response


def format_system_status(es_status: bool, db_status: bool, stats: Dict) -> str:
    """Format status sistem"""
    status = "✅ **System Status**\n\n"

    es_emoji = "✅" if es_status else "❌"
    status += f"{es_emoji} **Elasticsearch:** {'Online' if es_status else 'Offline'}\n"

    db_emoji = "✅" if db_status else "❌"
    status += f"{db_emoji} **Database:** {'Online' if db_status else 'Offline'}\n\n"

    import socket
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
        status += f"**Server Monitoring:** `{hostname} ({local_ip})`\n\n"
    except:
        status += f"**Server Monitoring:** `{hostname}`\n\n"

    if stats:
        status += "**📊 Statistics (1 jam terakhir):**\n"
        status += f"• Total serangan: {stats.get('total', 0)}\n"
        status += f"• Alert aktif: {stats.get('alerts', 0)}\n"

        if stats.get('top_attackers'):
            status += "\n**Top Attackers:**\n"
            for i, attacker in enumerate(stats['top_attackers'][:3], 1):
                ip = escape_markdown(attacker.get('ip', 'Unknown'))
                status += f"{i}. `{ip}`: {attacker.get('count')}\n"

    return status


def format_alert_message(alert: Dict) -> str:
    """Format pesan alert untuk dikirim ke Telegram"""
    severity_emoji = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '⚡',
        'low': 'ℹ️'
    }

    emoji = severity_emoji.get(alert.get('severity', 'medium'), '🔔')
    attack_type = alert.get('type', 'Unknown')
    attack_desc = get_attack_description(attack_type)

    message = f"{emoji} **ALERT: {attack_desc}**\n\n"
    
    src_ip = alert.get('ip', alert.get('src_ip', 'Unknown'))
    message += f"**Penyerang:** `{escape_markdown(src_ip)}`\n"
    
    server_info = get_server_info(alert)
    target = server_info['full_info']
    message += f"**Target Server:** `{escape_markdown(target)}`\n"
    
    message += f"**Count:** {alert.get('count', 0)} attempts\n"
    message += f"**Threshold:** {alert.get('threshold', 0)}\n"
    message += f"**Severity:** {escape_markdown(alert.get('severity', 'medium').upper())}\n"

    if alert.get('timestamp'):
        if isinstance(alert['timestamp'], datetime):
            time = alert['timestamp'].strftime('%H:%M:%S')
        else:
            time = str(alert['timestamp'])[11:19] if len(str(alert['timestamp'])) > 19 else str(alert['timestamp'])
        message += f"**Time:** {time}\n"

    return message


def format_thresholds(thresholds: Dict) -> str:
    """Format daftar threshold"""
    if not thresholds:
        return "📭 Tidak ada threshold terkonfigurasi."

    message = "⚙️ **Current Threshold Settings**\n\n"

    for alert_type, value in thresholds.items():
        emoji = {
            'failed_login': '🔑',
            'brute_force': '🔨',
            'port_scan': '🔍',
            'ddos': '🌊',
            'sql_injection': '💉',
            'xss': '📝'
        }.get(alert_type, '⚙️')

        safe_type = escape_markdown(alert_type)
        description = get_attack_description(alert_type).split(' - ')[1] if ' - ' in get_attack_description(alert_type) else ''
        message += f"{emoji} `{safe_type}`: **{value}** - {description}\n"

    return message


def format_help() -> str:
    """Format pesan help"""
    return """
🔍 **SOC Telegram Bot - Help**

**Perintah Dasar:**
/start - Mulai bot
/help - Tampilkan help ini
/status - Cek status sistem

**Analisis Serangan:**
/lihatattack [periode] - Lihat ringkasan serangan
   Contoh: /lihatattack 1h, /lihatattack 6h, /lihatattack 24h
/topattackers [limit] - Top IP penyerang
/lihatlog [jumlah] - Lihat log terbaru

**Konfigurasi:**
/thresholds - Lihat threshold saat ini
/setthreshold [type] [value] - Set threshold alert

**Mode Realtime:**
/realtime - Aktifkan update realtime
/stop - Matikan mode realtime
"""