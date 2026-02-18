"""Utility functions untuk memformat output ke Telegram"""
from datetime import datetime
from typing import List, Dict, Any, Optional

def format_attack_summary(attacks: List[Dict[str, Any]], periode: str) -> str:
    """Format ringkasan serangan untuk ditampilkan di Telegram"""
    if not attacks:
        return f"📭 Tidak ada serangan terdeteksi dalam {periode} terakhir."
    
    total_attacks = len(attacks)
    
    # Kelompokkan berdasarkan tipe serangan
    by_type = {}
    by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    for attack in attacks:
        attack_type = attack.get('attack_type', 'unknown')
        severity = attack.get('severity', 'medium')
        count = attack.get('count', 1)
        
        by_type[attack_type] = by_type.get(attack_type, 0) + count
        by_severity[severity] = by_severity.get(severity, 0) + count
    
    # Format response
    response = f"📊 **Analisis Serangan - {periode} Terakhir**\n\n"
    response += f"**Total:** {total_attacks} serangan terdeteksi\n\n"
    
    # Tampilkan berdasarkan severity
    response += "**Berdasarkan Severity:**\n"
    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}
    for severity, count in by_severity.items():
        if count > 0:
            emoji = severity_emoji.get(severity, '⚪')
            response += f"{emoji} {severity.title()}: {count}\n"
    
    # Tampilkan berdasarkan tipe
    response += "\n**Berdasarkan Tipe Serangan:**\n"
    type_emoji = {
        'failed_login': '🔑',
        'brute_force': '🔨',
        'port_scan': '🔍',
        'ddos': '🌊',
        'sql_injection': '💉',
        'xss': '📝'
    }
    for attack_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]:
        emoji = type_emoji.get(attack_type, '⚠️')
        response += f"{emoji} {attack_type.replace('_', ' ').title()}: {count}\n"
    
    # Tambahkan 5 serangan terbaru
    recent = sorted(attacks, key=lambda x: x.get('timestamp', ''), reverse=True)[:3]
    if recent:
        response += "\n**Serangan Terbaru:**\n"
        for attack in recent:
            time = attack.get('timestamp', '')
            if isinstance(time, datetime):
                time = time.strftime('%H:%M:%S')
            else:
                time = str(time)[11:19] if len(str(time)) > 19 else str(time)
            
            ip = attack.get('src_ip', 'Unknown')
            attack_type = attack.get('attack_type', 'unknown')
            count = attack.get('count', 1)
            response += f"• {time} - `{ip}` ({attack_type}) x{count}\n"
    
    return response

def format_top_attackers(attackers: List[Dict[str, Any]], limit: int = 10) -> str:
    """Format daftar top attackers"""
    if not attackers:
        return "📭 Tidak ada attacker terdeteksi."
    
    response = f"🔝 **Top {min(len(attackers), limit)} Attackers**\n\n"
    
    for i, attacker in enumerate(attackers[:limit], 1):
        ip = attacker.get('ip', attacker.get('src_ip', 'Unknown'))
        count = attacker.get('count', attacker.get('total', 1))
        
        # Cek apakah IP ini mencurigakan
        suspicious = ""
        if count > 100:
            suspicious = " ⚠️**HIGH**"
        elif count > 50:
            suspicious = " 👀"
        
        response += f"{i}. `{ip}` - {count} attempts{suspicious}\n"
    
    return response

def format_system_status(es_status: bool, db_status: bool, stats: Dict) -> str:
    """Format status sistem"""
    status = "✅ **System Status**\n\n"
    
    # Elasticsearch status
    es_emoji = "✅" if es_status else "❌"
    status += f"{es_emoji} **Elasticsearch:** {'Online' if es_status else 'Offline'}\n"
    
    # Database status
    db_emoji = "✅" if db_status else "❌"
    status += f"{db_emoji} **Database:** {'Online' if db_status else 'Offline'}\n\n"
    
    # Statistics
    if stats:
        status += "**📊 Statistics (1 jam terakhir):**\n"
        status += f"• Total serangan: {stats.get('total', 0)}\n"
        status += f"• Alert aktif: {stats.get('alerts', 0)}\n"
        
        if stats.get('top_attackers'):
            status += "\n**Top Attackers:**\n"
            for i, attacker in enumerate(stats['top_attackers'][:3], 1):
                status += f"{i}. `{attacker.get('ip')}`: {attacker.get('count')}\n"
    
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
    
    message = f"{emoji} **ALERT: {alert.get('type', 'Unknown').upper()}**\n\n"
    message += f"**IP:** `{alert.get('ip', 'Unknown')}`\n"
    message += f"**Count:** {alert.get('count', 0)} attempts\n"
    message += f"**Threshold:** {alert.get('threshold', 0)}\n"
    message += f"**Severity:** {alert.get('severity', 'medium').upper()}\n"
    
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
        # Tambahkan emoji sesuai tipe
        emoji = {
            'failed_login': '🔑',
            'brute_force': '🔨',
            'port_scan': '🔍',
            'ddos': '🌊',
            'sql_injection': '💉',
            'xss': '📝'
        }.get(alert_type, '⚙️')
        
        message += f"{emoji} `{alert_type}`: **{value}**\n"
    
    return message

def format_log_entry(log: Dict) -> str:
    """Format satu entry log"""
    timestamp = log.get('@timestamp', 'N/A')
    if isinstance(timestamp, str) and len(timestamp) > 19:
        timestamp = timestamp[:19]  # Ambil YYYY-MM-DD HH:MM:SS
    
    message = log.get('message', 'No message')
    if len(message) > 100:
        message = message[:97] + "..."
    
    return f"`{timestamp}` - {message}"

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
