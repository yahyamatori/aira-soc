from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import logging

from .models import SessionLocal, AttackLog, Alert, AttackerSummary, ThresholdConfig, SystemStatus

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manager class untuk operasi database"""

    def __init__(self):
        self.db = SessionLocal()

    def close(self):
        """Close database session"""
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # Attack Log operations
    def save_attack_log(self, attack_data: dict) -> AttackLog:
        """Save single attack log"""
        attack = AttackLog(**attack_data)
        self.db.add(attack)
        self.db.commit()
        self.db.refresh(attack)
        return attack

    def save_attack_logs_bulk(self, attacks: List[dict]) -> int:
        """Save multiple attack logs dengan validasi duplikat"""
        if not attacks:
            return 0
        
        # Filter out duplicates based on attack_type, src_ip, and timestamp (detik yang sama)
        new_attacks = []
        for attack in attacks:
            # Normalize timestamp to second precision for comparison
            timestamp = attack.get('timestamp')
            if isinstance(timestamp, str):
                try:
                    from datetime import datetime
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    pass
            
            # Check if this exact attack already exists
            existing = self.db.query(AttackLog).filter(
                AttackLog.attack_type == attack.get('attack_type'),
                AttackLog.src_ip == attack.get('src_ip'),
                AttackLog.timestamp == timestamp
            ).first()
            
            if not existing:
                new_attacks.append(attack)
        
        if not new_attacks:
            logger.info(f"Semua {len(attacks)} attack logs adalah duplikat, tidak ada yang disimpan")
            return 0
        
        # Save only new (non-duplicate) attacks
        attack_objects = [AttackLog(**data) for data in new_attacks]
        self.db.bulk_save_objects(attack_objects)
        self.db.commit()
        
        duplicates_count = len(attacks) - len(new_attacks)
        if duplicates_count > 0:
            logger.info(f"Disimpan {len(new_attacks)} attack logs, {duplicates_count} duplikat dilewati")
        else:
            logger.info(f"Disimpan {len(new_attacks)} attack logs")
        
        return len(new_attacks)

    def get_recent_attacks(self, minutes: int = 60, attack_type: str = None) -> List[AttackLog]:
        """Get recent attacks"""
        query = self.db.query(AttackLog).filter(
            AttackLog.timestamp >= datetime.now() - timedelta(minutes=minutes)
        )
        if attack_type:
            query = query.filter(AttackLog.attack_type == attack_type)
        return query.order_by(AttackLog.timestamp.desc()).all()

    def get_attack_summary(self, minutes: int = 60) -> Dict:
        """Get summary of attacks"""
        time_threshold = datetime.now() - timedelta(minutes=minutes)

        # Total attacks
        total = self.db.query(AttackLog).filter(
            AttackLog.timestamp >= time_threshold
        ).count()

        # By type
        by_type = self.db.query(
            AttackLog.attack_type,
            AttackLog.severity,
            AttackLog.count
        ).filter(
            AttackLog.timestamp >= time_threshold
        ).all()

        # Top attackers
        top_attackers = self.db.query(
            AttackLog.src_ip,
            AttackLog.attack_type,
            AttackLog.count
        ).filter(
            AttackLog.timestamp >= time_threshold
        ).order_by(AttackLog.count.desc()).limit(10).all()

        return {
            'total': total,
            'by_type': [{'type': t[0], 'severity': t[1], 'count': t[2]} for t in by_type],
            'top_attackers': [{'ip': a[0], 'type': a[1], 'count': a[2]} for a in top_attackers]
        }

    # Alert operations
    def save_alert(self, alert_data: dict) -> Alert:
        """Save alert"""
        alert = Alert(**alert_data)
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def get_recent_alerts(self, limit: int = 50) -> List[Alert]:
        """Get recent alerts"""
        return self.db.query(Alert).order_by(
            Alert.timestamp.desc()
        ).limit(limit).all()

    # Threshold operations
    def get_thresholds(self) -> Dict[str, int]:
        """Get all active thresholds"""
        thresholds = self.db.query(ThresholdConfig).filter(
            ThresholdConfig.is_active == True
        ).all()
        return {t.alert_type: t.threshold_value for t in thresholds}

    def update_threshold(self, alert_type: str, value: int, updated_by: str = 'system') -> bool:
        """Update threshold value"""
        threshold = self.db.query(ThresholdConfig).filter(
            ThresholdConfig.alert_type == alert_type
        ).first()

        if threshold:
            threshold.threshold_value = value
            threshold.updated_by = updated_by
            self.db.commit()
            return True
        return False

    # System Status - FIXED INDENTATION HERE
    def update_system_status(self, component: str, status: str,
                             response_time: float = None,
                             error: str = None):
        """Update system component status"""
        status_log = SystemStatus(
            timestamp=datetime.now(),
            component=component,
            status=status,
            response_time=response_time,
            error_message=error
        )
        self.db.add(status_log)
        self.db.commit()

    def get_system_status(self, minutes: int = 60) -> List[SystemStatus]:
        """Get recent system status"""
        return self.db.query(SystemStatus).filter(
            SystemStatus.timestamp >= datetime.now() - timedelta(minutes=minutes)
        ).order_by(SystemStatus.timestamp.desc()).all()

    # Cleanup old data
    def cleanup_old_data(self, days: int = 30):
        """Delete data older than specified days"""
        try:
            threshold = datetime.now() - timedelta(days=days)

            # Delete old attack logs
            deleted_attacks = self.db.query(AttackLog).filter(
                AttackLog.timestamp < threshold
            ).delete()

            # Delete old alerts
            deleted_alerts = self.db.query(Alert).filter(
                Alert.timestamp < threshold
            ).delete()

            self.db.commit()
            logger.info(f"Cleaned up {deleted_attacks} attacks and {deleted_alerts} alerts")

        except Exception as e:
            logger.error(f"Error cleaning up data: {e}")
            self.db.rollback()
