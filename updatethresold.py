from core.database import DatabaseManager
db = DatabaseManager()

# Tambahkan threshold untuk tipe serangan baru
from core.models import ThresholdConfig
from sqlalchemy.orm import Session
from core.models import SessionLocal

session = SessionLocal()
new_thresholds = [
    ThresholdConfig(
        alert_type='suspicious_request',
        threshold_value=5,
        time_window=5,
        severity='medium',
        description='Suspicious request patterns'
    ),
    ThresholdConfig(
        alert_type='scanner_activity',
        threshold_value=10,
        time_window=10,
        severity='low',
        description='Port scanner or bot activity'
    )
]
session.add_all(new_thresholds)
session.commit()
session.close()

print("✅ Thresholds updated")
exit()
