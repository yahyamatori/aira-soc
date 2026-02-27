from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
from config.settings import DATABASE_URL
import logging

logger = logging.getLogger(__name__)

# Create SQLAlchemy engine for MySQL
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # Cek koneksi sebelum digunakan
    echo=False  # Set True untuk debug SQL
)

# Create declarative base
Base = declarative_base()

# Create session factory
SessionLocal = sessionmaker(bind=engine)


class AttackLog(Base):
    """Model untuk menyimpan log serangan yang dianalisis"""
    __tablename__ = 'attack_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    # brute_force, port_scan, ddos, etc
    attack_type = Column(String(50), nullable=False, index=True)
    # IPv6 bisa sampai 45 karakter
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    severity = Column(
        String(20),
        nullable=False,
        default='medium')  # low, medium, high, critical
    count = Column(Integer, nullable=False, default=1)
    raw_data = Column(Text, nullable=True)  # JSON string dari log asli
    created_at = Column(DateTime, server_default=func.now())

    # Composite indexes untuk query umum
    __table_args__ = (
        Index('idx_src_ip_timestamp', 'src_ip', 'timestamp'),
        Index('idx_attack_type_timestamp', 'attack_type', 'timestamp'),
        # Unique constraint untuk mencegah duplikat data
        # Kombinasi attack_type, src_ip, dan waktu (detik yang sama) tidak boleh duplikat
        Index('idx_unique_attack', 'attack_type', 'src_ip', 'timestamp', unique=True),
    )

    def __repr__(self):
        return f"<AttackLog(ip={self.src_ip}, type={self.attack_type}, count={self.count})>"


class Alert(Base):
    """Model untuk menyimpan alert yang dikirim ke Telegram"""
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default='medium')
    attack_count = Column(Integer, nullable=False, default=0)
    threshold = Column(Integer, nullable=True)
    is_sent = Column(Boolean, default=True)
    chat_id = Column(String(50), nullable=True)  # Telegram chat ID tujuan
    created_at = Column(DateTime, server_default=func.now())

    def __repr__(self):
        return f"<Alert(type={self.alert_type}, severity={self.severity})>"


class AttackerSummary(Base):
    """Model untuk menyimpan ringkasan penyerang per periode"""
    __tablename__ = 'attacker_summary'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime, nullable=False, index=True)  # Tanggal ringkasan
    src_ip = Column(String(45), nullable=False, index=True)
    total_attacks = Column(Integer, nullable=False, default=0)
    # JSON: {"brute_force": 10, "port_scan": 5}
    attack_types = Column(Text, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    is_blocked = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    updated_at = Column(DateTime, onupdate=func.now())

    __table_args__ = (
        Index('idx_ip_date', 'src_ip', 'date'),
    )

    def __repr__(self):
        return f"<AttackerSummary(ip={self.src_ip}, total={self.total_attacks})>"


class ThresholdConfig(Base):
    """Model untuk konfigurasi threshold alert"""
    __tablename__ = 'threshold_config'

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_type = Column(String(50), nullable=False, unique=True, index=True)
    threshold_value = Column(Integer, nullable=False)
    time_window = Column(Integer, nullable=False, default=5)  # dalam menit
    severity = Column(String(20), nullable=False, default='medium')
    is_active = Column(Boolean, default=True)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, onupdate=func.now())
    updated_by = Column(String(50), nullable=True)  # Telegram user yang update

    def __repr__(self):
        return f"<Threshold(type={self.alert_type}, value={self.threshold_value})>"


class SystemStatus(Base):
    """Model untuk monitoring status sistem"""
    __tablename__ = 'system_status'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.now)
    # elasticsearch, telegram, database
    component = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)  # up, down, degraded
    response_time = Column(Float, nullable=True)  # dalam ms
    error_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<SystemStatus(component={self.component}, status={self.status})>"

# Function to initialize database


def init_db():
    """Create all tables if they don't exist"""
    try:
        Base.metadata.create_all(engine)
        logger.info("Database tables created successfully")

        # Insert default threshold config if table is empty
        db = SessionLocal()
        try:
            if db.query(ThresholdConfig).count() == 0:
                default_thresholds = [
                    ThresholdConfig(
                        alert_type='failed_login',
                        threshold_value=100,
                        time_window=5,
                        severity='high',
                        description='Failed login attempts in 5 minutes'
                    ),
                    ThresholdConfig(
                        alert_type='port_scan',
                        threshold_value=50,
                        time_window=5,
                        severity='medium',
                        description='Port scan attempts in 5 minutes'
                    ),
                    ThresholdConfig(
                        alert_type='ddos',
                        threshold_value=1000,
                        time_window=1,
                        severity='critical',
                        description='Requests per minute'
                    ),
                    ThresholdConfig(
                        alert_type='brute_force',
                        threshold_value=50,
                        time_window=5,
                        severity='high',
                        description='Brute force attempts in 5 minutes'
                    )
                ]
                db.add_all(default_thresholds)
                db.commit()
                logger.info("Default thresholds inserted")
        except Exception as e:
            logger.error(f"Error inserting default thresholds: {e}")
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        raise

# Dependency to get DB session


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
