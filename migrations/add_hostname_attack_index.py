"""
Migration: Add hostname column to attack_logs table
"""
import logging
from sqlalchemy import text
from core.models import engine

logger = logging.getLogger(__name__)


def upgrade():
    """Add hostname column to attack_logs table"""
    try:
        with engine.connect() as conn:
            # Check if column exists
            result = conn.execute(text("""
                SELECT COUNT(*) 
                FROM information_schema.COLUMNS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'attack_logs' 
                AND COLUMN_NAME = 'hostname'
            """))
            column_exists = result.scalar() > 0
            
            if not column_exists:
                conn.execute(text("""
                    ALTER TABLE attack_logs 
                    ADD COLUMN hostname VARCHAR(255) NULL
                """))
                conn.commit()
                logger.info("Successfully added 'hostname' column to attack_logs")
            else:
                logger.info("'hostname' column already exists in attack_logs")
                
    except Exception as e:
        logger.error(f"Error adding hostname column: {e}")
        raise


def downgrade():
    """Remove hostname column from attack_logs table"""
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                ALTER TABLE attack_logs 
                DROP COLUMN hostname
            """))
            conn.commit()
            logger.info("Successfully removed 'hostname' column from attack_logs")
    except Exception as e:
        logger.error(f"Error removing hostname column: {e}")
        raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    upgrade()
