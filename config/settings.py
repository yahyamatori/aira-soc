import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Telegram Settings
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
ALLOWED_USER_IDS = [int(id) for id in os.getenv('ALLOWED_USER_IDS', '').split(',') if id]

# Elasticsearch Settings
ELASTIC_HOST = os.getenv('ELASTIC_HOST', 'http://8.215.8.118:9200')
ELASTIC_USER = os.getenv('ELASTIC_USER')
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD')
ELASTIC_INDEX_PATTERN = os.getenv('ELASTIC_INDEX_PATTERN', 'logs-*')

# Database Settings (MySQL)
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', 3306))  # MySQL default port 3306
DB_NAME = os.getenv('DB_NAME', 'soc')
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'Dinda3737#')

# Alert Thresholds
FAILED_LOGIN_THRESHOLD = int(os.getenv('FAILED_LOGIN_THRESHOLD', 100))
FAILED_LOGIN_WINDOW = int(os.getenv('FAILED_LOGIN_WINDOW', 5))  # minutes
PORT_SCAN_THRESHOLD = int(os.getenv('PORT_SCAN_THRESHOLD', 50))
DDOS_THRESHOLD = int(os.getenv('DDOS_THRESHOLD', 1000))

# Monitoring
MONITOR_INTERVAL = int(os.getenv('MONITOR_INTERVAL', 60))  # seconds

# Database URL for MySQL
# Format: mysql+pymysql://user:password@host:port/database
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
