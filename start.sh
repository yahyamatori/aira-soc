#!/bin/bash
# Script untuk menjalankan SOC Telegram Bot di background

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  SOC Telegram Bot Starter${NC}"
echo -e "${GREEN}================================${NC}"

# Masuk ke direktori project
cd /root/aira-soc || { 
    echo -e "${RED}❌ Direktori /root/aira-soc tidak ditemukan${NC}"
    exit 1
}

# Cek apakah sudah ada proses yang berjalan
if [ -f bot.pid ]; then
    PID=$(cat bot.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Bot sudah berjalan dengan PID: $PID${NC}"
        echo -e "   Untuk restart, jalankan: ./stop.sh && ./start.sh"
        exit 1
    else
        echo -e "${YELLOW}⚠️  File PID ditemukan tapi proses tidak ada. Menghapus...${NC}"
        rm bot.pid
    fi
fi

# Aktifkan virtual environment
echo -e "📦 Mengaktifkan virtual environment..."
source venv/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Gagal mengaktifkan virtual environment${NC}"
    exit 1
fi

# Cek dependencies
echo -e "🔍 Memeriksa dependencies..."
python -c "import telegram" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Module telegram tidak ditemukan. Install dengan: pip install python-telegram-bot${NC}"
    exit 1
fi

# Jalankan bot di background dengan nohup
echo -e "🚀 Menjalankan bot di background..."
nohup python main.py > bot.log 2>&1 &

# Simpan PID
echo $! > bot.pid
PID=$(cat bot.pid)

# Tunggu sebentar untuk memastikan bot berjalan
sleep 3

# Cek apakah proses masih berjalan
if ps -p $PID > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Bot berhasil dijalankan dengan PID: $PID${NC}"
    echo -e "📝 Log: tail -f bot.log"
    echo -e "🛑 Stop: ./stop.sh"
else
    echo -e "${RED}❌ Bot gagal dijalankan. Cek error di bot.log${NC}"
    cat bot.log | tail -10
    exit 1
fi

echo -e "${GREEN}================================${NC}"
