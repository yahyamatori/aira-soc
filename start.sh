#!/bin/bash
# Script untuk menjalankan SOC Telegram Bot di background

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  SOC Telegram Bot Starter${NC}"
echo -e "${GREEN}================================${NC}"

cd /root/aira-soc || { 
    echo -e "${RED}❌ Direktori /root/aira-soc tidak ditemukan${NC}"
    exit 1
}

# Matikan proses lama jika ada
echo -e "🛑 Mematikan proses bot yang mungkin masih berjalan..."
pkill -f "python main.py" 2>/dev/null
sleep 2

# Hapus file PID jika ada
rm -f bot.pid

# Aktifkan virtual environment
echo -e "📦 Mengaktifkan virtual environment..."
source venv/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Gagal mengaktifkan virtual environment${NC}"
    exit 1
fi

# Jalankan bot di background
echo -e "🚀 Menjalankan bot di background..."
nohup python main.py > bot.log 2>&1 &

echo $! > bot.pid
PID=$(cat bot.pid)

sleep 3

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