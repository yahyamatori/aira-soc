#!/bin/bash
# Script untuk menghentikan SOC Telegram Bot

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  SOC Telegram Bot Stopper${NC}"
echo -e "${GREEN}================================${NC}"

# Cari semua proses bot
PIDS=$(ps aux | grep "python main.py" | grep -v grep | awk '{print $2}')

if [ -n "$PIDS" ]; then
    echo -e "🛑 Menghentikan proses bot: $PIDS"
    for PID in $PIDS; do
        kill -15 $PID 2>/dev/null
    done
    
    sleep 3
    
    # Paksa matikan yang masih hidup
    for PID in $PIDS; do
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}⚠️  Proses $PID tidak merespon, mematikan paksa...${NC}"
            kill -9 $PID 2>/dev/null
        fi
    done
    
    echo -e "${GREEN}✅ Semua proses bot telah dihentikan${NC}"
else
    echo -e "${GREEN}✅ Tidak ada proses bot yang berjalan${NC}"
fi

# Hapus file PID akan mengecek lebih lanjut
rm -f bot.pid

echo -e "${GREEN}================================${NC}"