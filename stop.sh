#!/bin/bash
# Script untuk menghentikan SOC Telegram Bot

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  SOC Telegram Bot Stopper${NC}"
echo -e "${GREEN}================================${NC}"

# Cek file PID
if [ ! -f bot.pid ]; then
    echo -e "${YELLOW}⚠️  File PID tidak ditemukan. Bot mungkin tidak berjalan.${NC}"
    
    # Coba cari proses bot secara manual
    PIDS=$(ps aux | grep "python main.py" | grep -v grep | awk '{print $2}')
    if [ -n "$PIDS" ]; then
        echo -e "🔍 Menemukan proses bot tanpa PID file: $PIDS"
        for PID in $PIDS; do
            echo -e "🛑 Menghentikan proses $PID..."
            kill -15 $PID 2>/dev/null
            sleep 2
            kill -9 $PID 2>/dev/null
        done
        echo -e "${GREEN}✅ Semua proses bot telah dihentikan${NC}"
    else
        echo -e "${GREEN}✅ Tidak ada proses bot yang berjalan${NC}"
    fi
    exit 0
fi

# Baca PID dari file
PID=$(cat bot.pid)
echo -e "📊 PID bot: $PID"

# Cek apakah proses masih berjalan
if ps -p $PID > /dev/null 2>&1; then
    echo -e "🛑 Menghentikan bot (PID: $PID)..."
    
    # Kirim SIGTERM (graceful shutdown)
    kill -15 $PID
    
    # Tunggu hingga proses berhenti
    for i in {1..10}; do
        sleep 1
        if ! ps -p $PID > /dev/null 2>&1; then
            break
        fi
        echo -e "   Menunggu... ($i/10)"
    done
    
    # Jika masih berjalan, paksa dengan SIGKILL
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Proses tidak merespon, mematikan paksa...${NC}"
        kill -9 $PID
        sleep 1
    fi
    
    # Verifikasi
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${RED}❌ Gagal menghentikan proses${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ Bot berhasil dihentikan${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Proses dengan PID $PID tidak ditemukan${NC}"
fi

# Hapus file PID
rm -f bot.pid
echo -e "📝 File PID dihapus"

# Cek apakah masih ada proses bot lain
OTHER_PIDS=$(ps aux | grep "python main.py" | grep -v grep | awk '{print $2}')
if [ -n "$OTHER_PIDS" ]; then
    echo -e "${YELLOW}⚠️  Masih ditemukan proses bot lain:${NC}"
    for PID in $OTHER_PIDS; do
        echo -e "   - PID: $PID"
        echo -e "     Mematikan..."
        kill -9 $PID 2>/dev/null
    done
    echo -e "${GREEN}✅ Semua proses dibersihkan${NC}"
fi

echo -e "${GREEN}================================${NC}"
