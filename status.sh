#!/bin/bash
# Script untuk melihat status SOC Telegram Bot

# Warna untuk output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}  SOC Telegram Bot Status${NC}"
echo -e "${BLUE}================================${NC}"

# Cek file PID
if [ -f bot.pid ]; then
    PID=$(cat bot.pid)
    if ps -p $PID > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Bot sedang BERJALAN${NC}"
        echo -e "   PID: $PID"
        
        # Info proses
        RUNTIME=$(ps -o etime= -p $PID 2>/dev/null | xargs)
        CPU=$(ps -o %cpu= -p $PID 2>/dev/null | xargs)
        MEM=$(ps -o %mem= -p $PID 2>/dev/null | xargs)
        
        echo -e "   Runtime: ${RUNTIME:-N/A}"
        echo -e "   CPU: ${CPU:-N/A}%"
        echo -e "   Memory: ${MEM:-N/A}%"
        
        # Cek log terakhir
        if [ -f bot.log ]; then
            LAST_LOG=$(tail -n 5 bot.log 2>/dev/null | grep -E "INFO|ERROR|WARNING" | tail -1)
            if [ -n "$LAST_LOG" ]; then
                echo -e "   Log terakhir: ${LAST_LOG:0:100}"
            fi
        fi
    else
        echo -e "${RED}❌ File PID ditemukan tapi proses tidak berjalan${NC}"
        echo -e "   PID file: $PID (tidak aktif)"
        echo -e "   Jalankan ./stop.sh untuk membersihkan"
    fi
else
    echo -e "${YELLOW}⚠️  Bot TIDAK berjalan (file PID tidak ditemukan)${NC}"
fi

# Cek proses secara manual
PIDS=$(ps aux | grep "python main.py" | grep -v grep | grep -v "status.sh")
if [ -n "$PIDS" ]; then
    echo -e "\n${YELLOW}🔍 Proses bot yang ditemukan (manual check):${NC}"
    echo "$PIDS" | while read line; do
        PID=$(echo $line | awk '{print $2}')
        CMD=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; print ""}')
        echo -e "   PID: $PID - ${CMD:0:50}..."
    done
fi

# Cek log file
echo -e "\n${BLUE}📊 Informasi Log:${NC}"
if [ -f bot.log ]; then
    LOG_SIZE=$(du -h bot.log | cut -f1)
    LOG_LINES=$(wc -l < bot.log)
    LOG_MOD=$(date -r bot.log "+%Y-%m-%d %H:%M:%S")
    echo -e "   File: bot.log"
    echo -e "   Size: $LOG_SIZE"
    echo -e "   Lines: $LOG_LINES"
    echo -e "   Modified: $LOG_MOD"
    
    # Cek error terakhir
    echo -e "\n${RED}⚠️  5 Error/Warning Terakhir:${NC}"
    grep -E "ERROR|WARNING" bot.log | tail -5 | while read line; do
        echo -e "   ${line:0:100}..."
    done
else
    echo -e "   File log tidak ditemukan"
fi

echo -e "${BLUE}================================${NC}"
