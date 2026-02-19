#!/bin/bash
# Script untuk merestart SOC Telegram Bot

echo -e "🔄 Merestart SOC Telegram Bot..."
./stop.sh
sleep 2
./start.sh
