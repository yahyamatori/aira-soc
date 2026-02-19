cat > logs.sh << 'EOF'
#!/bin/bash
# Script untuk melihat log bot secara real-time

if [ "$1" == "-f" ] || [ "$1" == "--follow" ]; then
    tail -f bot.log
elif [ "$1" == "-e" ] || [ "$1" == "--error" ]; then
    grep -E "ERROR|WARNING" bot.log | tail -50
elif [ "$1" == "-n" ]; then
    tail -n ${2:-50} bot.log
else
    tail -n 50 bot.log
fi
EOF

chmod +x logs.sh