#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 3: Scan for Suspicious Open Ports
# Purpose: Check if critical/vulnerable ports are exposed (Modbus, Telnet, etc.)
# Author: [Your Name]
# Date: October 2025
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - Port Scanner        "
echo "=============================================="
echo ""

# Critical ports from attack analysis
declare -A CRITICAL_PORTS=(
    [21]="FTP (Data Exfiltration Risk)"
    [23]="Telnet (Insecure - DISABLE)"
    [502]="Modbus (ICS/SCADA - RESTRICT)"
    [3389]="RDP (Remote Access Risk)"
    [445]="SMB (Lateral Movement Risk)"
)

echo "[*] Scanning for suspicious open ports..."
echo "[*] These ports were targeted in the Thames Water attack"
echo ""

printf "%-10s %-30s %-15s\n" "PORT" "SERVICE" "STATUS"
echo "--------------------------------------------------------"

VULNERABLE_COUNT=0

for port in "${!CRITICAL_PORTS[@]}"; do
    service="${CRITICAL_PORTS[$port]}"
    
    # Check if port is open
    if ss -tln | grep -q ":$port " 2>/dev/null || netstat -tln | grep -q ":$port " 2>/dev/null; then
        printf "%-10s %-30s \e[31m%-15s\e[0m\n" "$port" "$service" "OPEN - WARNING!"
        VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
    else
        printf "%-10s %-30s \e[32m%-15s\e[0m\n" "$port" "$service" "Closed"
    fi
done

echo ""
echo "=============================================="

if [ $VULNERABLE_COUNT -gt 0 ]; then
    echo -e "\e[31m[WARNING] $VULNERABLE_COUNT vulnerable port(s) found open!\e[0m"
    echo ""
    echo "Recommended Actions:"
    echo "  - Port 23 (Telnet): Disable immediately, use SSH instead"
    echo "  - Port 502 (Modbus): Restrict to internal ICS network only"
    echo "  - Port 21 (FTP): Block outbound FTP to external IPs"
    echo "  - Port 3389 (RDP): Restrict to VPN/internal only"
else
    echo -e "\e[32m[SECURE] No vulnerable ports found open.\e[0m"
fi

echo "=============================================="
echo ""
