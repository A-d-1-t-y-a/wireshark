#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 3: Scan for Suspicious Open Ports
# Purpose: Check if critical/vulnerable ports are exposed (Modbus, Telnet, etc.)
# Author: Aditya
# Date: October 2025
#
# Usage: ./Script3_Scan_Suspicious_Ports.sh
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - Port Scanner        "
echo "=============================================="
echo ""

echo "[*] Scanning for suspicious open ports..."
echo "[*] These ports were targeted in the Thames Water attack"
echo ""

# Critical ports from Thames Water PCAP attack analysis
echo "PORT       SERVICE                        STATUS"
echo "--------------------------------------------------------"

VULNERABLE_COUNT=0

# Check Port 21 - FTP (Data Exfiltration)
if ss -tln 2>/dev/null | grep -q ":21 " || netstat -tln 2>/dev/null | grep -q ":21 "; then
    echo -e "21         FTP (Data Exfiltration)        \e[31mOPEN - WARNING!\e[0m"
    VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
else
    echo -e "21         FTP (Data Exfiltration)        \e[32mClosed\e[0m"
fi

# Check Port 23 - Telnet (Insecure)
if ss -tln 2>/dev/null | grep -q ":23 " || netstat -tln 2>/dev/null | grep -q ":23 "; then
    echo -e "23         Telnet (INSECURE)              \e[31mOPEN - CRITICAL!\e[0m"
    VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
else
    echo -e "23         Telnet (INSECURE)              \e[32mClosed\e[0m"
fi

# Check Port 445 - SMB (Lateral Movement)
if ss -tln 2>/dev/null | grep -q ":445 " || netstat -tln 2>/dev/null | grep -q ":445 "; then
    echo -e "445        SMB (Lateral Movement)         \e[31mOPEN - WARNING!\e[0m"
    VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
else
    echo -e "445        SMB (Lateral Movement)         \e[32mClosed\e[0m"
fi

# Check Port 502 - Modbus (ICS/SCADA)
if ss -tln 2>/dev/null | grep -q ":502 " || netstat -tln 2>/dev/null | grep -q ":502 "; then
    echo -e "502        Modbus (ICS/SCADA)             \e[31mOPEN - CRITICAL!\e[0m"
    VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
else
    echo -e "502        Modbus (ICS/SCADA)             \e[32mClosed\e[0m"
fi

# Check Port 3389 - RDP (Remote Access)
if ss -tln 2>/dev/null | grep -q ":3389 " || netstat -tln 2>/dev/null | grep -q ":3389 "; then
    echo -e "3389       RDP (Remote Access)            \e[31mOPEN - WARNING!\e[0m"
    VULNERABLE_COUNT=$((VULNERABLE_COUNT + 1))
else
    echo -e "3389       RDP (Remote Access)            \e[32mClosed\e[0m"
fi

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
    echo "  - Port 445 (SMB): Restrict to internal network only"
else
    echo -e "\e[32m[SECURE] No vulnerable ports found open.\e[0m"
fi

echo "=============================================="
echo ""
echo "[INFO] These ports were used in Thames Water attack:"
echo "  - Port 502  : Modbus protocol to attack PLC (10.0.0.10)"
echo "  - Port 21   : FTP exfiltration to 198.51.100.12"
echo "  - Port 3389 : RDP targeted during reconnaissance"
echo "  - Port 23   : Telnet targeted during port scan"
echo "  - Port 445  : SMB targeted for lateral movement"
echo ""
