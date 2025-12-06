#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 1: Block Attacker IPs
# Purpose: Block malicious IPs identified from PCAP analysis using iptables
# Author: Aditya
# Date: October 2025
#
# Usage: sudo ./Script1_Block_Attacker_IPs.sh
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - Block Attacker IPs  "
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root!"
    echo "Usage: sudo ./Script1_Block_Attacker_IPs.sh"
    exit 1
fi

# Malicious IPs identified from Thames Water PCAP analysis
ATTACKER_IPS=(
    "203.0.113.5"     # C2 Server (updcdn.ru)
    "198.51.100.12"   # FTP Exfiltration Server
    "103.20.10.1"     # DDoS Attack Source
    "192.0.2.25"      # Port Scanner
)

echo "[*] Blocking malicious IPs identified from Thames Water attack..."
echo ""

BLOCKED=0

for ip in "${ATTACKER_IPS[@]}"; do
    echo "[+] Blocking IP: $ip"
    
    # Block incoming traffic from attacker
    if iptables -A INPUT -s "$ip" -j DROP 2>/dev/null; then
        echo "    [OK] Blocked incoming from $ip"
    else
        echo "    [FAIL] Could not block incoming from $ip"
    fi
    
    # Block outgoing traffic to attacker
    if iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null; then
        echo "    [OK] Blocked outgoing to $ip"
        BLOCKED=$((BLOCKED + 1))
    else
        echo "    [FAIL] Could not block outgoing to $ip"
    fi
done

echo ""
echo "[*] Verifying blocked IPs in iptables rules..."
echo ""
echo "INPUT Chain (Blocked Incoming):"
iptables -L INPUT -n | grep DROP | head -5
echo ""
echo "OUTPUT Chain (Blocked Outgoing):"
iptables -L OUTPUT -n | grep DROP | head -5

echo ""
echo "=============================================="
echo "[SUCCESS] $BLOCKED attacker IP(s) blocked!"
echo "=============================================="
echo ""
echo "Blocked IPs:"
for ip in "${ATTACKER_IPS[@]}"; do
    echo "  - $ip"
done
echo ""
echo "[INFO] These IPs were identified from Thames Water PCAP analysis:"
echo "  - 203.0.113.5    : C2 Server (Command & Control)"
echo "  - 198.51.100.12  : FTP Server (Data Exfiltration)"
echo "  - 103.20.10.1    : DDoS Attack Source"
echo "  - 192.0.2.25     : Port Scanner (Reconnaissance)"
echo ""
