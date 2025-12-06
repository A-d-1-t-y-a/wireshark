#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 1: Block Attacker IPs
# Purpose: Block malicious IPs identified from PCAP analysis using iptables
# Author: [Your Name]
# Date: October 2025
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - Block Attacker IPs  "
echo "=============================================="
echo ""

# Malicious IPs from PCAP analysis
ATTACKER_IPS=(
    "203.0.113.5"     # C2 Server
    "198.51.100.12"   # FTP Exfiltration Server
    "103.20.10.1"     # DDoS Source
    "192.0.2.25"      # Port Scanner
)

echo "[*] Blocking malicious IPs identified from Thames Water attack..."
echo ""

for ip in "${ATTACKER_IPS[@]}"; do
    echo "[+] Blocking IP: $ip"
    
    # Block incoming traffic from attacker
    iptables -A INPUT -s "$ip" -j DROP
    
    # Block outgoing traffic to attacker
    iptables -A OUTPUT -d "$ip" -j DROP
    
    echo "    - Blocked incoming from $ip"
    echo "    - Blocked outgoing to $ip"
done

echo ""
echo "[*] Verifying blocked IPs..."
echo ""
iptables -L -n | grep -E "DROP.*(203.0.113.5|198.51.100.12|103.20.10.1|192.0.2.25)"

echo ""
echo "=============================================="
echo "[SUCCESS] All attacker IPs have been blocked!"
echo "=============================================="
echo ""
echo "Blocked IPs:"
for ip in "${ATTACKER_IPS[@]}"; do
    echo "  - $ip"
done
echo ""
