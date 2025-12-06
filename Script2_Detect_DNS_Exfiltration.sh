#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 2: Detect DNS Exfiltration
# Purpose: Monitor DNS queries for suspicious domains (DNS tunneling detection)
# Author: Aditya
# Date: October 2025
#
# Usage: sudo ./Script2_Detect_DNS_Exfiltration.sh
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - DNS Exfiltration    "
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root!"
    echo "Usage: sudo ./Script2_Detect_DNS_Exfiltration.sh"
    exit 1
fi

# Malicious domains identified from Thames Water PCAP analysis
MALICIOUS_DOMAINS=("syslog-host.cn" "updcdn.ru")

echo "[*] Checking for DNS exfiltration patterns..."
echo "[*] Malicious domains from Thames Water attack:"
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    echo "    - $domain"
done
echo ""

# Check if domains are already blocked in /etc/hosts
echo "[*] Checking if malicious domains are blocked..."
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    if grep -q "$domain" /etc/hosts 2>/dev/null; then
        echo "    [OK] $domain is BLOCKED in /etc/hosts"
    else
        echo "    [WARN] $domain is NOT blocked"
    fi
done
echo ""

# Check DNS cache/recent queries
echo "[*] Checking recent DNS activity..."
if command -v journalctl &> /dev/null; then
    DNS_HITS=0
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        count=$(journalctl -u systemd-resolved --no-pager 2>/dev/null | grep -ci "$domain" || echo "0")
        if [ "$count" -gt 0 ]; then
            echo "    [ALERT] Found $count queries to $domain in DNS logs!"
            DNS_HITS=$((DNS_HITS + count))
        fi
    done
    if [ "$DNS_HITS" -eq 0 ]; then
        echo "    [OK] No queries to malicious domains found"
    fi
else
    echo "    [INFO] journalctl not available, skipping DNS log check"
fi
echo ""

# Live capture DNS traffic (5 seconds)
echo "[*] Capturing live DNS traffic for 5 seconds..."
echo ""

if command -v tcpdump &> /dev/null; then
    ALERT_COUNT=0
    timeout 5 tcpdump -i any port 53 -nn -c 10 2>/dev/null | while read line; do
        echo "    [DNS] $line"
        for domain in "${MALICIOUS_DOMAINS[@]}"; do
            if echo "$line" | grep -qi "$domain"; then
                echo ""
                echo "    [ALERT] DNS EXFILTRATION DETECTED!"
                echo "    [ALERT] Domain: $domain"
                echo ""
            fi
        done
    done
else
    echo "    [INFO] tcpdump not available, skipping live capture"
fi

echo ""
echo "=============================================="
echo "[*] DNS Exfiltration Check Complete"
echo "=============================================="
echo ""
echo "[INFO] Malicious domains from Thames Water attack:"
echo "  - syslog-host.cn : Used for DNS tunneling (C2 channel)"
echo "  - updcdn.ru      : C2 server domain"
echo ""
echo "[INFO] If threats detected, take these actions:"
echo "  1. Block domain: echo '0.0.0.0 domain.com' >> /etc/hosts"
echo "  2. Isolate affected host from network"
echo "  3. Investigate compromised system"
echo ""
