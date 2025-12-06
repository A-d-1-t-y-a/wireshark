#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 2: Detect DNS Exfiltration
# Purpose: Monitor DNS queries for suspicious domains (DNS tunneling detection)
# Author: [Your Name]
# Date: October 2025
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - DNS Exfiltration    "
echo "=============================================="
echo ""

# Malicious domains from PCAP analysis
MALICIOUS_DOMAINS=("syslog-host.cn" "updcdn.ru")

echo "[*] Monitoring DNS traffic for malicious domains..."
echo "[*] Malicious domains to detect:"
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    echo "    - $domain"
done
echo ""
echo "[*] Capturing DNS queries for 10 seconds..."
echo ""

# Capture DNS traffic and check for malicious domains
tcpdump -i any port 53 -nn -c 20 -l 2>/dev/null | while read line; do
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if echo "$line" | grep -qi "$domain"; then
            echo "[ALERT] DNS EXFILTRATION DETECTED!"
            echo "        Domain: $domain"
            echo "        Traffic: $line"
            echo ""
        fi
    done
    echo "[INFO] $line"
done

echo ""
echo "=============================================="
echo "[*] DNS monitoring complete"
echo "=============================================="
echo ""
echo "If malicious domains detected, take action:"
echo "  1. Block domain in /etc/hosts"
echo "  2. Isolate affected host"
echo "  3. Investigate compromised system"
echo ""
