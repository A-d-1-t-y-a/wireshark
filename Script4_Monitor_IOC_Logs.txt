#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 4: Monitor Logs for IOCs
# Purpose: Check system logs for Indicators of Compromise from the attack
# Author: [Your Name]
# Date: October 2025
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - IOC Log Monitor     "
echo "=============================================="
echo ""

# IOCs from PCAP analysis
MALICIOUS_IPS=("203.0.113.5" "198.51.100.12" "103.20.10.1" "192.0.2.25")
MALICIOUS_DOMAINS=("updcdn.ru" "syslog-host.cn")
SUSPICIOUS_PATTERNS=("PHISH-TOKEN" "secret-chunk" "STOR" "Modbus")

echo "[*] Searching logs for Indicators of Compromise..."
echo ""

IOC_FOUND=0

# Check for malicious IPs in logs
echo "[*] Checking for malicious IP addresses..."
for ip in "${MALICIOUS_IPS[@]}"; do
    count=$(grep -r "$ip" /var/log/ 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo -e "    \e[31m[ALERT] Found $ip in logs ($count occurrences)\e[0m"
        IOC_FOUND=$((IOC_FOUND + 1))
    else
        echo "    [OK] $ip - Not found in logs"
    fi
done

echo ""

# Check for malicious domains in logs
echo "[*] Checking for malicious domains..."
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    count=$(grep -r "$domain" /var/log/ 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo -e "    \e[31m[ALERT] Found $domain in logs ($count occurrences)\e[0m"
        IOC_FOUND=$((IOC_FOUND + 1))
    else
        echo "    [OK] $domain - Not found in logs"
    fi
done

echo ""

# Check for suspicious patterns
echo "[*] Checking for suspicious patterns..."
for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
    count=$(grep -r "$pattern" /var/log/ 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo -e "    \e[33m[WARN] Found '$pattern' in logs ($count occurrences)\e[0m"
        IOC_FOUND=$((IOC_FOUND + 1))
    else
        echo "    [OK] '$pattern' - Not found in logs"
    fi
done

echo ""
echo "=============================================="

if [ $IOC_FOUND -gt 0 ]; then
    echo -e "\e[31m[ALERT] $IOC_FOUND IOC(s) found in system logs!\e[0m"
    echo ""
    echo "Recommended Actions:"
    echo "  1. Isolate affected systems immediately"
    echo "  2. Block identified malicious IPs"
    echo "  3. Preserve logs for forensic analysis"
    echo "  4. Reset compromised credentials"
else
    echo -e "\e[32m[SECURE] No IOCs found in system logs.\e[0m"
fi

echo "=============================================="
echo ""
