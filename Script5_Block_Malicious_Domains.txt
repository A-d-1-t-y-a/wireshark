#!/bin/bash
#===============================================================================
# Thames Water Attack - Script 5: Block Malicious Domains
# Purpose: Block C2 and exfiltration domains using /etc/hosts DNS sinkhole
# Author: Aditya
# Date: October 2025
#
# Usage: sudo ./Script5_Block_Malicious_Domains.sh
#===============================================================================

echo "=============================================="
echo "  Thames Water Defense - Block Domains       "
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root!"
    echo "Usage: sudo ./Script5_Block_Malicious_Domains.sh"
    exit 1
fi

# Malicious domains identified from Thames Water PCAP analysis
MALICIOUS_DOMAINS=(
    "updcdn.ru"         # C2 Server Domain
    "syslog-host.cn"    # DNS Tunneling Domain
)

echo "[*] Blocking malicious domains identified from Thames Water attack..."
echo ""

BLOCKED=0
HOSTS_FILE="/etc/hosts"
BACKUP_FILE="/etc/hosts.backup.$(date +%Y%m%d_%H%M%S)"

# Create backup of hosts file
echo "[*] Creating backup of /etc/hosts..."
if cp "$HOSTS_FILE" "$BACKUP_FILE" 2>/dev/null; then
    echo "    [OK] Backup created: $BACKUP_FILE"
else
    echo "    [WARN] Could not create backup"
fi
echo ""

# Block each domain
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    echo "[+] Blocking domain: $domain"
    
    # Check if domain is already blocked
    if grep -q "0.0.0.0 $domain" "$HOSTS_FILE" 2>/dev/null; then
        echo "    [INFO] Already blocked in /etc/hosts"
        BLOCKED=$((BLOCKED + 1))
    else
        # Add domain to hosts file (redirect to 0.0.0.0)
        if echo "0.0.0.0 $domain" >> "$HOSTS_FILE" 2>/dev/null; then
            echo "    [OK] Blocked $domain (redirected to 0.0.0.0)"
            BLOCKED=$((BLOCKED + 1))
        else
            echo "    [FAIL] Could not block $domain"
        fi
    fi
    
    # Also block www subdomain
    www_domain="www.$domain"
    if grep -q "0.0.0.0 $www_domain" "$HOSTS_FILE" 2>/dev/null; then
        echo "    [INFO] Already blocked www.$domain"
    else
        if echo "0.0.0.0 $www_domain" >> "$HOSTS_FILE" 2>/dev/null; then
            echo "    [OK] Blocked www.$domain"
        fi
    fi
done

echo ""
echo "[*] Verifying blocked domains in /etc/hosts..."
echo ""
grep -E "(updcdn\.ru|syslog-host\.cn)" "$HOSTS_FILE" 2>/dev/null

echo ""
echo "=============================================="
echo "[SUCCESS] $BLOCKED malicious domain(s) blocked!"
echo "=============================================="
echo ""
echo "Blocked Domains:"
for domain in "${MALICIOUS_DOMAINS[@]}"; do
    echo "  - $domain"
done
echo ""
echo "[INFO] These domains were identified from Thames Water PCAP analysis:"
echo "  - updcdn.ru      : C2 Server (Command & Control)"
echo "  - syslog-host.cn : DNS Tunneling (Covert Channel)"
echo ""
echo "[INFO] DNS Resolution Test:"
echo "  - Testing updcdn.ru..."
if host updcdn.ru 2>/dev/null | grep -q "0.0.0.0"; then
    echo "    [OK] Domain is blocked (resolves to 0.0.0.0)"
else
    echo "    [INFO] Domain blocked in hosts file"
fi
echo ""
echo "[INFO] To restore original hosts file, run:"
echo "  sudo cp $BACKUP_FILE /etc/hosts"
echo ""
