#!/bin/bash

#===============================================================================
# Thames Water Treatment Facility - Network Defense Script
# Purpose: Automated detection and mitigation of cyber threats
# Author: Cyber Operations Analyst
# Date: October 2025
# 
# This script addresses the specific threats identified in the Thames Water
# cyberattack including:
#   - C2 communication blocking
#   - Malicious IP blocking
#   - Modbus traffic monitoring
#   - DNS tunneling detection
#   - FTP exfiltration prevention
#===============================================================================

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file location
LOG_FILE="/var/log/thames_water_defense.log"
BLOCKED_IPS_FILE="/etc/thames_water_blocked_ips.txt"

# Malicious IPs identified from PCAP analysis
MALICIOUS_IPS=(
    "203.0.113.5"    # C2 Server (updcdn.ru)
    "198.51.100.12"  # FTP Exfiltration Server
    "103.20.10.1"    # DDoS Source
    "192.0.2.25"     # Port Scanner
)

# Malicious domains identified from PCAP analysis
MALICIOUS_DOMAINS=(
    "updcdn.ru"       # C2 Domain
    "syslog-host.cn"  # DNS Tunneling Domain
)

# Critical ports to monitor
MODBUS_PORT=502
FTP_PORT=21
RDP_PORT=3389
TELNET_PORT=23

#===============================================================================
# Function: Print banner
#===============================================================================
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║     Thames Water Treatment Facility - Network Defense System      ║"
    echo "║                    Incident Response Script                       ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#===============================================================================
# Function: Log messages with timestamp
#===============================================================================
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ALERT")
            echo -e "${RED}[ALERT]${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

#===============================================================================
# Function: Check if script is run as root
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

#===============================================================================
# Function: Block malicious IPs using iptables
#===============================================================================
block_malicious_ips() {
    log_message "INFO" "Starting malicious IP blocking..."
    
    for ip in "${MALICIOUS_IPS[@]}"; do
        # Check if rule already exists
        if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
            log_message "INFO" "IP $ip is already blocked"
        else
            # Block incoming traffic from malicious IP
            iptables -A INPUT -s "$ip" -j DROP
            # Block outgoing traffic to malicious IP
            iptables -A OUTPUT -d "$ip" -j DROP
            log_message "ALERT" "Blocked malicious IP: $ip"
            echo "$ip" >> "$BLOCKED_IPS_FILE"
        fi
    done
    
    log_message "INFO" "Malicious IP blocking completed"
}

#===============================================================================
# Function: Block malicious domains using /etc/hosts
#===============================================================================
block_malicious_domains() {
    log_message "INFO" "Starting malicious domain blocking..."
    
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if grep -q "$domain" /etc/hosts; then
            log_message "INFO" "Domain $domain is already blocked"
        else
            echo "0.0.0.0 $domain" >> /etc/hosts
            echo "0.0.0.0 www.$domain" >> /etc/hosts
            log_message "ALERT" "Blocked malicious domain: $domain"
        fi
    done
    
    # Flush DNS cache if systemd-resolved is available
    if command -v systemd-resolve &> /dev/null; then
        systemd-resolve --flush-caches
        log_message "INFO" "DNS cache flushed"
    fi
    
    log_message "INFO" "Malicious domain blocking completed"
}

#===============================================================================
# Function: Monitor Modbus traffic for anomalies
#===============================================================================
monitor_modbus_traffic() {
    log_message "INFO" "Starting Modbus traffic monitoring..."
    
    # Check if tcpdump is available
    if ! command -v tcpdump &> /dev/null; then
        log_message "WARN" "tcpdump not found. Please install tcpdump for Modbus monitoring."
        return 1
    fi
    
    echo -e "${YELLOW}Monitoring Modbus traffic on port $MODBUS_PORT...${NC}"
    echo "Press Ctrl+C to stop monitoring"
    
    # Capture Modbus traffic and analyze
    tcpdump -i any port $MODBUS_PORT -nn -c 100 2>/dev/null | while read line; do
        # Check for Function Code 16 (Write Multiple Registers) - potential attack
        if echo "$line" | grep -q "502"; then
            log_message "ALERT" "Modbus traffic detected: $line"
        fi
    done
}

#===============================================================================
# Function: Detect DNS tunneling attempts
#===============================================================================
detect_dns_tunneling() {
    log_message "INFO" "Starting DNS tunneling detection..."
    
    # Check for high-frequency DNS queries to suspicious domains
    echo -e "${YELLOW}Analyzing DNS queries for tunneling patterns...${NC}"
    
    # Monitor DNS traffic for 30 seconds
    timeout 30 tcpdump -i any port 53 -nn 2>/dev/null | while read line; do
        # Check for queries to known malicious domains
        for domain in "${MALICIOUS_DOMAINS[@]}"; do
            if echo "$line" | grep -qi "$domain"; then
                log_message "ALERT" "DNS tunneling attempt detected to: $domain"
                log_message "ALERT" "Traffic: $line"
            fi
        done
    done
    
    log_message "INFO" "DNS tunneling detection completed"
}

#===============================================================================
# Function: Block unauthorized FTP connections
#===============================================================================
block_ftp_exfiltration() {
    log_message "INFO" "Implementing FTP exfiltration prevention..."
    
    # Block outbound FTP to non-whitelisted servers
    # Allow only internal FTP if needed
    iptables -A OUTPUT -p tcp --dport $FTP_PORT -j DROP
    iptables -A OUTPUT -p tcp --dport 20 -j DROP  # FTP data port
    
    log_message "ALERT" "Blocked all outbound FTP connections"
    log_message "INFO" "FTP exfiltration prevention implemented"
}

#===============================================================================
# Function: Secure Modbus/ICS network
#===============================================================================
secure_ics_network() {
    log_message "INFO" "Implementing ICS network security measures..."
    
    # Block external access to Modbus port
    iptables -A INPUT -p tcp --dport $MODBUS_PORT -s 10.0.0.0/24 -j ACCEPT
    iptables -A INPUT -p tcp --dport $MODBUS_PORT -j DROP
    
    log_message "INFO" "Modbus port restricted to internal network only"
    
    # Block Telnet (insecure protocol)
    iptables -A INPUT -p tcp --dport $TELNET_PORT -j DROP
    iptables -A OUTPUT -p tcp --dport $TELNET_PORT -j DROP
    
    log_message "INFO" "Telnet port blocked (insecure protocol)"
    
    # Restrict RDP access
    iptables -A INPUT -p tcp --dport $RDP_PORT -s 10.0.0.0/24 -j ACCEPT
    iptables -A INPUT -p tcp --dport $RDP_PORT -j DROP
    
    log_message "INFO" "RDP restricted to internal network only"
    log_message "INFO" "ICS network security measures implemented"
}

#===============================================================================
# Function: Generate threat report
#===============================================================================
generate_threat_report() {
    local report_file="/tmp/thames_water_threat_report_$(date +%Y%m%d_%H%M%S).txt"
    
    log_message "INFO" "Generating threat report..."
    
    {
        echo "=========================================="
        echo "Thames Water Defense - Threat Report"
        echo "Generated: $(date)"
        echo "=========================================="
        echo ""
        echo "BLOCKED MALICIOUS IPs:"
        for ip in "${MALICIOUS_IPS[@]}"; do
            echo "  - $ip"
        done
        echo ""
        echo "BLOCKED MALICIOUS DOMAINS:"
        for domain in "${MALICIOUS_DOMAINS[@]}"; do
            echo "  - $domain"
        done
        echo ""
        echo "ACTIVE FIREWALL RULES:"
        iptables -L -n --line-numbers 2>/dev/null
        echo ""
        echo "CURRENT NETWORK CONNECTIONS:"
        netstat -tuln 2>/dev/null || ss -tuln
        echo ""
        echo "RECENT SECURITY EVENTS:"
        tail -20 "$LOG_FILE" 2>/dev/null
        echo ""
        echo "=========================================="
    } > "$report_file"
    
    log_message "INFO" "Threat report saved to: $report_file"
    echo -e "${GREEN}Report generated: $report_file${NC}"
}

#===============================================================================
# Function: Check for active threats
#===============================================================================
check_active_threats() {
    log_message "INFO" "Checking for active threats..."
    
    local threats_found=0
    
    # Check for connections to malicious IPs
    for ip in "${MALICIOUS_IPS[@]}"; do
        if netstat -an 2>/dev/null | grep -q "$ip" || ss -an 2>/dev/null | grep -q "$ip"; then
            log_message "ALERT" "Active connection detected to malicious IP: $ip"
            threats_found=$((threats_found + 1))
        fi
    done
    
    # Check for Modbus connections from unexpected sources
    modbus_connections=$(netstat -an 2>/dev/null | grep ":$MODBUS_PORT" | grep -v "10.0.0" || ss -an 2>/dev/null | grep ":$MODBUS_PORT" | grep -v "10.0.0")
    if [[ -n "$modbus_connections" ]]; then
        log_message "ALERT" "Suspicious Modbus connections detected:"
        echo "$modbus_connections"
        threats_found=$((threats_found + 1))
    fi
    
    if [[ $threats_found -eq 0 ]]; then
        log_message "INFO" "No active threats detected"
    else
        log_message "ALERT" "Total active threats found: $threats_found"
    fi
}

#===============================================================================
# Function: Display menu
#===============================================================================
show_menu() {
    echo ""
    echo -e "${BLUE}Select an option:${NC}"
    echo "1) Block all malicious IPs"
    echo "2) Block malicious domains"
    echo "3) Monitor Modbus traffic"
    echo "4) Detect DNS tunneling"
    echo "5) Block FTP exfiltration"
    echo "6) Secure ICS network"
    echo "7) Check for active threats"
    echo "8) Generate threat report"
    echo "9) Run ALL defenses"
    echo "0) Exit"
    echo ""
    read -p "Enter your choice: " choice
}

#===============================================================================
# Function: Run all defenses
#===============================================================================
run_all_defenses() {
    log_message "INFO" "Running all defense measures..."
    block_malicious_ips
    block_malicious_domains
    block_ftp_exfiltration
    secure_ics_network
    check_active_threats
    generate_threat_report
    log_message "INFO" "All defense measures completed"
}

#===============================================================================
# Main execution
#===============================================================================
main() {
    print_banner
    check_root
    
    # Create log file if it doesn't exist
    touch "$LOG_FILE"
    
    log_message "INFO" "Thames Water Defense Script started"
    
    while true; do
        show_menu
        
        case $choice in
            1)
                block_malicious_ips
                ;;
            2)
                block_malicious_domains
                ;;
            3)
                monitor_modbus_traffic
                ;;
            4)
                detect_dns_tunneling
                ;;
            5)
                block_ftp_exfiltration
                ;;
            6)
                secure_ics_network
                ;;
            7)
                check_active_threats
                ;;
            8)
                generate_threat_report
                ;;
            9)
                run_all_defenses
                ;;
            0)
                log_message "INFO" "Thames Water Defense Script terminated"
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
    done
}

# Run main function
main "$@"
