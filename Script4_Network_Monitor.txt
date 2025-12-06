#!/bin/bash

#===============================================================================
# Thames Water Treatment Facility - Real-Time Network Monitor
#===============================================================================
# Purpose: Continuous monitoring of network traffic for attack indicators
# Author: Cyber Operations Analyst
# Date: October 2025
#
# This script provides real-time monitoring for:
#   - Active connections to malicious IPs
#   - Modbus/ICS traffic anomalies
#   - DNS query patterns
#   - Network bandwidth anomalies
#   - New connection alerts
#
# Features:
#   - Live dashboard display
#   - Automatic alerting
#   - Log rotation
#   - Email notifications (optional)
#===============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Configuration
MONITOR_INTERVAL=5  # seconds
LOG_DIR="/var/log/thames_water_monitor"
ALERT_LOG="$LOG_DIR/alerts.log"
STATS_LOG="$LOG_DIR/statistics.log"
CONNECTIONS_LOG="$LOG_DIR/connections.log"

# Threat indicators from PCAP analysis
MALICIOUS_IPS=("203.0.113.5" "198.51.100.12" "103.20.10.1" "192.0.2.25")
MALICIOUS_DOMAINS=("updcdn.ru" "syslog-host.cn")
COMPROMISED_HOSTS=("10.0.0.30" "10.0.0.40")
CRITICAL_PORTS=(502 21 23 3389 445)

# Counters
declare -A CONNECTION_COUNT
declare -A ALERT_COUNT
TOTAL_ALERTS=0
MONITORING_START=""

#===============================================================================
# Initialize monitoring environment
#===============================================================================
init_monitor() {
    # Create log directory
    mkdir -p "$LOG_DIR" 2>/dev/null
    
    # Initialize log files
    touch "$ALERT_LOG" "$STATS_LOG" "$CONNECTIONS_LOG" 2>/dev/null
    
    # Set monitoring start time
    MONITORING_START=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Initialize counters
    for ip in "${MALICIOUS_IPS[@]}"; do
        CONNECTION_COUNT[$ip]=0
        ALERT_COUNT[$ip]=0
    done
}

#===============================================================================
# Print dashboard header
#===============================================================================
print_header() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║          THAMES WATER TREATMENT FACILITY - NETWORK MONITOR               ║"
    echo "║                      Real-Time Threat Detection                          ║"
    echo "╠══════════════════════════════════════════════════════════════════════════╣"
    echo -e "║  Started: ${WHITE}$MONITORING_START${CYAN}                                          ║"
    echo -e "║  Current: ${WHITE}$(date '+%Y-%m-%d %H:%M:%S')${CYAN}                                          ║"
    echo -e "║  Total Alerts: ${RED}$TOTAL_ALERTS${CYAN}                                                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#===============================================================================
# Log alert
#===============================================================================
log_alert() {
    local severity=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$severity] $message" >> "$ALERT_LOG"
    TOTAL_ALERTS=$((TOTAL_ALERTS + 1))
    
    case $severity in
        "CRITICAL")
            echo -e "${RED}${BOLD}[CRITICAL]${NC} ${RED}$message${NC}"
            ;;
        "HIGH")
            echo -e "${RED}[HIGH]${NC} $message"
            ;;
        "MEDIUM")
            echo -e "${YELLOW}[MEDIUM]${NC} $message"
            ;;
        "LOW")
            echo -e "${GREEN}[LOW]${NC} $message"
            ;;
    esac
}

#===============================================================================
# Check for connections to malicious IPs
#===============================================================================
check_malicious_connections() {
    echo -e "\n${BLUE}[MALICIOUS IP MONITORING]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    local found_threat=false
    
    for ip in "${MALICIOUS_IPS[@]}"; do
        # Check active connections
        local count=$(ss -an 2>/dev/null | grep -c "$ip" || netstat -an 2>/dev/null | grep -c "$ip" || echo "0")
        
        if [ "$count" -gt 0 ]; then
            found_threat=true
            log_alert "CRITICAL" "Active connection to malicious IP: $ip (Count: $count)"
            CONNECTION_COUNT[$ip]=$((CONNECTION_COUNT[$ip] + count))
        fi
        
        # Display status
        if [ "$count" -gt 0 ]; then
            echo -e "  ${RED}●${NC} $ip: ${RED}$count active connections${NC}"
        else
            echo -e "  ${GREEN}●${NC} $ip: ${GREEN}No connections${NC}"
        fi
    done
    
    if [ "$found_threat" = false ]; then
        echo -e "  ${GREEN}✓ No connections to known malicious IPs${NC}"
    fi
}

#===============================================================================
# Monitor Modbus/ICS traffic
#===============================================================================
monitor_modbus() {
    echo -e "\n${BLUE}[MODBUS/ICS MONITORING - Port 502]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    # Check for Modbus connections
    local modbus_conns=$(ss -an 2>/dev/null | grep ":502" || netstat -an 2>/dev/null | grep ":502" || echo "")
    
    if [ -n "$modbus_conns" ]; then
        local count=$(echo "$modbus_conns" | wc -l)
        echo -e "  ${YELLOW}Active Modbus connections: $count${NC}"
        
        # Check for connections from compromised hosts
        for host in "${COMPROMISED_HOSTS[@]}"; do
            if echo "$modbus_conns" | grep -q "$host"; then
                log_alert "CRITICAL" "Modbus connection from compromised host: $host"
            fi
        done
        
        # Check for external Modbus connections
        if echo "$modbus_conns" | grep -v "10.0.0" | grep -q ":502"; then
            log_alert "HIGH" "External Modbus connection detected!"
        fi
        
        # Display connections
        echo "$modbus_conns" | head -5 | while read line; do
            echo -e "    ${CYAN}$line${NC}"
        done
    else
        echo -e "  ${GREEN}✓ No active Modbus connections${NC}"
    fi
}

#===============================================================================
# Monitor DNS queries
#===============================================================================
monitor_dns() {
    echo -e "\n${BLUE}[DNS MONITORING]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    # Check DNS cache/queries if available
    if command -v resolvectl &> /dev/null; then
        echo -e "  ${CYAN}Recent DNS statistics:${NC}"
        resolvectl statistics 2>/dev/null | head -5 | while read line; do
            echo "    $line"
        done
    fi
    
    # Check for suspicious domain resolutions
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if grep -q "$domain" /etc/hosts 2>/dev/null; then
            echo -e "  ${GREEN}✓ $domain is blocked in /etc/hosts${NC}"
        else
            echo -e "  ${YELLOW}⚠ $domain is NOT blocked${NC}"
        fi
    done
    
    # Monitor DNS traffic briefly
    if command -v tcpdump &> /dev/null; then
        echo -e "\n  ${CYAN}Live DNS queries (5 second sample):${NC}"
        timeout 2 tcpdump -i any port 53 -nn -c 10 2>/dev/null | while read line; do
            # Check for malicious domains
            for domain in "${MALICIOUS_DOMAINS[@]}"; do
                if echo "$line" | grep -qi "$domain"; then
                    log_alert "CRITICAL" "DNS query to malicious domain: $domain"
                fi
            done
            echo "    $line" | head -c 70
            echo "..."
        done
    fi
}

#===============================================================================
# Monitor critical ports
#===============================================================================
monitor_critical_ports() {
    echo -e "\n${BLUE}[CRITICAL PORTS MONITORING]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    printf "  %-10s %-20s %-15s\n" "PORT" "SERVICE" "STATUS"
    echo "  ──────────────────────────────────────────────"
    
    declare -A PORT_NAMES=(
        [21]="FTP"
        [22]="SSH"
        [23]="Telnet"
        [80]="HTTP"
        [443]="HTTPS"
        [445]="SMB"
        [502]="Modbus"
        [3389]="RDP"
    )
    
    for port in 21 22 23 80 443 445 502 3389; do
        local service=${PORT_NAMES[$port]}
        local listening=$(ss -tln 2>/dev/null | grep -c ":$port " || netstat -tln 2>/dev/null | grep -c ":$port " || echo "0")
        local connections=$(ss -tn 2>/dev/null | grep -c ":$port " || netstat -tn 2>/dev/null | grep -c ":$port " || echo "0")
        
        if [ "$listening" -gt 0 ]; then
            if [ "$port" -eq 23 ]; then
                printf "  ${RED}%-10s %-20s %-15s${NC}\n" "$port" "$service" "LISTENING (INSECURE!)"
                log_alert "MEDIUM" "Insecure Telnet port is open"
            else
                printf "  ${YELLOW}%-10s %-20s %-15s${NC}\n" "$port" "$service" "LISTENING ($connections conn)"
            fi
        else
            printf "  ${GREEN}%-10s %-20s %-15s${NC}\n" "$port" "$service" "Closed"
        fi
    done
}

#===============================================================================
# Monitor network bandwidth
#===============================================================================
monitor_bandwidth() {
    echo -e "\n${BLUE}[NETWORK BANDWIDTH]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    # Get network interface
    local interface=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [ -n "$interface" ]; then
        # Get current stats
        local rx_bytes=$(cat /sys/class/net/$interface/statistics/rx_bytes 2>/dev/null || echo "0")
        local tx_bytes=$(cat /sys/class/net/$interface/statistics/tx_bytes 2>/dev/null || echo "0")
        
        # Convert to MB
        local rx_mb=$((rx_bytes / 1024 / 1024))
        local tx_mb=$((tx_bytes / 1024 / 1024))
        
        echo -e "  Interface: ${CYAN}$interface${NC}"
        echo -e "  Received:  ${GREEN}$rx_mb MB${NC}"
        echo -e "  Sent:      ${YELLOW}$tx_mb MB${NC}"
        
        # Check for unusual outbound traffic
        if [ "$tx_mb" -gt 1000 ]; then
            log_alert "MEDIUM" "High outbound traffic detected: $tx_mb MB"
        fi
    else
        echo -e "  ${YELLOW}Could not determine network interface${NC}"
    fi
}

#===============================================================================
# Monitor compromised hosts
#===============================================================================
monitor_compromised_hosts() {
    echo -e "\n${BLUE}[COMPROMISED HOSTS MONITORING]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    for host in "${COMPROMISED_HOSTS[@]}"; do
        echo -e "  ${YELLOW}Checking $host:${NC}"
        
        # Check outbound connections from this host
        local outbound=$(ss -tn 2>/dev/null | grep "$host" | grep -v "10.0.0" || echo "")
        
        if [ -n "$outbound" ]; then
            local count=$(echo "$outbound" | wc -l)
            log_alert "HIGH" "Compromised host $host has $count external connections"
            echo -e "    ${RED}⚠ External connections detected: $count${NC}"
        else
            echo -e "    ${GREEN}✓ No suspicious external connections${NC}"
        fi
    done
}

#===============================================================================
# Display alert summary
#===============================================================================
display_alert_summary() {
    echo -e "\n${BLUE}[ALERT SUMMARY]${NC}"
    echo "─────────────────────────────────────────────────────────────────────────"
    
    if [ -f "$ALERT_LOG" ]; then
        local critical=$(grep -c "CRITICAL" "$ALERT_LOG" 2>/dev/null || echo "0")
        local high=$(grep -c "HIGH" "$ALERT_LOG" 2>/dev/null || echo "0")
        local medium=$(grep -c "MEDIUM" "$ALERT_LOG" 2>/dev/null || echo "0")
        local low=$(grep -c "LOW" "$ALERT_LOG" 2>/dev/null || echo "0")
        
        echo -e "  ${RED}CRITICAL: $critical${NC}"
        echo -e "  ${RED}HIGH:     $high${NC}"
        echo -e "  ${YELLOW}MEDIUM:   $medium${NC}"
        echo -e "  ${GREEN}LOW:      $low${NC}"
        echo ""
        
        # Show last 5 alerts
        echo -e "  ${CYAN}Recent Alerts:${NC}"
        tail -5 "$ALERT_LOG" 2>/dev/null | while read line; do
            echo "    $line"
        done
    else
        echo -e "  ${GREEN}No alerts recorded${NC}"
    fi
}

#===============================================================================
# Display footer with controls
#===============================================================================
display_footer() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${WHITE}Refresh: ${MONITOR_INTERVAL}s${NC} | ${WHITE}Press Ctrl+C to stop${NC} | ${WHITE}Logs: $LOG_DIR${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
}

#===============================================================================
# Run single monitoring cycle
#===============================================================================
run_monitoring_cycle() {
    print_header
    check_malicious_connections
    monitor_modbus
    monitor_critical_ports
    monitor_compromised_hosts
    monitor_bandwidth
    monitor_dns
    display_alert_summary
    display_footer
}

#===============================================================================
# Cleanup on exit
#===============================================================================
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping network monitor...${NC}"
    echo ""
    echo -e "${CYAN}Session Summary:${NC}"
    echo "  Started: $MONITORING_START"
    echo "  Ended:   $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  Total Alerts: $TOTAL_ALERTS"
    echo "  Logs saved to: $LOG_DIR"
    echo ""
    exit 0
}

#===============================================================================
# Check root privileges
#===============================================================================
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[WARNING]${NC} Running without root privileges."
        echo "Some monitoring features may be limited."
        echo "For full functionality, run: sudo $0"
        echo ""
        read -p "Continue anyway? (y/n): " choice
        if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
            exit 1
        fi
    fi
}

#===============================================================================
# Print banner for non-interactive mode
#===============================================================================
print_static_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║          THAMES WATER TREATMENT FACILITY - NETWORK MONITOR               ║"
    echo "║                      Real-Time Threat Detection                          ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#===============================================================================
# Run single check (non-interactive mode)
#===============================================================================
run_single_check() {
    print_static_banner
    echo -e "${GREEN}[INFO]${NC} Running single security check..."
    echo ""
    
    init_monitor
    
    check_malicious_connections
    monitor_modbus
    monitor_critical_ports
    monitor_compromised_hosts
    monitor_bandwidth
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}[COMPLETE]${NC} Security check finished. Total alerts: $TOTAL_ALERTS"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════${NC}"
}

#===============================================================================
# Main execution
#===============================================================================
main() {
    # Handle command line arguments
    case "${1:-}" in
        "--once"|"-o")
            check_root
            run_single_check
            exit 0
            ;;
        "--help"|"-h")
            echo "Thames Water Network Monitor"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --once, -o     Run single check and exit"
            echo "  --help, -h     Show this help message"
            echo ""
            echo "Default: Run continuous monitoring"
            exit 0
            ;;
    esac
    
    # Set up signal handlers
    trap cleanup SIGINT SIGTERM
    
    # Check privileges
    check_root
    
    # Initialize
    init_monitor
    
    echo -e "${GREEN}[INFO]${NC} Starting continuous monitoring..."
    echo -e "${GREEN}[INFO]${NC} Press Ctrl+C to stop"
    sleep 2
    
    # Main monitoring loop
    while true; do
        run_monitoring_cycle
        sleep $MONITOR_INTERVAL
    done
}

# Run main
main "$@"
