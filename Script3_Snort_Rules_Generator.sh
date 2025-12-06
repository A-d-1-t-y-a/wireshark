#!/bin/bash

#===============================================================================
# Thames Water Treatment Facility - Snort IDS Rules Generator
#===============================================================================
# Purpose: Generate Snort/Suricata IDS rules to detect Thames Water attack patterns
# Author: Cyber Operations Analyst
# Date: October 2025
#
# This script creates custom IDS rules to detect:
#   - C2 communications to known malicious domains
#   - Modbus/ICS protocol attacks
#   - FTP data exfiltration patterns
#   - DNS tunneling attempts
#   - Port scanning activity
#   - Phishing payload indicators
#
# Output: Snort-compatible rules file for immediate deployment
#===============================================================================

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
RULES_FILE="thames_water_snort.rules"
SURICATA_RULES_FILE="thames_water_suricata.rules"
LOG_FILE="snort_rules_generator.log"

# Malicious indicators from PCAP analysis
declare -A MALICIOUS_IPS=(
    ["203.0.113.5"]="C2_Server_updcdn_ru"
    ["198.51.100.12"]="FTP_Exfiltration_Server"
    ["103.20.10.1"]="DDoS_Source"
    ["192.0.2.25"]="Port_Scanner"
)

MALICIOUS_DOMAINS=("updcdn.ru" "syslog-host.cn")

# Compromised internal hosts
COMPROMISED_HOSTS=("10.0.0.30" "10.0.0.40")
PLC_TARGET="10.0.0.10"

#===============================================================================
# Print banner
#===============================================================================
print_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║     Thames Water Treatment Facility - Snort Rules Generator        ║"
    echo "║                  Intrusion Detection System Rules                  ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

#===============================================================================
# Log function
#===============================================================================
log_msg() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO") echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN") echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "RULE") echo -e "${PURPLE}[RULE]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
}

#===============================================================================
# Generate Snort rules header
#===============================================================================
generate_header() {
    cat << 'EOF'
#===============================================================================
# Thames Water Treatment Facility - Custom Snort/Suricata Rules
#===============================================================================
# Generated: $(date)
# Purpose: Detect attack patterns from Thames Water cyberattack
# 
# Rule Categories:
#   - SID 1000001-1000010: C2 Communication Detection
#   - SID 1000011-1000020: Modbus/ICS Attack Detection
#   - SID 1000021-1000030: Data Exfiltration Detection
#   - SID 1000031-1000040: DNS Tunneling Detection
#   - SID 1000041-1000050: Reconnaissance Detection
#
# Deployment:
#   1. Copy rules to /etc/snort/rules/ or /etc/suricata/rules/
#   2. Add 'include $RULE_PATH/thames_water_snort.rules' to snort.conf
#   3. Restart Snort/Suricata service
#===============================================================================

EOF
}

#===============================================================================
# Generate C2 detection rules
#===============================================================================
generate_c2_rules() {
    log_msg "RULE" "Generating C2 communication detection rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# C2 Communication Detection Rules
#-------------------------------------------------------------------------------

# Detect HTTP POST to known C2 domain (updcdn.ru)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THAMES-WATER C2 Communication to updcdn.ru"; flow:established,to_server; content:"Host|3a| updcdn.ru"; nocase; http_header; classtype:trojan-activity; sid:1000001; rev:1; priority:1;)

# Detect PHISH-TOKEN exfiltration pattern
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THAMES-WATER Phishing Token Exfiltration"; flow:established,to_server; content:"PHISH-TOKEN"; nocase; http_client_body; classtype:trojan-activity; sid:1000002; rev:1; priority:1;)

# Detect POST to /login endpoint (C2 beacon pattern)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"THAMES-WATER C2 Beacon POST /login"; flow:established,to_server; content:"POST"; http_method; content:"/login"; http_uri; content:"payload="; http_client_body; classtype:trojan-activity; sid:1000003; rev:1; priority:1;)

# Detect traffic to C2 server IP
alert ip $HOME_NET any -> 203.0.113.5 any (msg:"THAMES-WATER Traffic to C2 Server 203.0.113.5"; classtype:trojan-activity; sid:1000004; rev:1; priority:1;)

# Detect traffic to exfiltration server
alert ip $HOME_NET any -> 198.51.100.12 any (msg:"THAMES-WATER Traffic to Exfil Server 198.51.100.12"; classtype:trojan-activity; sid:1000005; rev:1; priority:2;)

# Detect traffic from DDoS source
alert ip 103.20.10.1 any -> $HOME_NET any (msg:"THAMES-WATER Traffic from DDoS Source 103.20.10.1"; classtype:attempted-dos; sid:1000006; rev:1; priority:1;)

EOF
}

#===============================================================================
# Generate Modbus/ICS attack detection rules
#===============================================================================
generate_modbus_rules() {
    log_msg "RULE" "Generating Modbus/ICS attack detection rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# Modbus/ICS Attack Detection Rules
#-------------------------------------------------------------------------------

# Detect Modbus Write Multiple Registers (Function Code 16) - Attack Pattern
alert tcp any any -> $HOME_NET 502 (msg:"THAMES-WATER Modbus Write Multiple Registers Attack"; flow:established,to_server; content:"|00 00|"; offset:0; depth:2; content:"|00 00 00|"; distance:0; byte_test:1,=,16,7; classtype:attempted-admin; sid:1000011; rev:1; priority:1;)

# Detect Modbus traffic from non-HMI sources
alert tcp !10.0.0.51 any -> 10.0.0.10 502 (msg:"THAMES-WATER Unauthorized Modbus Access to PLC"; flow:established; classtype:attempted-admin; sid:1000012; rev:1; priority:1;)

# Detect Modbus traffic from compromised workstation
alert tcp 10.0.0.30 any -> 10.0.0.10 502 (msg:"THAMES-WATER Modbus from Compromised Host 10.0.0.30"; flow:established; classtype:attempted-admin; sid:1000013; rev:1; priority:1;)

# Detect high volume Modbus commands (potential attack)
alert tcp any any -> $HOME_NET 502 (msg:"THAMES-WATER High Volume Modbus Traffic"; flow:established; threshold:type both, track by_src, count 50, seconds 60; classtype:attempted-admin; sid:1000014; rev:1; priority:2;)

# Detect Modbus from external network
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"THAMES-WATER External Modbus Connection Attempt"; flow:to_server; classtype:attempted-admin; sid:1000015; rev:1; priority:1;)

EOF
}

#===============================================================================
# Generate data exfiltration detection rules
#===============================================================================
generate_exfil_rules() {
    log_msg "RULE" "Generating data exfiltration detection rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# Data Exfiltration Detection Rules
#-------------------------------------------------------------------------------

# Detect FTP STOR command to external server
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"THAMES-WATER FTP Upload to External Server"; flow:established,to_server; content:"STOR"; nocase; classtype:policy-violation; sid:1000021; rev:1; priority:2;)

# Detect FTP upload with suspicious filename pattern
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"THAMES-WATER FTP Exfil - Secret Chunk Pattern"; flow:established,to_server; content:"STOR"; nocase; content:"secret-chunk"; nocase; classtype:trojan-activity; sid:1000022; rev:1; priority:1;)

# Detect FTP to known exfiltration server
alert tcp $HOME_NET any -> 198.51.100.12 21 (msg:"THAMES-WATER FTP to Known Exfil Server"; flow:established; classtype:trojan-activity; sid:1000023; rev:1; priority:1;)

# Detect large outbound data transfer
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"THAMES-WATER Large Outbound Data Transfer"; flow:established,to_server; dsize:>1000; threshold:type both, track by_src, count 100, seconds 60; classtype:policy-violation; sid:1000024; rev:1; priority:2;)

# Detect data transfer from compromised admin workstation
alert tcp 10.0.0.30 any -> $EXTERNAL_NET any (msg:"THAMES-WATER Outbound from Compromised Admin Host"; flow:established,to_server; classtype:trojan-activity; sid:1000025; rev:1; priority:1;)

EOF
}

#===============================================================================
# Generate DNS tunneling detection rules
#===============================================================================
generate_dns_rules() {
    log_msg "RULE" "Generating DNS tunneling detection rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# DNS Tunneling Detection Rules
#-------------------------------------------------------------------------------

# Detect DNS queries to known malicious domain (syslog-host.cn)
alert udp $HOME_NET any -> any 53 (msg:"THAMES-WATER DNS Query to Malicious Domain syslog-host.cn"; content:"|0b|syslog-host|02|cn"; nocase; classtype:trojan-activity; sid:1000031; rev:1; priority:1;)

# Detect DNS queries to .cn TLD (suspicious for UK infrastructure)
alert udp $HOME_NET any -> any 53 (msg:"THAMES-WATER DNS Query to .cn Domain"; content:"|02|cn|00|"; classtype:policy-violation; sid:1000032; rev:1; priority:3;)

# Detect DNS queries to .ru TLD (suspicious for UK infrastructure)
alert udp $HOME_NET any -> any 53 (msg:"THAMES-WATER DNS Query to .ru Domain"; content:"|02|ru|00|"; classtype:policy-violation; sid:1000033; rev:1; priority:3;)

# Detect high frequency DNS queries (potential tunneling)
alert udp $HOME_NET any -> any 53 (msg:"THAMES-WATER High Frequency DNS - Possible Tunneling"; threshold:type both, track by_src, count 100, seconds 60; classtype:trojan-activity; sid:1000034; rev:1; priority:2;)

# Detect unusually long DNS queries (tunneling indicator)
alert udp $HOME_NET any -> any 53 (msg:"THAMES-WATER Long DNS Query - Possible Tunneling"; dsize:>100; classtype:trojan-activity; sid:1000035; rev:1; priority:2;)

EOF
}

#===============================================================================
# Generate reconnaissance detection rules
#===============================================================================
generate_recon_rules() {
    log_msg "RULE" "Generating reconnaissance detection rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# Reconnaissance Detection Rules
#-------------------------------------------------------------------------------

# Detect port scanning from known scanner IP
alert tcp 192.0.2.25 any -> $HOME_NET any (msg:"THAMES-WATER Port Scan from Known Scanner"; flags:S; threshold:type both, track by_src, count 20, seconds 10; classtype:attempted-recon; sid:1000041; rev:1; priority:2;)

# Detect Telnet connection attempts (insecure protocol)
alert tcp any any -> $HOME_NET 23 (msg:"THAMES-WATER Telnet Connection Attempt"; flow:to_server; classtype:attempted-admin; sid:1000042; rev:1; priority:2;)

# Detect RDP connection from external network
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"THAMES-WATER External RDP Connection Attempt"; flow:to_server; classtype:attempted-admin; sid:1000043; rev:1; priority:2;)

# Detect SMB connection from external network
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"THAMES-WATER External SMB Connection Attempt"; flow:to_server; classtype:attempted-admin; sid:1000044; rev:1; priority:2;)

# Detect SYN scan pattern
alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"THAMES-WATER SYN Scan Detected"; flags:S,12; threshold:type both, track by_src, count 50, seconds 30; classtype:attempted-recon; sid:1000045; rev:1; priority:2;)

# Detect connection to Modbus port from external
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 (msg:"THAMES-WATER External Modbus Scan"; flow:to_server; classtype:attempted-recon; sid:1000046; rev:1; priority:1;)

EOF
}

#===============================================================================
# Generate IP blocklist rules
#===============================================================================
generate_blocklist_rules() {
    log_msg "RULE" "Generating IP blocklist rules..."
    
    cat << 'EOF'
#-------------------------------------------------------------------------------
# IP Blocklist Rules (Drop/Reject)
#-------------------------------------------------------------------------------

# Block all traffic from/to C2 server
drop ip 203.0.113.5 any <> $HOME_NET any (msg:"THAMES-WATER BLOCKED C2 Server"; classtype:trojan-activity; sid:1000051; rev:1; priority:1;)

# Block all traffic from/to exfiltration server
drop ip 198.51.100.12 any <> $HOME_NET any (msg:"THAMES-WATER BLOCKED Exfil Server"; classtype:trojan-activity; sid:1000052; rev:1; priority:1;)

# Block all traffic from DDoS source
drop ip 103.20.10.1 any -> $HOME_NET any (msg:"THAMES-WATER BLOCKED DDoS Source"; classtype:attempted-dos; sid:1000053; rev:1; priority:1;)

# Block all traffic from scanner
drop ip 192.0.2.25 any -> $HOME_NET any (msg:"THAMES-WATER BLOCKED Scanner"; classtype:attempted-recon; sid:1000054; rev:1; priority:2;)

EOF
}

#===============================================================================
# Generate complete rules file
#===============================================================================
generate_rules_file() {
    log_msg "INFO" "Generating Snort rules file: $RULES_FILE"
    
    # Create rules file
    {
        generate_header
        generate_c2_rules
        generate_modbus_rules
        generate_exfil_rules
        generate_dns_rules
        generate_recon_rules
        generate_blocklist_rules
        
        echo ""
        echo "# End of Thames Water custom rules"
        echo "# Total rules generated: 30+"
        
    } > "$RULES_FILE"
    
    # Fix the date in header
    sed -i "s/\$(date)/$(date)/" "$RULES_FILE" 2>/dev/null || \
    sed "s/\$(date)/$(date)/" "$RULES_FILE" > "${RULES_FILE}.tmp" && mv "${RULES_FILE}.tmp" "$RULES_FILE"
    
    log_msg "SUCCESS" "Rules file created: $RULES_FILE"
}

#===============================================================================
# Validate rules syntax
#===============================================================================
validate_rules() {
    log_msg "INFO" "Validating rules syntax..."
    
    if command -v snort &> /dev/null; then
        snort -T -c /etc/snort/snort.conf --rule-path="$(pwd)" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_msg "SUCCESS" "Rules validated successfully with Snort"
        else
            log_msg "WARN" "Rules validation failed - check syntax"
        fi
    else
        log_msg "WARN" "Snort not installed - skipping validation"
    fi
}

#===============================================================================
# Display rules summary
#===============================================================================
display_summary() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                        RULES GENERATION SUMMARY${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${CYAN}[RULES GENERATED]${NC}"
    echo "  - C2 Detection Rules: 6"
    echo "  - Modbus/ICS Rules: 5"
    echo "  - Exfiltration Rules: 5"
    echo "  - DNS Tunneling Rules: 5"
    echo "  - Reconnaissance Rules: 6"
    echo "  - Blocklist Rules: 4"
    echo "  ─────────────────────"
    echo "  Total Rules: 31"
    
    echo ""
    echo -e "${CYAN}[OUTPUT FILES]${NC}"
    echo "  - Snort Rules: $RULES_FILE"
    echo "  - Log File: $LOG_FILE"
    
    echo ""
    echo -e "${YELLOW}[DEPLOYMENT INSTRUCTIONS]${NC}"
    echo "  1. Copy rules to Snort/Suricata rules directory:"
    echo "     sudo cp $RULES_FILE /etc/snort/rules/"
    echo ""
    echo "  2. Add to snort.conf:"
    echo "     include \$RULE_PATH/$RULES_FILE"
    echo ""
    echo "  3. Restart Snort service:"
    echo "     sudo systemctl restart snort"
    echo ""
    echo "  4. Monitor alerts:"
    echo "     tail -f /var/log/snort/alert"
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
}

#===============================================================================
# Main execution
#===============================================================================
main() {
    print_banner
    
    log_msg "INFO" "Starting Snort rules generation..."
    
    # Generate rules
    generate_rules_file
    
    # Validate if possible
    validate_rules
    
    # Display summary
    display_summary
    
    log_msg "SUCCESS" "Rules generation completed successfully"
    
    # Show first few rules as preview
    echo ""
    echo -e "${PURPLE}[RULES PREVIEW]${NC}"
    echo "─────────────────────────────────────────────────────────────────────"
    head -50 "$RULES_FILE" | tail -30
    echo "─────────────────────────────────────────────────────────────────────"
    echo ""
}

# Run main
main "$@"
