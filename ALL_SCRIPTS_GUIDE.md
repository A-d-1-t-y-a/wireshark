# Thames Water Cyberattack - 4 Different Script Approaches

## Overview

You have **4 different scripts**, each using a unique approach to address the Thames Water cyberattack. Each script can be run independently and produces different output.

---

## Script Comparison Table

| # | Script Name | Language | Approach | Purpose |
|---|-------------|----------|----------|---------|
| 1 | `thames_water_defense.sh` | Bash | **Firewall-based** | Block IPs/domains using iptables |
| 2 | `Script2_PCAP_Analyzer.py` | Python | **Forensic Analysis** | Analyze PCAP files for threats |
| 3 | `Script3_Snort_Rules_Generator.sh` | Bash | **IDS Rules** | Generate Snort/Suricata detection rules |
| 4 | `Script4_Network_Monitor.sh` | Bash | **Real-time Monitoring** | Live network threat monitoring |

---

## Script 1: Firewall Defense (iptables)

### File: `thames_water_defense.sh` / `thames_water_defense_script.txt`

### Purpose:
Blocks malicious IPs and domains using Linux firewall (iptables) and /etc/hosts

### Features:
- Block malicious IPs (203.0.113.5, 198.51.100.12, etc.)
- Block malicious domains (updcdn.ru, syslog-host.cn)
- Secure ICS/Modbus ports
- Block FTP exfiltration
- Interactive menu system

### How to Run:
```bash
chmod +x thames_water_defense.sh
sudo ./thames_water_defense.sh
```

### Expected Output:
```
╔═══════════════════════════════════════════════════════════════════╗
║     Thames Water Treatment Facility - Network Defense System      ║
╚═══════════════════════════════════════════════════════════════════╝

Select an option:
1) Block all malicious IPs
2) Block malicious domains
...
9) Run ALL defenses

[ALERT] Blocked malicious IP: 203.0.113.5
[ALERT] Blocked malicious IP: 198.51.100.12
[INFO] Malicious IP blocking completed
```

---

## Script 2: PCAP Threat Analyzer (Python)

### File: `Script2_PCAP_Analyzer.py` / `Script2_PCAP_Analyzer.txt`

### Purpose:
Analyzes PCAP files to detect attack patterns and extract IOCs

### Features:
- Detect C2 communications
- Identify Modbus/ICS attacks
- Find FTP exfiltration
- Detect DNS tunneling
- Generate IOCs JSON file
- Works in demo mode without dependencies

### How to Run:
```bash
# With PCAP file:
python3 Script2_PCAP_Analyzer.py Thames_water_attack.pcap

# Demo mode (no dependencies needed):
python3 Script2_PCAP_Analyzer.py --demo
```

### Expected Output:
```
╔════════════════════════════════════════════════════════════════════╗
║      Thames Water Treatment Facility - PCAP Threat Analyzer        ║
╚════════════════════════════════════════════════════════════════════╝

[INFO] Running in DEMO mode with known Thames Water attack data
[THREAT] Detected 199 C2 beacons to updcdn.ru
[THREAT] Detected 199 FTP file uploads (secret-chunk-*)
[THREAT] Detected 200 Modbus write commands (Function Code 16)
[THREAT] Detected 400 DNS queries to syslog-host.cn

═══════════════════════════════════════════════════════════════════
                    THREAT ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════

[STATISTICS]
  Total Packets Analyzed: 12000
  Malicious IPs Detected: 4
  C2 Communications: 199
  FTP Exfiltration Attempts: 199
  Modbus/ICS Attacks: 200
  DNS Tunneling Queries: 400

[MALICIOUS IPs DETECTED]
  - 203.0.113.5: C2 Server (updcdn.ru)
  - 198.51.100.12: FTP Exfiltration Server
  - 103.20.10.1: DDoS Source
  - 192.0.2.25: Port Scanner

[INFO] IOCs exported to: thames_water_iocs.json
[SUMMARY] Total threats detected: 998
[COMPLETE] Analysis finished successfully
```

---

## Script 3: Snort IDS Rules Generator

### File: `Script3_Snort_Rules_Generator.sh` / `Script3_Snort_Rules_Generator.txt`

### Purpose:
Generates Snort/Suricata IDS rules to detect attack patterns

### Features:
- C2 detection rules
- Modbus/ICS attack rules
- Data exfiltration rules
- DNS tunneling rules
- Reconnaissance detection rules
- IP blocklist rules

### How to Run:
```bash
chmod +x Script3_Snort_Rules_Generator.sh
./Script3_Snort_Rules_Generator.sh
```

### Expected Output:
```
╔════════════════════════════════════════════════════════════════════╗
║     Thames Water Treatment Facility - Snort Rules Generator        ║
╚════════════════════════════════════════════════════════════════════╝

[RULE] Generating C2 communication detection rules...
[RULE] Generating Modbus/ICS attack detection rules...
[RULE] Generating data exfiltration detection rules...
[RULE] Generating DNS tunneling detection rules...
[RULE] Generating reconnaissance detection rules...
[RULE] Generating IP blocklist rules...
[SUCCESS] Rules file created: thames_water_snort.rules

═══════════════════════════════════════════════════════════════════
                        RULES GENERATION SUMMARY
═══════════════════════════════════════════════════════════════════

[RULES GENERATED]
  - C2 Detection Rules: 6
  - Modbus/ICS Rules: 5
  - Exfiltration Rules: 5
  - DNS Tunneling Rules: 5
  - Reconnaissance Rules: 6
  - Blocklist Rules: 4
  ─────────────────────
  Total Rules: 31

[OUTPUT FILES]
  - Snort Rules: thames_water_snort.rules
```

---

## Script 4: Real-Time Network Monitor

### File: `Script4_Network_Monitor.sh` / `Script4_Network_Monitor.txt`

### Purpose:
Provides continuous real-time monitoring for attack indicators

### Features:
- Live connection monitoring
- Modbus/ICS traffic detection
- Critical port monitoring
- Compromised host tracking
- Bandwidth monitoring
- DNS query analysis
- Alert logging

### How to Run:
```bash
chmod +x Script4_Network_Monitor.sh

# Continuous monitoring:
sudo ./Script4_Network_Monitor.sh

# Single check:
sudo ./Script4_Network_Monitor.sh --once
```

### Expected Output:
```
╔══════════════════════════════════════════════════════════════════════════╗
║          THAMES WATER TREATMENT FACILITY - NETWORK MONITOR               ║
║                      Real-Time Threat Detection                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Started: 2025-10-27 14:30:00                                            ║
║  Current: 2025-10-27 14:35:00                                            ║
║  Total Alerts: 0                                                         ║
╚══════════════════════════════════════════════════════════════════════════╝

[MALICIOUS IP MONITORING]
─────────────────────────────────────────────────────────────────────────
  ● 203.0.113.5: No connections
  ● 198.51.100.12: No connections
  ● 103.20.10.1: No connections
  ● 192.0.2.25: No connections
  ✓ No connections to known malicious IPs

[MODBUS/ICS MONITORING - Port 502]
─────────────────────────────────────────────────────────────────────────
  ✓ No active Modbus connections

[CRITICAL PORTS MONITORING]
─────────────────────────────────────────────────────────────────────────
  PORT       SERVICE              STATUS
  ──────────────────────────────────────────────
  21         FTP                  Closed
  22         SSH                  LISTENING (0 conn)
  23         Telnet               Closed
  502        Modbus               Closed
  3389       RDP                  Closed

═══════════════════════════════════════════════════════════════════════════
  Refresh: 5s | Press Ctrl+C to stop | Logs: /var/log/thames_water_monitor
═══════════════════════════════════════════════════════════════════════════
```

---

## Quick Reference - Running All Scripts

### In Kali VM:

```bash
# Navigate to scripts folder
cd /path/to/scripts

# Make all scripts executable
chmod +x *.sh

# Script 1: Firewall Defense
sudo ./thames_water_defense.sh

# Script 2: PCAP Analyzer
python3 Script2_PCAP_Analyzer.py --demo

# Script 3: Snort Rules Generator
./Script3_Snort_Rules_Generator.sh

# Script 4: Network Monitor (single check)
sudo ./Script4_Network_Monitor.sh --once
```

---

## Submission Files

For your assignment, submit ONE of these .txt files:

| Approach | File to Submit |
|----------|----------------|
| 1 - Firewall | `thames_water_defense_script.txt` |
| 2 - PCAP Analysis | `Script2_PCAP_Analyzer.txt` |
| 3 - IDS Rules | `Script3_Snort_Rules_Generator.txt` |
| 4 - Monitoring | `Script4_Network_Monitor.txt` |

---

## Screenshots Needed

For each script, take a screenshot showing:
1. The script running
2. The output/results
3. Any generated files

Include these in your report's Appendix.

---

## Which Script to Choose?

| If you want to show... | Use Script |
|------------------------|------------|
| Immediate threat blocking | Script 1 (Firewall) |
| Forensic analysis skills | Script 2 (PCAP Analyzer) |
| IDS/Detection capabilities | Script 3 (Snort Rules) |
| Continuous monitoring | Script 4 (Network Monitor) |

All scripts address the same attack but from different defensive perspectives!
