# Thames Water Treatment Facility Cyber Incident Report

## Executive Summary

On 27 October 2025, between 14:30 and 15:30 IST, the Thames Water Treatment Facility Control System (WTCS) suffered a sophisticated, multi-stage cyberattack combining technical intrusion with a coordinated psychological operation. The attack compromised critical infrastructure systems, exfiltrated sensitive operational data, and attempted to sabotage industrial control systems responsible for water purification and chemical dosing.

### Key Findings:
- **Initial Access**: Spear-phishing campaign compromised plant administrator credentials
- **Compromised Systems**: 2 workstations (10.0.0.30, 10.0.0.40) and 1 PLC controller (10.0.0.10)
- **Data Exfiltration**: 199 files containing sensitive operational data stolen via FTP
- **ICS Sabotage**: 200 Modbus write commands sent to PLC controlling water treatment processes
- **Psychological Operation**: Coordinated disinformation campaign across social media and fake news outlets
- **Attribution**: Evidence suggests state-sponsored actors with Russian and Chinese infrastructure involvement

### Impact Assessment:
- **Operational**: Potential manipulation of chemical dosing systems
- **Data Loss**: Classified operational data exfiltrated
- **Public Trust**: Disinformation campaign caused public panic and distrust
- **Economic**: Bottled water shortages, emergency response costs

---

## 1. Threat Intelligence Analysis

### 1.1 Attacker Profile (MOC Attributes)

Based on the analysis of network traffic and multimedia evidence, the attack exhibits characteristics consistent with a **state-sponsored Advanced Persistent Threat (APT)** group.

#### Means:
- **Technical Sophistication**: Multi-stage attack combining phishing, C2 infrastructure, ICS exploitation, and DDoS
- **Infrastructure**: Dedicated C2 servers (updcdn.ru), FTP exfiltration servers, DNS tunneling infrastructure
- **Tools**: Custom malware with beaconing capability, Modbus exploitation tools, data chunking for exfiltration

#### Opportunity:
- **Target Selection**: Critical National Infrastructure (CNI) - water treatment facility
- **Timing**: Attack coincided with geopolitical tensions affecting UK
- **Access Vector**: Exploited human factor through spear-phishing of plant administrator

#### Capability:
- **ICS Knowledge**: Demonstrated understanding of Modbus protocol and SCADA systems
- **Operational Security**: Used multiple C2 channels (HTTP, DNS tunneling)
- **Coordination**: Synchronized cyber attack with psychological operation

### 1.2 Attribution Analysis

| Indicator | Evidence | Attribution |
|-----------|----------|-------------|
| C2 Domain | updcdn.ru (.ru TLD) | Russian infrastructure |
| DNS Tunneling | syslog-host.cn (.cn TLD) | Chinese infrastructure |
| Target | UK Critical Infrastructure | State-level interest |
| Sophistication | ICS/SCADA targeting | APT-level capability |
| Coordination | Cyber + PsyOps | State-sponsored resources |

**Assessment**: The attack likely involves cooperation between Russian and Chinese threat actors, or a single actor using infrastructure in both countries for obfuscation. Possible APT groups include APT28 (Fancy Bear), APT44 (Sandworm), or APT1.

### 1.3 Disinformation Campaign Analysis

#### Target Audience:
- London residents and surrounding communities
- General UK public
- Social media users

#### Intended Message:
- Water supply is contaminated with toxic chemicals (Chloramine-T)
- Government is covering up the crisis
- Immediate health risks require avoiding tap water

#### Distribution Channels:
1. **Fake News Websites**: The National Post, The Daily Chronicle, London Dispatch
2. **Social Media**: Twitter/X accounts with fake verification badges
3. **Messaging Apps**: WhatsApp group "London Water Alert"

#### Manipulation Techniques:
- **Fear Appeal**: Biohazard symbols, images of contaminated water
- **Authority Exploitation**: Fake doctor accounts, fake government sources
- **Social Proof**: Multiple coordinated posts creating illusion of widespread concern
- **Urgency**: "BREAKING NEWS", "DO NOT DRINK THE WATER"

#### Indicators of Fabrication:
- Spelling and grammatical errors (AI-generated content artifacts)
- Inconsistent typography and formatting
- Stock imagery with digital manipulation
- Fake verification badges on social media accounts

#### Impact on Public Perception:
- Panic buying of bottled water
- Distrust in government communications
- Potential health anxiety and psychosomatic symptoms
- Economic disruption to water utility

---

## 2. Technical Analysis of Cyber Components

### 2.1 Attack Overview

| Metric | Value |
|--------|-------|
| Attack Duration | 59 minutes 59 seconds |
| Total Packets Captured | 12,000 |
| Attack Date | 27 October 2025 |
| Attack Window | 14:30:00 - 15:29:59 IST |

### 2.2 Phase 1: Initial Access (Spear-Phishing)

**Evidence**: HTTP POST requests containing phishing tokens

```
Source: 10.0.0.40
Destination: 203.0.113.5 (updcdn.ru)
Method: POST /login
Payload: payload=PHISH-TOKEN-XXX-PHISH&file=PHISH-TOKEN-XXX-PHISH.bin
```

**Analysis**:
- Plant administrator received spear-phishing email
- Credentials harvested and transmitted to C2 server
- 199 unique token exfiltrations observed
- First beacon: 14:30:01 IST

### 2.3 Phase 2: Reconnaissance

**Port Scanning Activity**:

| Attacker IP | Target Hosts | Ports Scanned |
|-------------|--------------|---------------|
| 198.51.100.12 | 10.0.0.10, 10.0.0.20, 10.0.0.50 | 23, 80, 443, 445, 502, 3389 |
| 203.0.113.5 | 10.0.0.10, 10.0.0.20, 10.0.0.50 | 22, 23, 80, 443, 445, 502, 3389 |
| 192.0.2.25 | 10.0.0.10, 10.0.0.20, 10.0.0.50 | 22, 23, 80, 443, 502, 3389 |

**Critical Ports Targeted**:
- **Port 502**: Modbus/TCP (Industrial Control Systems)
- **Port 3389**: RDP (Remote Desktop Protocol)
- **Port 445**: SMB (Lateral Movement)
- **Port 23**: Telnet (Legacy Remote Access)

### 2.4 Phase 3: Command & Control (C2)

**Primary C2 Channel**:
```
Protocol: HTTP
Host: updcdn.ru
IP: 203.0.113.5
Endpoint: POST /login
Beacons: 199 requests
Compromised Host: 10.0.0.40
```

**Secondary C2 Channel (DNS Tunneling)**:
```
Protocol: DNS
Domain: syslog-host.cn
Queries: 400
Compromised Host: 10.0.0.30
Purpose: Covert command channel
```

### 2.5 Phase 4: Lateral Movement & Privilege Escalation

**Evidence of Internal Reconnaissance**:
- NetBIOS Session Service (NBSS): 2,593 frames
- DNS queries to internal resources: local-server-01.local, local-print-server.local
- Attacker pivoted from 10.0.0.40 to 10.0.0.30 (admin workstation)

### 2.6 Phase 5: Data Exfiltration

**FTP Exfiltration Details**:
```
Source: 10.0.0.30 (Compromised Admin Workstation)
Destination: 198.51.100.12 (Attacker FTP Server)
Command: STOR (Upload)
Files: secret-chunk-1 through secret-chunk-199
Total Files: 199
Estimated Data: ~392 KB
```

**Exfiltration Technique**:
- Data split into chunks to avoid detection
- Named "secret-chunk-XXX" indicating sensitive content
- Likely contains: operational procedures, system configurations, credentials

### 2.7 Phase 6: ICS/SCADA Sabotage

**Modbus Attack Details**:
```
Source: 10.0.0.30 (Compromised Admin Workstation)
Target: 10.0.0.10 (PLC/SCADA Controller)
Protocol: Modbus/TCP
Function Code: 16 (Write Multiple Holding Registers)
Register Address: 0
Data Value: 524954
Total Commands: 200
Attack Window: 15:27:30 - 15:29:58 IST
```

**Impact Analysis**:
- Function Code 16 writes values to PLC holding registers
- These registers control critical processes:
  - Chemical dosing rates (chlorine, fluoride)
  - Valve positions
  - Pump speeds
  - Alarm thresholds
- Potential consequences:
  - Over/under-chlorination of water supply
  - Incorrect pH levels
  - Contamination of treated water

### 2.8 Phase 7: Distributed Denial of Service (DDoS)

**DDoS Attack Details**:
```
Source: 103.20.10.1
Target: 10.0.0.20
Protocol: UDP
Packets: 1,000
Packet Size: 1,280 bytes
Total Volume: ~1.28 MB
Start Time: 15:25:00 IST
```

**Purpose**: Distraction and disruption during sabotage phase

### 2.9 Vulnerabilities Exploited

1. **Human Factor**: Spear-phishing susceptibility
2. **Lack of Network Segmentation**: IT and OT networks connected
3. **Unencrypted Protocols**: HTTP for C2, FTP for exfiltration
4. **Exposed ICS Protocols**: Modbus/TCP accessible from compromised workstation
5. **Insufficient Monitoring**: Attack persisted for ~1 hour
6. **Weak Access Controls**: Admin workstation could write to PLC

---

## 3. Impact Assessment

### 3.1 Operational Impact

| System | Impact Level | Description |
|--------|--------------|-------------|
| PLC Controller (10.0.0.10) | **CRITICAL** | 200 unauthorized write commands executed |
| Admin Workstation (10.0.0.30) | **SEVERE** | Fully compromised, used for attacks |
| Workstation (10.0.0.40) | **SEVERE** | Initial compromise, C2 beaconing |
| Network Infrastructure | **MODERATE** | Reconnaissance and lateral movement |

### 3.2 Data Impact

- **Confidentiality**: 199 files exfiltrated containing operational data
- **Integrity**: PLC registers modified with unauthorized values
- **Availability**: DDoS attack on internal server

### 3.3 Public Health Risk

- Potential manipulation of chemical dosing could result in:
  - Under-chlorination: Microbial contamination
  - Over-chlorination: Chemical burns, toxic byproducts
  - Incorrect pH: Corrosion, contamination

### 3.4 Psychological/Social Impact

- Public panic due to disinformation campaign
- Loss of trust in water utility and government
- Economic impact from bottled water hoarding
- Potential long-term anxiety about water safety

---

## 4. Defence and Counter-Disinformation Strategy

### 4.1 Threat Model for Water Treatment Infrastructure

#### Assets:
1. SCADA/HMI Systems
2. PLCs controlling chemical dosing
3. Network infrastructure
4. Employee credentials
5. Operational data
6. Public trust

#### Threat Actors:
- State-sponsored APT groups
- Hacktivists
- Insider threats
- Cybercriminals

#### Attack Vectors:
- Spear-phishing
- Exposed ICS protocols
- Unpatched vulnerabilities
- Supply chain compromise

### 4.2 Technical Security Measures

#### Immediate Actions (0-24 hours):
1. **Isolate compromised systems**: 10.0.0.30, 10.0.0.40
2. **Block malicious IPs** at firewall:
   - 203.0.113.5 (C2)
   - 198.51.100.12 (Exfil)
   - 103.20.10.1 (DDoS)
   - 192.0.2.25 (Scanner)
3. **Block malicious domains**:
   - updcdn.ru
   - syslog-host.cn
4. **Reset all credentials** for affected users
5. **Verify PLC configurations** and restore from known-good backup

#### Short-term Actions (1-7 days):
1. **Network Segmentation**: Separate IT and OT networks with firewalls
2. **Implement ICS-specific firewall rules**: Block unauthorized Modbus traffic
3. **Deploy IDS/IPS**: Monitor for Modbus anomalies
4. **Enable MFA**: For all remote access and privileged accounts
5. **Patch vulnerable systems**: Especially those with exposed ports

#### Long-term Actions (1-6 months):
1. **Zero Trust Architecture**: Implement for OT network
2. **Security Awareness Training**: Focus on spear-phishing
3. **Incident Response Plan**: Develop and test ICS-specific procedures
4. **Threat Intelligence Integration**: Subscribe to ICS-CERT feeds
5. **Regular Penetration Testing**: Include ICS/SCADA systems
6. **Backup and Recovery**: Regular PLC configuration backups

### 4.3 Counter-Disinformation Measures

#### Immediate Response:
1. **Official Statement**: Issue clear, factual communication about water safety
2. **Social Media Monitoring**: Track and report fake accounts
3. **Media Engagement**: Brief legitimate journalists on the situation
4. **Hotline**: Establish public information line

#### Ongoing Measures:
1. **Media Literacy Campaign**: Educate public on identifying fake news
2. **Rapid Response Team**: Dedicated team for countering disinformation
3. **Platform Coordination**: Work with social media companies to remove fake content
4. **Transparency**: Regular water quality reports publicly available

### 4.4 Incident Response Plan

#### Phase 1: Detection & Analysis
- Monitor for IoCs identified in this report
- Correlate alerts across IT and OT systems
- Preserve evidence for forensic analysis

#### Phase 2: Containment
- Isolate affected systems
- Block C2 communications
- Implement emergency firewall rules

#### Phase 3: Eradication
- Remove malware from compromised systems
- Reset compromised credentials
- Patch exploited vulnerabilities

#### Phase 4: Recovery
- Restore systems from clean backups
- Verify PLC configurations
- Gradually restore network connectivity

#### Phase 5: Lessons Learned
- Document incident timeline
- Identify gaps in detection/response
- Update security controls

---

## 5. Indicators of Compromise (IoCs)

### Malicious IP Addresses
```
203.0.113.5    # C2 Server (updcdn.ru)
198.51.100.12  # FTP Exfiltration Server
103.20.10.1    # DDoS Source
192.0.2.25     # Port Scanner
```

### Malicious Domains
```
updcdn.ru        # C2 Domain
syslog-host.cn   # DNS Tunneling Domain
```

### File Indicators
```
PHISH-TOKEN-*.bin    # Phishing payload files
secret-chunk-*       # Exfiltrated data chunks
```

### Network Signatures
```
HTTP POST to /login with "PHISH-TOKEN" in body
DNS queries to syslog-host.cn (>10/minute)
Modbus Function Code 16 from non-HMI sources
FTP STOR commands to external IPs
```

---

## 6. Conclusion

The Thames Water Treatment Facility suffered a sophisticated, coordinated attack combining cyber intrusion with psychological operations. The attackers demonstrated advanced capabilities including ICS/SCADA exploitation, multi-channel C2, and synchronized disinformation campaigns.

Immediate action is required to:
1. Contain the breach and restore system integrity
2. Implement network segmentation between IT and OT
3. Counter the disinformation campaign with factual communications
4. Enhance security monitoring and incident response capabilities

The attack underscores the critical importance of protecting national infrastructure from state-sponsored threats and the need for integrated cyber-physical security strategies.

---

## Appendix A: Network Topology

```
[Internet]
    |
[Firewall]
    |
[Internal Network 10.0.0.0/24]
    |
    +-- 10.0.0.10 (PLC/SCADA Controller) [ATTACKED]
    +-- 10.0.0.20 (Server) [DDoS Target]
    +-- 10.0.0.30 (Admin Workstation) [COMPROMISED]
    +-- 10.0.0.40 (Workstation) [COMPROMISED - Initial Access]
    +-- 10.0.0.50 (Server)
    +-- 10.0.0.51 (HMI System)
    +-- 10.0.0.52 (HMI System)
    +-- 10.0.0.254 (Gateway/Router)
```

## Appendix B: Attack Statistics

| Metric | Value |
|--------|-------|
| Total Packets | 12,000 |
| Attack Duration | 59m 59s |
| C2 Beacons | 199 |
| Files Exfiltrated | 199 |
| Modbus Commands | 200 |
| DNS Tunnel Queries | 400 |
| DDoS Packets | 1,000 |
| Compromised Hosts | 2 |
| Targeted Hosts | 6 |

## Appendix C: References

- NIST Cybersecurity Framework
- ICS-CERT Advisories
- MITRE ATT&CK for ICS
- NCSC UK CNI Guidance

---

*Report prepared by: Cyber Operations Analyst*
*Date: [Current Date]*
*Classification: OFFICIAL-SENSITIVE*
