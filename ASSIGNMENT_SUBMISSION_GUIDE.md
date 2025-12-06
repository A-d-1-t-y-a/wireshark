# Thames Water Cyberattack - Assignment Submission Guide

## Files Created

| File | Purpose | Format Required |
|------|---------|-----------------|
| `Thames_Water_Incident_Report.md` | Main report (convert to .docx) | .doc or .docx |
| `thames_water_defense_script.txt` | Defensive bash script | .txt |
| `thames_water_defense.sh` | Executable script version | For testing |

---

## Submission Checklist

### 1. Main Report (.docx)
- [ ] Convert `Thames_Water_Incident_Report.md` to Word format
- [ ] Add your name and student ID
- [ ] Add page numbers
- [ ] Format tables properly
- [ ] Add screenshots in Appendix (see below)
- [ ] Check word count (~3500 words)
- [ ] Proofread for spelling/grammar

### 2. Script (.txt)
- [ ] Submit `thames_water_defense_script.txt`
- [ ] Ensure it's plain text format

### 3. Screenshots for Appendix
Add these screenshots to your report appendix:

1. **PCAP Overview**: Wireshark showing protocol hierarchy
2. **Modbus Traffic**: Filter showing Modbus attacks
3. **C2 Communication**: HTTP POST requests to updcdn.ru
4. **FTP Exfiltration**: FTP STOR commands
5. **Script Output**: Run the script and capture output

---

## How to Get Screenshots

### In Kali VM, run these Wireshark filters:

1. **Modbus Attack**:
   ```
   modbus
   ```

2. **C2 Traffic**:
   ```
   http.host == "updcdn.ru"
   ```

3. **FTP Exfiltration**:
   ```
   ftp.request.command == "STOR"
   ```

4. **DNS Tunneling**:
   ```
   dns.qry.name contains "cn"
   ```

5. **Port Scanning**:
   ```
   tcp.flags.syn == 1 && tcp.flags.ack == 0
   ```

### Script Output Screenshot:

Run in Kali:
```bash
chmod +x thames_water_defense.sh
sudo ./thames_water_defense.sh
```

Select option 9 (Run ALL defenses) and take a screenshot.

---

## Report Structure (Matches Rubric)

| Section | Marks | Status |
|---------|-------|--------|
| Executive Summary | 5 | ✅ Included |
| Threat Intelligence & Disinformation Analysis | 10 | ✅ Included |
| Technical Analysis of Cyber Components | 25 | ✅ Included |
| Defence & Counter-Disinformation Strategy | 15 | ✅ Included |
| Immediate Mitigation Measures (Script) | 5 | ✅ Included |
| **Total** | **60** | |

---

## Key Points for Each Section

### Executive Summary (5 marks)
- Clear overview of both cyber and psychological attack
- Impact on Thames Water and community
- Key findings summarized

### Threat Intelligence (10 marks)
- MOC attributes (Means, Opportunity, Capability)
- Attacker attribution (Russian/Chinese infrastructure)
- Deepfake/disinformation analysis
- Target audience and distribution methods

### Technical Analysis (25 marks)
- All attack phases covered:
  - Reconnaissance (port scanning)
  - Initial Access (phishing)
  - C2 (updcdn.ru, DNS tunneling)
  - Lateral Movement
  - Exfiltration (FTP)
  - ICS Sabotage (Modbus)
  - DDoS
- PCAP evidence cited
- Vulnerabilities identified

### Defence Strategy (15 marks)
- Technical measures (firewall, segmentation, monitoring)
- Counter-disinformation measures
- Incident response plan
- Threat model

### Script (5 marks)
- Functional bash script
- Addresses specific threats from PCAP
- Well-commented
- Screenshot of output included

---

## Converting Markdown to Word

### Option 1: Using Pandoc (Kali)
```bash
sudo apt install pandoc
pandoc Thames_Water_Incident_Report.md -o Thames_Water_Incident_Report.docx
```

### Option 2: Online Converter
- Use https://www.markdowntoword.com/
- Or copy content to Google Docs and download as .docx

### Option 3: Manual
- Open in VS Code with Markdown preview
- Copy formatted content to Word

---

## Final Checks Before Submission

1. **Report**:
   - [ ] .docx format
   - [ ] ~3500 words
   - [ ] All sections complete
   - [ ] Screenshots in appendix
   - [ ] References included
   - [ ] Your name and student ID

2. **Script**:
   - [ ] .txt format
   - [ ] Plain text (no special characters)
   - [ ] Comments explaining functionality

3. **General**:
   - [ ] No plagiarism
   - [ ] Submitted before 12 Dec 2025, 10 AM
   - [ ] Both files uploaded

---

## Evidence Summary (for your reference)

### Attack Statistics
- **Duration**: 59 minutes 59 seconds
- **C2 Beacons**: 199
- **FTP Exfiltration**: 199 files
- **Modbus Attacks**: 200 commands
- **DNS Tunneling**: 400 queries
- **DDoS Packets**: 1,000

### Malicious IPs
- 203.0.113.5 (C2 - updcdn.ru)
- 198.51.100.12 (FTP Exfil)
- 103.20.10.1 (DDoS)
- 192.0.2.25 (Scanner)

### Compromised Hosts
- 10.0.0.40 (Initial phishing victim)
- 10.0.0.30 (Admin workstation - attack source)
- 10.0.0.10 (PLC - sabotage target)

---

Good luck with your submission!
