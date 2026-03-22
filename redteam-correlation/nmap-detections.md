# Defensive Nmap Usage — Red Team Correlation

## Overview

Nmap is primarily known as an offensive reconnaissance tool, but it is equally valuable on the defensive side. Blue teams can use nmap to establish known-good baselines of their network, detect unauthorized changes, identify attacker artifacts like backdoors and rogue services, and verify that vulnerabilities have been patched. This document covers defensive nmap usage within the 192.168.56.0/24 pentest lab, targeting Ubuntu (.102) and Windows (.101) from a monitoring perspective.

## Baseline Scans

Establishing a baseline is critical. Run these scans before any red team activity begins, and store the results for later comparison with `ndiff`.

### Ubuntu Baseline (192.168.56.102)

**Full TCP port scan with service versions and OS detection:**

```bash
# Command 1: Comprehensive Ubuntu baseline
nmap -sS -sV -O -p- --open -oA baseline-ubuntu-tcp 192.168.56.102
```

This performs a SYN scan of all 65535 TCP ports, detects service versions on open ports, and attempts OS fingerprinting. The `-oA` flag saves output in all three formats (normal, XML, grepable).

**UDP scan of common services:**

```bash
# Command 2: UDP baseline for Ubuntu
nmap -sU --top-ports 100 -sV -oA baseline-ubuntu-udp 192.168.56.102
```

**Expected baseline results for Ubuntu:**
- Port 22/tcp — OpenSSH
- Port 80/tcp — Apache httpd
- Port 3306/tcp — MySQL (if DVWA is configured)
- OS: Linux 5.x or 6.x

### Windows Baseline (192.168.56.101)

**Full TCP port scan with service versions and OS detection:**

```bash
# Command 3: Comprehensive Windows baseline
nmap -sS -sV -O -p- --open -oA baseline-windows-tcp 192.168.56.101
```

**UDP scan of common services:**

```bash
# Command 4: UDP baseline for Windows
nmap -sU --top-ports 100 -sV -oA baseline-windows-udp 192.168.56.101
```

**Expected baseline results for Windows:**
- Port 135/tcp — MSRPC
- Port 139/tcp — NetBIOS-SSN
- Port 445/tcp — Microsoft-DS (SMB)
- Port 3389/tcp — Microsoft Terminal Services (RDP)
- Port 5985/tcp — WinRM (if enabled)
- OS: Windows 10/11 or Windows Server

### Network-Wide Discovery Scan

```bash
# Command 5: Network discovery scan
nmap -sn -oA baseline-network-discovery 192.168.56.0/24
```

This ping sweep identifies all live hosts on the network. The baseline should show only known hosts (.101, .102, .103, .110). Any additional hosts appearing later indicate rogue VMs or containers.

```bash
# Command 6: ARP discovery (more reliable on local segments)
nmap -PR -sn -oA baseline-arp-discovery 192.168.56.0/24
```

## Change Detection

### Using ndiff to Compare Baseline vs Current State

`ndiff` compares two nmap XML output files and reports differences: new hosts, new open ports, changed services, and removed services.

```bash
# Command 7: Compare current Ubuntu state against baseline
nmap -sS -sV -p- --open -oX current-ubuntu-tcp.xml 192.168.56.102
ndiff baseline-ubuntu-tcp.xml current-ubuntu-tcp.xml
```

**Sample ndiff output showing attacker artifacts:**

```
-Nmap scan of 192.168.56.102 at 2026-03-14 08:00
+Nmap scan of 192.168.56.102 at 2026-03-15 14:30

 192.168.56.102:
  22/tcp  open  ssh      OpenSSH 8.9p1
  80/tcp  open  http     Apache httpd 2.4.52
  3306/tcp open mysql    MySQL 8.0.32
+ 4444/tcp open shell    Netcat listener           <-- REVERSE SHELL
+ 8000/tcp open http     Python 3.10 http.server   <-- STAGING SERVER
+ 2222/tcp open ssh      OpenSSH 8.9p1             <-- PERSISTENCE BACKDOOR
```

Lines prefixed with `+` indicate new open ports not present in the baseline — strong indicators of compromise.

### Scheduling Periodic Scans with Cron

Automate change detection by running nmap scans on a schedule from the Security Onion box or a dedicated monitoring host:

```bash
# Add to crontab on Security Onion (192.168.56.110)
# Run every 30 minutes, compare with baseline, email differences

*/30 * * * * /usr/local/bin/nmap-monitor.sh
```

**nmap-monitor.sh:**

```bash
#!/bin/bash
TIMESTAMP=$(date +%Y%m%d-%H%M)
BASELINE_DIR="/opt/nmap-baselines"
SCAN_DIR="/opt/nmap-scans"

# Scan both targets
nmap -sS -sV -p- --open -oX ${SCAN_DIR}/ubuntu-${TIMESTAMP}.xml 192.168.56.102
nmap -sS -sV -p- --open -oX ${SCAN_DIR}/windows-${TIMESTAMP}.xml 192.168.56.101

# Compare with baselines
UBUNTU_DIFF=$(ndiff ${BASELINE_DIR}/baseline-ubuntu-tcp.xml ${SCAN_DIR}/ubuntu-${TIMESTAMP}.xml)
WINDOWS_DIFF=$(ndiff ${BASELINE_DIR}/baseline-windows-tcp.xml ${SCAN_DIR}/windows-${TIMESTAMP}.xml)

# Alert if changes detected
if [ -n "$UBUNTU_DIFF" ] || [ -n "$WINDOWS_DIFF" ]; then
    echo "ALERT: Network changes detected at ${TIMESTAMP}" >> /var/log/nmap-monitor.log
    echo "$UBUNTU_DIFF" >> /var/log/nmap-monitor.log
    echo "$WINDOWS_DIFF" >> /var/log/nmap-monitor.log
fi
```

### Detecting New Services (Indicators of Persistence Backdoors, Rogue Services)

After the red team operates, new services may appear on targets. Common indicators:

| Port | Service | Indicator |
|---|---|---|
| 4444/tcp | Netcat/Meterpreter | Reverse shell listener |
| 4445/tcp | Unknown shell | Alternative reverse shell |
| 8080/tcp | HTTP proxy | Chisel tunnel endpoint |
| 8000/tcp | Python HTTP | Staging/exfiltration server |
| 2222/tcp | SSH | Persistence SSH backdoor |
| 9001/tcp | Tor | Tor hidden service |
| 1337/tcp | Unknown | Custom backdoor |
| 5555/tcp | Unknown service | WindowsCoreHelper (persistence) |

## Detecting Attacker Artifacts

### New Listening Ports on Targets

```bash
# Command 8: Quick scan for non-baseline ports on Ubuntu
nmap -sS -p 1-65535 --open 192.168.56.102 | diff - baseline-ubuntu-ports.txt

# Command 9: Quick scan for non-baseline ports on Windows
nmap -sS -p 1-65535 --open 192.168.56.101 | diff - baseline-windows-ports.txt
```

**Focused scan on common backdoor ports:**

```bash
# Command 10: Scan for common reverse shell and backdoor ports
nmap -sS -sV -p 4444,4445,4446,5555,6666,7777,8000,8080,8443,9001,1337,2222,31337 192.168.56.101-102
```

### Unauthorized SSH Keys (Banner Grab Showing Key Changes)

```bash
# Command 11: SSH banner grab and host key fingerprint
nmap -p 22 --script ssh-hostkey 192.168.56.102
```

Compare the host key fingerprint against the baseline. If the host key has changed and the system was not reinstalled, this indicates a possible MITM or that an attacker replaced the SSH server.

```bash
# Command 12: Detailed SSH authentication methods check
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" 192.168.56.102
```

If `publickey` authentication appears and was not originally configured, an attacker may have added keys to `authorized_keys`.

### New SMB Shares

```bash
# Command 13: Enumerate SMB shares on Windows target
nmap -p 445 --script smb-enum-shares --script-args smbusername=guest 192.168.56.101
```

Compare against the baseline share list. New shares may indicate:
- Attacker staging directories
- Exfiltration shares
- Persistence mechanisms via hidden shares

```bash
# Command 14: Check for SMB shares on Ubuntu (Samba)
nmap -p 445 --script smb-enum-shares 192.168.56.102
```

### Services on Unusual Ports

```bash
# Command 15: Aggressive service detection on all open ports
nmap -sS -sV --version-intensity 9 -p- --open 192.168.56.102
```

The `--version-intensity 9` flag makes nmap try harder to identify services. This helps detect:
- **Chisel on port 8080:** Will show as an HTTP service with unusual headers
- **Python HTTP server on port 8000:** Identified as "SimpleHTTPServer" or "http.server"
- **Meterpreter on port 4444:** May show as "Metasploit RPC" or unidentified shell
- **WindowsCoreHelper:** Custom service name on unexpected port

## Vulnerability Assessment

### Using NSE Scripts Defensively

NSE (Nmap Scripting Engine) scripts can verify whether targets are vulnerable to known exploits — useful for confirming that patches are applied after remediation.

**SMB vulnerability checks (EternalBlue/MS17-010):**

```bash
# Command 16: Check for MS17-010 (EternalBlue)
nmap -p 445 --script smb-vuln-ms17-010 192.168.56.101
```

**HTTP vulnerability checks:**

```bash
# Command 17: Check for common web vulnerabilities
nmap -p 80 --script http-vuln-cve2017-5638,http-vuln-cve2021-41773,http-shellshock 192.168.56.102
```

**General vulnerability scan using vulners:**

```bash
# Command 18: Vulners-based vulnerability assessment
nmap -sV --script vulners -p- --open 192.168.56.101-102
```

The `vulners` script cross-references detected service versions against the Vulners vulnerability database, reporting known CVEs.

### Verifying Patches Are Applied

After applying patches, re-run vulnerability scans and compare:

```bash
# Command 19: Post-patch verification scan
nmap -sV --script vuln -p 445 192.168.56.101
# Should show "NOT VULNERABLE" for MS17-010 after patching

# Command 20: Verify SSH is updated (no longer vulnerable)
nmap -sV -p 22 --script ssh2-enum-algos 192.168.56.102
# Check that weak algorithms (arcfour, diffie-hellman-group1) are removed
```

## Sample Commands

Below is a reference table of all commands plus additional useful scans:

| # | Command | Purpose |
|---|---|---|
| 1 | `nmap -sS -sV -O -p- --open -oA baseline-ubuntu-tcp 192.168.56.102` | Full Ubuntu TCP baseline with service/OS detection |
| 2 | `nmap -sU --top-ports 100 -sV -oA baseline-ubuntu-udp 192.168.56.102` | Ubuntu UDP baseline |
| 3 | `nmap -sS -sV -O -p- --open -oA baseline-windows-tcp 192.168.56.101` | Full Windows TCP baseline with service/OS detection |
| 4 | `nmap -sU --top-ports 100 -sV -oA baseline-windows-udp 192.168.56.101` | Windows UDP baseline |
| 5 | `nmap -sn -oA baseline-network-discovery 192.168.56.0/24` | Network-wide host discovery |
| 6 | `nmap -PR -sn -oA baseline-arp-discovery 192.168.56.0/24` | ARP-based host discovery |
| 7 | `ndiff baseline-ubuntu-tcp.xml current-ubuntu-tcp.xml` | Compare baseline vs current state |
| 8 | `nmap -sS -p 1-65535 --open 192.168.56.102` | Full port scan for change detection |
| 9 | `nmap -sS -p 1-65535 --open 192.168.56.101` | Full port scan for change detection |
| 10 | `nmap -sS -sV -p 4444,4445,4446,5555,6666,7777,8000,8080,8443,9001,1337,2222,31337 192.168.56.101-102` | Scan common backdoor ports |
| 11 | `nmap -p 22 --script ssh-hostkey 192.168.56.102` | SSH host key fingerprint |
| 12 | `nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" 192.168.56.102` | Check SSH auth methods |
| 13 | `nmap -p 445 --script smb-enum-shares --script-args smbusername=guest 192.168.56.101` | Enumerate Windows SMB shares |
| 14 | `nmap -p 445 --script smb-enum-shares 192.168.56.102` | Enumerate Ubuntu SMB/Samba shares |
| 15 | `nmap -sS -sV --version-intensity 9 -p- --open 192.168.56.102` | Aggressive service identification |
| 16 | `nmap -p 445 --script smb-vuln-ms17-010 192.168.56.101` | Check for EternalBlue vulnerability |
| 17 | `nmap -p 80 --script http-vuln-cve2017-5638,http-vuln-cve2021-41773,http-shellshock 192.168.56.102` | Check HTTP vulnerabilities |
| 18 | `nmap -sV --script vulners -p- --open 192.168.56.101-102` | Vulners CVE assessment |
| 19 | `nmap -sV --script vuln -p 445 192.168.56.101` | Post-patch verification |
| 20 | `nmap -sV -p 22 --script ssh2-enum-algos 192.168.56.102` | SSH algorithm audit |
| 21 | `nmap -sS -sV -p 80,443 --script http-enum 192.168.56.102` | Web application directory enumeration |
| 22 | `nmap -p 3306 --script mysql-info,mysql-enum 192.168.56.102` | MySQL service information |
| 23 | `nmap -sS -sV --script default,safe -oA full-audit 192.168.56.0/24` | Network-wide safe audit scan |
| 24 | `nmap -p 445 --script smb-enum-users 192.168.56.101` | Enumerate SMB users on Windows |
| 25 | `nmap -sV --script banner -p 1-10000 192.168.56.102` | Banner grabbing on common ports |
