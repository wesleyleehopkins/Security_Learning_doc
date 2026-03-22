# SOC Log Correlation Cheatsheet — Red Team Correlation

## Overview

Quick-reference guide for SOC analysts to correlate log sources against each phase of the pentest lab attack chain. Lab network: 192.168.56.0/24 (Kali attacker .103, Ubuntu target .102, Windows target .101).

---

## Master Correlation Matrix

| Attack Phase | auth.log | syslog | Apache access | Apache error | audit.log | Win Security | Win System | Sysmon | PowerShell | Zeek conn | Zeek http | Zeek dns | Zeek ssh | Zeek smb | Snort/Suricata | OSSEC |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **1. Recon & Scanning** | N/A | N/A | S | N/A | N/A | N/A | N/A | N/A | N/A | P | P | S | S | N/A | P | S |
| **2. Enumeration** | N/A | N/A | P | S | N/A | S | N/A | N/A | N/A | P | P | P | S | S | P | S |
| **3. Brute Force** | P | S | S | N/A | P | P | N/A | N/A | N/A | P | S | N/A | P | N/A | P | P |
| **4. Web Exploitation** | N/A | S | P | P | S | N/A | N/A | N/A | N/A | P | P | S | N/A | N/A | P | P |
| **5. Linux Privesc** | P | P | S | S | P | N/A | N/A | N/A | N/A | S | S | N/A | N/A | N/A | S | P |
| **6. Lateral Movement** | P | S | N/A | N/A | P | P | S | P | S | P | S | N/A | P | P | P | P |
| **7. Windows Privesc** | N/A | N/A | N/A | N/A | N/A | P | P | P | P | S | S | N/A | N/A | N/A | S | S |
| **8. Post-Exploitation** | S | S | S | N/A | S | P | P | P | P | P | P | S | N/A | S | P | P |

**Legend:** P = Primary (check first), S = Secondary (supporting evidence), N/A = Not applicable

---

## Per-Phase Quick Reference

### Phase 1: Reconnaissance & Scanning

**What happened:** Nmap scans and service enumeration from 192.168.56.103 against both targets to identify open ports, services, and OS versions.

**Primary log sources:** Zeek conn.log, Zeek http.log, Snort/Suricata alerts

**Key search terms:**
- `192.168.56.103` (source IP in all logs)
- Zeek conn: high volume of `SF`, `REJ`, `S0` connection states from single source
- Snort: `ET SCAN Nmap`, `GPL SCAN`, `ET SCAN Potential SSH Scan`
- Apache access.log: rapid sequential requests to non-existent paths

**MITRE ATT&CK:** T1595 (Active Scanning), T1046 (Network Service Discovery)

**Triage priority:** P3

---

### Phase 2: Service Enumeration

**What happened:** Detailed enumeration of HTTP, SSH, SMB, and other discovered services. Directory brute-forcing (gobuster/dirb), SMB share enumeration, and banner grabbing.

**Primary log sources:** Apache access.log, Zeek http.log, Zeek conn.log, Zeek dns.log

**Key search terms:**
- Apache access: HTTP 404 flood from single IP, sequential alphabetical paths (`/admin`, `/backup`, `/cgi-bin`...)
- Zeek http: `GET` requests with `gobuster`, `dirb`, `nikto`, `sqlmap` in User-Agent
- Zeek smb: `SMB::Tree_Connect` events from .103
- Snort: `ET SCAN`, `ET WEB_SERVER`
- `enum4linux`, `smbclient`, `rpcclient` connection patterns

**MITRE ATT&CK:** T1083 (File and Directory Discovery), T1135 (Network Share Discovery), T1087 (Account Discovery)

**Triage priority:** P3

---

### Phase 3: Brute Force Attacks

**What happened:** SSH and/or web login brute force (Hydra/Medusa) against target services followed by a successful authentication.

**Primary log sources:** auth.log, Windows Security (4625/4624), audit.log, Zeek ssh.log, Snort/Suricata

**Key search terms:**
- auth.log: `Failed password for .* from 192.168.56.103` (high volume), then `Accepted password`
- Windows Security: Event IDs `4625` (flood) then `4624` from .103
- Zeek ssh: `auth_success: false` repeated, then `auth_success: true`
- Snort: `ET SCAN Bruteforce`, `GPL SSH`
- `hydra`, `medusa`, `patator` in any log

**MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing), T1110.003 (Password Spraying)

**Triage priority:** P1

---

### Phase 4: Web Application Exploitation

**What happened:** Exploitation of web application vulnerabilities (SQL injection, file upload, command injection, LFI/RFI) on the Ubuntu target's web server to achieve initial code execution.

**Primary log sources:** Apache access.log, Apache error.log, Zeek http.log, Snort/Suricata, OSSEC

**Key search terms:**
- Apache access: `UNION SELECT`, `' OR 1=1`, `../../etc/passwd`, `<?php`, `cmd=`, `system(`, `; ls`, `| cat`
- Apache access: POST requests to upload endpoints, then GET to `/uploads/shell.php`
- Apache error: `PHP Warning`, `PHP Fatal error`, `mod_security`
- Zeek http: response bodies with `/etc/passwd` content, abnormal POST sizes
- Snort: `ET WEB_SERVER`, `ET SQL`, `ET WEB_SPECIFIC_APPS`
- OSSEC: web shell file creation alerts

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059.004 (Command and Scripting Interpreter: Unix Shell), T1505.003 (Web Shell)

**Triage priority:** P1

---

### Phase 5: Linux Privilege Escalation

**What happened:** Escalation from web shell/low-privilege user to root on Ubuntu (.102) via SUID binaries, kernel exploits, misconfigured sudo, cron jobs, or LD_PRELOAD abuse.

**Primary log sources:** auth.log, syslog, audit.log, OSSEC

**Key search terms:**
- auth.log: `sudo:.*COMMAND=`, `su:.*session opened`, `pam_unix.*session opened.*root`
- syslog: `kernel:.*segfault` (kernel exploit attempts), unusual cron execution
- audit.log: `type=EXECVE.*a0="/bin/sh"`, `type=SYSCALL.*syscall=59.*uid=0`, `auid!=uid` (privilege change)
- OSSEC: `File integrity monitoring` alerts on `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `find / -perm -4000`, `linpeas`, `linux-exploit-suggester` in command logs
- Files written to `/tmp`, `/dev/shm`, `/var/tmp`

**MITRE ATT&CK:** T1548.001 (Setuid/Setgid), T1068 (Exploitation for Privilege Escalation), T1053.003 (Cron), T1574.006 (LD_PRELOAD)

**Triage priority:** P1

---

### Phase 6: Lateral Movement

**What happened:** Pivot from compromised Ubuntu (.102) to Windows (.101) using stolen credentials, SSH tunnels, or pass-the-hash techniques.

**Primary log sources:** auth.log (source), Windows Security (destination), Sysmon, Zeek conn/ssh/smb, Snort/Suricata, OSSEC

**Key search terms:**
- Windows Security: `4624` with LogonType `3` (network) or `10` (RemoteInteractive) from .102
- Windows Security: `4648` explicit credential logon from .102
- Zeek conn: new connections from .102 to .101 on ports 445, 3389, 5985, 5986
- Zeek smb: `SMB::Tree_Connect` from .102 to .101
- Zeek ssh: tunnel indicators (long-duration connections with periodic data)
- Sysmon Event 3: inbound network connection on .101 from .102
- auth.log on .102: SSH port forwarding (`-L`, `-D`, `-R` patterns)
- Snort: `ET POLICY SMB`, `ET EXPLOIT MS17-010`, `PSEXEC`

**MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares), T1550.002 (Pass the Hash), T1021.001 (Remote Desktop), T1572 (Protocol Tunneling)

**Triage priority:** P1

---

### Phase 7: Windows Privilege Escalation

**What happened:** Escalation from standard user to SYSTEM/Administrator on Windows (.101) via service misconfigurations, AlwaysInstallElevated, token impersonation, UAC bypass, or unquoted service paths.

**Primary log sources:** Windows Security, Windows System, Sysmon, PowerShell Operational

**Key search terms:**
- PowerShell 4104: `Invoke-AllChecks`, `PowerUp`, `Seatbelt`, `winPEAS`, `Get-UnquotedService`
- Security 4688: `whoami /priv`, `systeminfo`, `net user`, `net localgroup administrators`
- Security 4697 / System 7045: new service with suspicious binary path
- Security 4688: `msiexec /quiet /qn /i` (AlwaysInstallElevated)
- Sysmon 13: registry writes to `ms-settings\Shell\Open\command` (UAC bypass)
- Sysmon 1: `fodhelper.exe`, `eventvwr.exe` spawning `cmd.exe` or `powershell.exe`
- Security 4672: special privilege assignment to unexpected user

**MITRE ATT&CK:** T1548.002 (UAC Bypass), T1574.009 (Unquoted Service Path), T1134 (Access Token Manipulation), T1543.003 (Windows Service)

**Triage priority:** P1

---

### Phase 8: Post-Exploitation

**What happened:** Data exfiltration, persistence establishment, credential harvesting, log cleanup, and covering tracks on both compromised systems.

**Primary log sources:** Windows Security, Sysmon, PowerShell Operational, Zeek conn/http, Snort/Suricata, OSSEC

**Key search terms:**
- PowerShell 4104: `Invoke-Mimikatz`, `Compress-Archive`, `Invoke-WebRequest.*192.168.56.103`
- Security 1102: `audit log was cleared` (anti-forensics)
- Security 4720: new user account created
- Security 4732: user added to `Administrators` group
- Sysmon 11: file creation in staging directories
- Sysmon 3: outbound connections to .103 on non-standard ports
- Zeek http: large outbound data transfer to .103 (exfiltration)
- Zeek conn: long-duration connections to .103 (C2)
- auth.log: `history -c`, evidence of log tampering (`/var/log` modifications)
- OSSEC: file integrity alerts on system binaries, log files

**MITRE ATT&CK:** T1003 (Credential Dumping), T1041 (Exfiltration Over C2), T1070.001 (Clear Windows Event Logs), T1070.003 (Clear Command History), T1547.001 (Registry Run Keys)

**Triage priority:** P1

---

## Incident Response Playbook Stubs

### 1. Reverse Shell Detected

**Trigger:** Snort/Suricata alert or Zeek conn showing persistent outbound TCP from internal host to 192.168.56.103 on port 4444-4447.

1. **Isolate** — Immediately quarantine the affected host from the network (disable NIC or move to isolated VLAN). Do not power off.
2. **Identify the process** — On the host, identify the process holding the connection: `netstat -anop | findstr 4444` (Windows) or `ss -tnp | grep 4444` (Linux). Record PID, binary path, parent process.
3. **Capture volatile evidence** — Dump process memory, capture running process list, network connections, and loaded modules before termination.
4. **Kill and contain** — Terminate the malicious process. Check for persistence mechanisms (scheduled tasks, services, Run keys) that would re-establish the shell.
5. **Scope and escalate** — Search all network logs for other hosts communicating with the same C2 IP. Check if lateral movement occurred. Reset credentials for any accounts accessed from the compromised host.

### 2. Brute Force Followed by Successful Login

**Trigger:** High volume of auth.log `Failed password` or Windows 4625 events from a single source IP, followed by a 4624/`Accepted password` event.

1. **Confirm compromise** — Verify the successful login is real (not a false positive from legitimate retry). Check the timestamp gap between last failure and success.
2. **Lock the account** — Immediately disable or lock the compromised account. If it is a service account, assess impact before disabling.
3. **Trace post-auth activity** — Review all commands, processes, and network connections made by the account after successful authentication. Check for privilege escalation indicators.
4. **Identify attack scope** — Determine if the same source IP brute-forced other accounts. Check if the compromised credentials were reused on other systems.
5. **Remediate** — Force password reset for the compromised account (and any accounts with the same password). Implement account lockout policy if not already in place. Add the source IP to the blocklist.

### 3. Privilege Escalation Detected

**Trigger:** PowerShell 4104 showing PowerUp/Seatbelt execution, Security 7045 with suspicious service, or Sysmon 13 with UAC bypass registry keys.

1. **Determine current access level** — Check what privileges the attacker now holds. Query the host for current sessions: `query user`, `whoami /all`.
2. **Capture escalation artifacts** — Collect the specific escalation mechanism: malicious service binary, modified registry key, MSI file, or exploit binary. Preserve with hash.
3. **Contain the host** — Isolate the host from the network. If SYSTEM-level access was achieved, assume full host compromise including credential material.
4. **Check for credential theft** — Review for Mimikatz execution, LSASS access (Sysmon 10), SAM registry access, or ntds.dit extraction. Assume all credentials on the host are compromised.
5. **Remediate the vulnerability** — Fix the specific misconfiguration exploited (unquoted service path, weak service permissions, AlwaysInstallElevated policy, missing patches). Reset all credentials that existed on the host.

### 4. Lateral Movement — Pass-the-Hash

**Trigger:** Windows Security 4624 with LogonType 3 and NTLM authentication from an internal host, or Sysmon 3 showing SMB/WinRM connections between internal hosts.

1. **Map the movement path** — Identify source and destination hosts. Review Zeek smb.log, conn.log, and Windows 4624/4648 events to build a timeline of the lateral movement chain.
2. **Isolate both endpoints** — Quarantine both the source and destination hosts. The source is already compromised; the destination may be newly compromised.
3. **Identify the credential used** — Determine which account's NTLM hash was used. Check Security 4624 for the account name and SID. That account and all accounts that logged into the source host are compromised.
4. **Check for further pivoting** — From the destination host, review all outbound connections and authentication events to detect additional lateral movement hops.
5. **Reset credentials** — Reset passwords for all compromised accounts. If a domain admin hash was used, initiate a full krbtgt password reset (twice). Consider resetting all domain passwords if scope is unclear.

### 5. Data Exfiltration Detected

**Trigger:** Zeek conn.log showing large outbound data transfer to 192.168.56.103, or Zeek http.log showing large POST/PUT requests to external IP.

1. **Quantify the exfiltration** — Calculate total bytes transferred using Zeek conn.log `orig_bytes` and `resp_bytes` fields. Identify the time window and duration.
2. **Identify what was exfiltrated** — On the source host, check for data staging artifacts: recently created zip/archive files, `Compress-Archive` in PowerShell logs, files in temp directories. Check file access logs for sensitive file reads.
3. **Block the exfiltration channel** — If still active, block the destination IP at the firewall. Terminate the responsible process on the host.
4. **Assess data sensitivity** — Determine what data was accessible from the compromised host. Cross-reference with file access logs to narrow down what was actually taken.
5. **Notify and document** — Initiate breach notification procedures if PII or regulated data was exfiltrated. Preserve all log evidence with chain of custody. Engage legal/compliance if required.

---

## Log Retention Requirements

| Log Source | Minimum Retention | Recommended Retention | Notes |
|---|---|---|---|
| Windows Security | 90 days | 1 year | Critical for auth and process tracking |
| Windows System | 90 days | 6 months | Service installation events |
| Sysmon | 90 days | 1 year | Most detailed endpoint telemetry |
| PowerShell Operational | 90 days | 1 year | Script block logging is high-value |
| auth.log | 90 days | 1 year | SSH/sudo authentication chain |
| syslog | 30 days | 6 months | General system events |
| audit.log | 90 days | 1 year | Syscall-level detail for Linux |
| Apache access.log | 90 days | 1 year | Web attack evidence |
| Apache error.log | 90 days | 6 months | Exploitation error indicators |
| Zeek conn.log | 90 days | 1 year | Network baseline and anomaly detection |
| Zeek http.log | 90 days | 1 year | HTTP payload and exfil detection |
| Zeek dns.log | 90 days | 1 year | DNS tunneling and C2 detection |
| Zeek ssh.log | 90 days | 1 year | Brute force and lateral movement |
| Zeek smb.log | 90 days | 1 year | Lateral movement via SMB |
| Snort/Suricata alerts | 90 days | 1 year | Signature-based detections |
| OSSEC alerts | 90 days | 1 year | Host integrity monitoring |
| Transcription logs | 30 days | 90 days | Large volume, review and archive |

**Storage guidance:** Forward all logs to a centralized SIEM with immutable storage. Attackers in Phase 8 will attempt to clear local logs (Event 1102). Centralized copies ensure evidence preservation.

---

## Common Pitfalls

### 1. Focusing Only on the Alert, Not the Chain
A single alert (e.g., brute force) is rarely the full story. Always pivot backward and forward in time from the initial indicator. The brute force at 14:00 means you should check what happened from .103 at 13:30 (recon) and 14:15 (post-exploitation).

### 2. Ignoring Zeek Conn Logs for Baselining
Zeek conn.log is the single best source for identifying anomalous connections. SOC analysts often skip it in favor of alert-based tools. A reverse shell on port 4444 will appear clearly in conn.log as a long-duration outbound connection even if Snort missed it.

### 3. Not Correlating Across Linux and Windows
Lateral movement (Phase 6) bridges both OSes. If you detect a compromise on the Ubuntu host, you must immediately check Windows Security logs for authentication from .102. Investigating each host in isolation misses the full kill chain.

### 4. Missing Encoded PowerShell
Attackers use `-EncodedCommand` to bypass simple string matching. Always decode Base64 content in 4688 events. Script Block Logging (4104) records the decoded content automatically — prefer it over process creation logs when available.

### 5. Overlooking Legitimate Tool Abuse
Tools like `certutil`, `msiexec`, `rundll32`, and `mshta` are legitimate Windows binaries used for living-off-the-land attacks. Do not whitelist them from monitoring. Flag any instance where these tools make network connections or execute from unusual parent processes.

### 6. Log Gaps from Insufficient Retention
Default Windows Security log size is 20 MB, which can be overwritten in hours on a busy system. Ensure log forwarding to SIEM is configured and verified before an engagement. Check for Event ID 1102 (log cleared) as an indicator of anti-forensics.

### 7. Tunnel Vision on Known Signatures
Snort/Suricata rules catch known patterns but miss custom payloads. Supplement signature-based detection with behavioral analysis: unusual connection durations, data volume anomalies, process parent-child relationships, and time-of-day patterns.

### 8. Not Checking for Persistence After Incident
After finding and remediating an active compromise, always sweep for persistence mechanisms: scheduled tasks, services, Run keys, WMI subscriptions, cron jobs, SSH authorized_keys, and web shells. Missing even one persistence mechanism means the attacker returns.
