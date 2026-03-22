# Splunk Detection Queries -- Red Team Correlation

## Overview

This document provides Splunk Processing Language (SPL) queries designed to detect each phase of a penetration test attack chain executed against a lab environment. The queries correlate attacker activity from multiple data sources -- network logs (Zeek), host-based logs (Sysmon, auditd, auth.log), web server logs (Apache), and Windows Security Event Logs -- to give a Blue Team full visibility into the kill chain.

**Lab Network:** 192.168.56.0/24

| Host | Role | IP Address |
|------|------|------------|
| Kali Linux | Attacker | 192.168.56.103 |
| Ubuntu Server | Target | 192.168.56.102 |
| Windows Server | Target | 192.168.56.101 |

---

## Data Sources & Index Configuration

### Indexes

| Index | Purpose | Sourcetypes |
|-------|---------|-------------|
| `main` | General catch-all | Various |
| `sysmon` | Windows Sysmon events | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` |
| `ossec` | OSSEC/Wazuh alerts | `ossec:alerts` |
| `zeek` | Zeek/Bro network logs | `bro:conn:json`, `bro:dns:json`, `bro:http:json`, `bro:files:json` |
| `apache` | Apache access and error logs | `apache:access`, `apache:error` |
| `auth` | Linux authentication logs | `linux:auth`, `syslog` |
| `winevt` | Windows Event Logs | `WinEventLog:Security`, `WinEventLog:System` |

### Data Onboarding Notes

- Deploy the Splunk Universal Forwarder to both the Ubuntu and Windows targets.
- On Ubuntu, forward `/var/log/auth.log`, `/var/log/syslog`, `/var/log/apache2/access.log`, `/var/log/apache2/error.log`, and auditd logs from `/var/log/audit/audit.log`.
- On Windows, forward Sysmon operational logs (requires Sysmon installed with a comprehensive config such as SwiftOnSecurity or Olaf Hartong), Security Event Logs, and System Event Logs.
- Deploy Zeek on a span port or network tap monitoring the 192.168.56.0/24 segment. Forward `conn.log`, `dns.log`, `http.log`, and `files.log` as JSON.
- Set all forwarders to use UTC timestamps to simplify cross-source correlation.
- Create a `redteam` macro for the attacker IP: `definition = "192.168.56.103"`.

---

## Phase 2: Active Scanning Detection

### Query 1 -- Port Scan Detection (Zeek conn.log)

Detects a single source IP contacting an unusually high number of destination ports on a single host, characteristic of a port scan.

```spl
index=zeek sourcetype="bro:conn:json" id.orig_h=192.168.56.103
| bin _time span=5m
| stats dc(id.resp_p) as unique_ports values(id.resp_p) as ports by _time id.orig_h id.resp_h
| where unique_ports > 50
| sort - unique_ports
```

### Query 2 -- Nmap Service Fingerprinting (Zeek conn.log)

Detects short-lived connections with minimal data transfer typical of service version scanning (-sV).

```spl
index=zeek sourcetype="bro:conn:json" id.orig_h=192.168.56.103
| where duration < 2 AND orig_bytes < 500 AND resp_bytes < 500
| bin _time span=2m
| stats count dc(id.resp_p) as unique_ports by _time id.orig_h id.resp_h
| where count > 30 AND unique_ports > 20
```

### Query 3 -- Directory Brute Force from Apache Logs

Identifies directory and file enumeration tools (dirb, gobuster, feroxbuster) by a high volume of 404 responses from a single source.

```spl
index=apache sourcetype="apache:access" status=404
| bin _time span=2m
| stats count as total_404 dc(uri_path) as unique_paths by _time clientip
| where total_404 > 100 AND unique_paths > 80
| sort - total_404
```

### Query 4 -- SMB Enumeration (Windows Security Logs)

Detects rapid enumeration of network shares via repeated logon and share access events.

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=5140 Source_Network_Address=192.168.56.103
| bin _time span=5m
| stats count dc(Share_Name) as unique_shares values(Share_Name) as shares by _time Source_Network_Address
| where count > 10
```

---

## Phase 3: Web Exploitation Detection

### Query 5 -- SQL Injection Attempts in Apache Logs

Detects common SQL injection keywords and tool signatures in request URIs and query strings.

```spl
index=apache sourcetype="apache:access"
| rex field=uri_path "(?<full_request>.*)"
| search uri_query=*UNION* OR uri_query=*SELECT* OR uri_query=*OR+1=1* OR uri_query=*%27* OR uri_query=*sqlmap* OR uri_query=*SLEEP* OR uri_query=*BENCHMARK*
| stats count values(uri_query) as payloads by clientip uri_path status
| where count > 3
| sort - count
```

### Query 6 -- sqlmap User-Agent Detection

```spl
index=apache sourcetype="apache:access" useragent=*sqlmap*
| stats count earliest(_time) as first_seen latest(_time) as last_seen by clientip useragent
| convert ctime(first_seen) ctime(last_seen)
```

### Query 7 -- Cross-Site Scripting (XSS) Payload Detection

```spl
index=apache sourcetype="apache:access"
| where match(uri_query, "(?i)(<script|javascript:|onerror=|onload=|alert\(|document\.cookie|eval\()")
| stats count values(uri_query) as payloads by clientip uri_path
| sort - count
```

### Query 8 -- Command Injection Detection

```spl
index=apache sourcetype="apache:access"
| where match(uri_query, "(?i)(;\s*(ls|cat|id|whoami|uname|pwd|wget|curl|nc |bash|sh |python)|%7C|\|.*(/bin/|/etc/)|`.*`|\$\(.*\))")
| stats count values(uri_query) as payloads by clientip uri_path status
| sort - count
```

### Query 9 -- Suspicious File Upload Detection

```spl
index=apache sourcetype="apache:access" method=POST
| where match(uri_path, "(?i)(upload|file|image|avatar)")
| where match(uri_query, "(?i)\.(php|phtml|php5|jsp|asp|aspx|cgi|sh|py|pl)") OR status=200
| stats count values(uri_path) as paths by clientip status
| where count > 3
```

### Query 10 -- Local/Remote File Inclusion (LFI/RFI) Detection

```spl
index=apache sourcetype="apache:access"
| where match(uri_query, "(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self|php://|data://|expect://|file://|input://)")
| stats count values(uri_query) as payloads values(status) as status_codes by clientip uri_path
| sort - count
```

---

## Phase 4: Password Attack Detection

### Query 11 -- SSH Brute Force Detection (auth.log)

Detects rapid SSH authentication failures from a single source, indicative of Hydra, Medusa, or Patator.

```spl
index=auth sourcetype="linux:auth" "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=5m
| stats count dc(target_user) as unique_users values(target_user) as users by _time src_ip
| where count > 15
| sort - count
```

### Query 12 -- SMB / Windows Logon Brute Force (EventID 4625)

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count dc(TargetUserName) as unique_accounts values(TargetUserName) as accounts values(LogonType) as logon_types by _time IpAddress
| where count > 10
| sort - count
```

### Query 13 -- RDP Brute Force Detection

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4625 LogonType=10
| bin _time span=5m
| stats count dc(TargetUserName) as unique_accounts values(TargetUserName) as accounts by _time IpAddress
| where count > 5
| sort - count
```

### Query 14 -- Successful Login After Brute Force (Correlation)

Identifies a successful authentication that follows a burst of failures from the same source IP, a strong indicator of a compromised credential.

```spl
index=auth sourcetype="linux:auth" ("Failed password" OR "Accepted password")
| rex field=_raw "(?<auth_status>Failed|Accepted) password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=10m
| stats count(eval(auth_status="Failed")) as failures count(eval(auth_status="Accepted")) as successes values(eval(if(auth_status="Accepted",target_user,null()))) as compromised_user by _time src_ip
| where failures > 10 AND successes > 0
```

### Query 15 -- Credential Spraying Detection (Same Password, Multiple Accounts)

On Windows, credential spraying appears as 4625 events with SubStatus 0xC000006A (bad password) across many accounts in a short window.

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4625 Sub_Status="0xc000006a"
| bin _time span=10m
| stats dc(TargetUserName) as unique_accounts count values(TargetUserName) as accounts by _time IpAddress
| where unique_accounts > 5
| sort - unique_accounts
```

---

## Phase 5: Metasploit Detection

### Query 16 -- Metasploit User-Agent in HTTP Logs

Metasploit modules frequently use default or distinctive user-agent strings.

```spl
index=apache sourcetype="apache:access"
| where match(useragent, "(?i)(metasploit|meterpreter|Mozilla/4\.0 \(compatible; MSIE 6\.0\)|MSF)")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by clientip useragent uri_path
| convert ctime(first_seen) ctime(last_seen)
```

### Query 17 -- Meterpreter Network Connections (Sysmon Event 3)

Sysmon EventID 3 logs network connections. This detects outbound connections from target hosts to the attacker on common Meterpreter ports.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp=192.168.56.103
| where DestinationPort >= 4444 AND DestinationPort <= 5555
| stats count earliest(_time) as first_seen values(Image) as processes values(User) as users by DestinationIp DestinationPort SourceIp
| convert ctime(first_seen)
```

### Query 18 -- Suspicious Outbound Connections to Common C2 Ports

Broader search across Zeek for any host on the lab network connecting outbound to the attacker on known tool default ports.

```spl
index=zeek sourcetype="bro:conn:json" id.resp_h=192.168.56.103
| where id.resp_p >= 4444 AND id.resp_p <= 5555
| stats count sum(orig_bytes) as bytes_out sum(resp_bytes) as bytes_in by id.orig_h id.resp_h id.resp_p
| eval total_bytes=bytes_out+bytes_in
| sort - total_bytes
```

---

## Phase 6: Linux Privilege Escalation Detection

### Query 19 -- SUID Binary Abuse (auditd EUID Change)

Detects process execution where the effective UID changes to 0 (root) from a non-root user, which occurs during SUID exploitation.

```spl
index=auth sourcetype="linux:audit" type=SYSCALL exe=* euid=0 uid!=0
| stats count values(exe) as executables values(comm) as commands by uid euid auid
| where count > 0
| sort - count
```

### Query 20 -- Sudo Exploitation Detection

Detects unusual sudo activity including exploitation of sudo misconfigurations or CVEs.

```spl
index=auth sourcetype="linux:auth" "sudo:" NOT "pam_unix"
| rex field=_raw "sudo:\s+(?<sudo_user>\S+)\s.*COMMAND=(?<command>.*)"
| where match(command, "(?i)(/bin/bash|/bin/sh|vi\b|vim\b|nano\b|less\b|find\b.*-exec|python|perl|ruby|awk\b.*system)")
| stats count values(command) as commands by sudo_user
| sort - count
```

### Query 21 -- Crontab Modification Detection

```spl
index=auth sourcetype="linux:auth" "crontab" ("REPLACE" OR "CREATE" OR "DELETE")
| rex field=_raw "(?<action>REPLACE|CREATE|DELETE) \((?<cron_user>\S+)\)"
| stats count values(action) as actions by cron_user _time
```

### Query 22 -- PATH Hijack / Suspicious Executables in /tmp

Detects new process execution from world-writable directories commonly used for privilege escalation staging.

```spl
index=auth sourcetype="linux:audit" type=EXECVE
| where match(a0, "(?i)^(/tmp/|/var/tmp/|/dev/shm/)")
| stats count values(a0) as executables by uid auid _time
| sort - _time
```

### Query 23 -- LinPEAS / LinEnum Execution Detection

Detects execution of popular Linux enumeration scripts by matching process names and command-line arguments.

```spl
index=auth sourcetype="linux:audit" type=EXECVE
| where match(a0, "(?i)(linpeas|linenum|linux-exploit-suggester|les\.sh|lse\.sh|pspy)")
    OR match(a1, "(?i)(linpeas|linenum|linux-exploit-suggester)")
| stats count values(a0) as executables by uid auid _time
```

---

## Phase 7: Windows Privilege Escalation Detection

### Query 24 -- Malicious Service Creation (System Event 7045)

Detects new services with suspicious binaries, often used by Metasploit for privilege escalation.

```spl
index=winevt sourcetype="WinEventLog:System" EventCode=7045
| where match(ImagePath, "(?i)(cmd\.exe|powershell|%COMSPEC%|/c\s|\\\\temp\\\\|\\\\tmp\\\\|meterpreter|rundll32|msiexec|certutil)")
    OR ServiceType="user mode service" AND match(Service_File_Name, "(?i)\\\\(appdata|temp|tmp|public)\\\\")
| table _time ServiceName ImagePath ServiceType AccountName
```

### Query 25 -- UAC Bypass via Registry Modification (Sysmon 12/13)

Detects writes to the `ms-settings` or `mscfile` registry keys used by common UAC bypass techniques (fodhelper, eventvwr).

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (12,13)
| where match(TargetObject, "(?i)(ms-settings\\\\shell\\\\open\\\\command|mscfile\\\\shell\\\\open\\\\command|Classes\\\\exefile\\\\shell|Environment\\\\windir|Environment\\\\COR_)")
| stats count values(TargetObject) as registry_keys values(Details) as values values(Image) as processes by Computer User
| sort - _time
```

### Query 26 -- AlwaysInstallElevated Exploitation (msiexec Abuse)

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\msiexec.exe"
| where match(CommandLine, "(?i)(/quiet|/qn|/i.*\\\\temp|/i.*\\\\tmp|/i.*\\\\appdata)")
| stats count values(CommandLine) as commands values(User) as users by Computer ParentImage
| sort - _time
```

### Query 27 -- Token Impersonation / Potato Exploits

Detects execution of known privilege escalation tools that abuse token impersonation.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(printspoofer|godpotato|sweetpotato|juicypotato|roguepotato|hotpotato|rottenpotato|incognito|tokenvator)")
    OR match(OriginalFileName, "(?i)(printspoofer|potato)")
| table _time Computer User Image CommandLine ParentImage
```

### Query 28 -- SAM/SYSTEM Registry Dump

Detects attempts to save the SAM, SYSTEM, or SECURITY registry hives for offline credential extraction.

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(reg\s+save\s+hklm\\\\(sam|system|security)|secretsdump|mimikatz|hashdump|pwdump|fgdump)")
| table _time Computer User Image CommandLine ParentImage
```

### Query 29 -- winPEAS Execution Detection

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image, "(?i)(winpeas|seatbelt|sharpup|watson|powerup|privesc)")
    OR match(CommandLine, "(?i)(winpeas|seatbelt|sharpup|powerup|privesccheck)")
    OR match(OriginalFileName, "(?i)(winPEAS|Seatbelt)")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine
```

---

## Phase 8: Post-Exploitation Detection

### Query 30 -- SSH Authorized Keys Modification

Detects changes to authorized_keys files, a common persistence mechanism on Linux.

```spl
index=auth sourcetype="linux:audit" type=SYSCALL
| where match(name, "authorized_keys")
| stats count values(exe) as executables values(comm) as commands by uid auid _time
| sort - _time
```

### Query 31 -- New User Account Creation (Linux)

```spl
index=auth sourcetype="linux:auth" ("useradd" OR "adduser" OR "new user")
| rex field=_raw "new user: name=(?<new_user>\S+)"
| stats count values(new_user) as new_users by host _time
```

### Query 32 -- New Scheduled Task (Windows Event 4698)

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4698
| table _time SubjectUserName TaskName TaskContent
| where match(TaskContent, "(?i)(cmd|powershell|mshta|rundll32|cscript|wscript|certutil|bitsadmin|msiexec|\\\\temp\\\\|\\\\tmp\\\\)")
```

### Query 33 -- WMI Event Subscription Persistence (Sysmon 19/20/21)

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (19,20,21)
| stats count values(EventType) as event_types values(Operation) as operations values(Consumer) as consumers values(Destination) as destinations by Computer User
| sort - _time
```

### Query 34 -- Pass-the-Hash Detection (Event 4624 Type 3 NTLM)

Detects NTLM network logons that may indicate pass-the-hash activity when the source is internal and the logon uses NTLM rather than Kerberos.

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| where IpAddress!= "-" AND NOT match(IpAddress, "^(::1|127\.0\.0\.1)$")
| stats count dc(TargetUserName) as unique_users values(TargetUserName) as users by IpAddress WorkstationName
| where count > 3
| sort - count
```

### Query 35 -- DNS Tunneling Detection

Identifies potential DNS tunneling by looking for unusually high query volumes or DNS labels exceeding normal length thresholds.

```spl
index=zeek sourcetype="bro:dns:json" id.orig_h IN (192.168.56.101, 192.168.56.102)
| eval query_length=len(query)
| eval label_count=mvcount(split(query, "."))
| bin _time span=5m
| stats count avg(query_length) as avg_len max(query_length) as max_len dc(query) as unique_queries by _time id.orig_h
| where count > 200 OR avg_len > 40 OR max_len > 60
| sort - count
```

### Query 36 -- Data Exfiltration (Large Outbound Transfers)

Detects unusually large data transfers from target hosts to the attacker.

```spl
index=zeek sourcetype="bro:conn:json" id.orig_h IN (192.168.56.101, 192.168.56.102) id.resp_h=192.168.56.103
| stats sum(orig_bytes) as total_bytes_out count by id.orig_h id.resp_h id.resp_p
| eval MB_out=round(total_bytes_out/1048576,2)
| where MB_out > 5
| sort - MB_out
| table id.orig_h id.resp_h id.resp_p total_bytes_out MB_out count
```

---

## Correlation Searches & Alerts

These searches combine multiple data sources and phases to surface high-confidence attack chain activity.

### Correlation 1 -- Brute Force to Successful Login to Command Execution

Links a brute force burst against SSH with a subsequent successful login and suspicious command execution from the same source.

```spl
index=auth sourcetype="linux:auth" ("Failed password" OR "Accepted password")
| rex field=_raw "(?<auth_status>Failed|Accepted) password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bin _time span=15m
| stats count(eval(auth_status="Failed")) as failures count(eval(auth_status="Accepted")) as successes values(eval(if(auth_status="Accepted",target_user,null()))) as compromised_user by _time src_ip
| where failures > 10 AND successes > 0
| join src_ip type=left
    [search index=auth sourcetype="linux:audit" type=EXECVE
     | rex field=a0 "(?<executed_cmd>.*)"
     | stats values(a0) as post_login_commands by auid]
| table _time src_ip failures successes compromised_user post_login_commands
```

### Correlation 2 -- Web Exploit to Reverse Shell

Detects a web exploitation attempt (SQL injection or command injection) followed by an outbound connection from the web server to the attacker on a common shell port.

```spl
index=apache sourcetype="apache:access" clientip=192.168.56.103
| where match(uri_query, "(?i)(UNION|SELECT|;.*cat|;.*id|;.*bash|\|.*nc )")
| stats count earliest(_time) as exploit_time by clientip
| convert ctime(exploit_time)
| join type=left
    [search index=zeek sourcetype="bro:conn:json" id.orig_h=192.168.56.102 id.resp_h=192.168.56.103
     | where id.resp_p >= 4444 AND id.resp_p <= 9999
     | stats earliest(_time) as shell_time values(id.resp_p) as shell_ports by id.orig_h id.resp_h
     | convert ctime(shell_time)
     | rename id.orig_h as target id.resp_h as attacker]
| where isnotnull(shell_time)
| table exploit_time clientip shell_time shell_ports target attacker
```

### Correlation 3 -- Tool Download Followed by Privilege Escalation

Detects when an enumeration or exploit tool is downloaded to a target and subsequently privilege escalation indicators appear.

```spl
index=zeek sourcetype="bro:http:json" id.orig_h IN (192.168.56.101, 192.168.56.102) id.resp_h=192.168.56.103
| where match(uri, "(?i)(linpeas|winpeas|pspy|chisel|potato|mimikatz|nc\.exe|exploit)")
| stats earliest(_time) as download_time values(uri) as downloaded_files by id.orig_h
| convert ctime(download_time)
| join id.orig_h type=left
    [search (index=auth sourcetype="linux:audit" type=SYSCALL euid=0 uid!=0)
        OR (index=winevt sourcetype="WinEventLog:System" EventCode=7045)
     | stats earliest(_time) as escalation_time by host
     | convert ctime(escalation_time)
     | rename host as id.orig_h]
| where isnotnull(escalation_time)
| table id.orig_h download_time downloaded_files escalation_time
```

### Correlation 4 -- Lateral Movement Chain (Pass-the-Hash to Remote Execution)

Detects NTLM authentication from the attacker IP followed by remote service creation on the target, a classic lateral movement pattern.

```spl
index=winevt sourcetype="WinEventLog:Security" EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM IpAddress=192.168.56.103
| stats earliest(_time) as logon_time values(TargetUserName) as logon_users by IpAddress Computer
| convert ctime(logon_time)
| join Computer type=left
    [search index=winevt sourcetype="WinEventLog:System" EventCode=7045
     | stats earliest(_time) as service_time values(ServiceName) as new_services values(ImagePath) as service_paths by Computer
     | convert ctime(service_time)]
| where isnotnull(service_time)
| table Computer logon_time IpAddress logon_users service_time new_services service_paths
```

### Correlation 5 -- Full Kill Chain Timeline

Produces a single timeline view across all detection phases for the known attacker IP, giving analysts a chronological picture of the entire attack chain.

```spl
(index=zeek id.orig_h=192.168.56.103)
    OR (index=apache clientip=192.168.56.103)
    OR (index=auth "192.168.56.103")
    OR (index=winevt IpAddress=192.168.56.103)
    OR (index=sysmon DestinationIp=192.168.56.103)
| eval phase=case(
    sourcetype=="bro:conn:json" AND match(_raw, "conn"), "Scanning",
    sourcetype=="apache:access" AND match(uri_query, "(?i)(UNION|script|;|\.\./)"), "Web Exploit",
    sourcetype=="linux:auth" AND match(_raw, "Failed password"), "Brute Force",
    sourcetype=="linux:auth" AND match(_raw, "Accepted password"), "Access Gained",
    sourcetype=="WinEventLog:Security" AND EventCode==4625, "Brute Force",
    sourcetype=="WinEventLog:Security" AND EventCode==4624, "Access Gained",
    sourcetype=="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode==3, "C2 Connection",
    1==1, "Other"
  )
| stats count by _time phase sourcetype
| sort _time
```

---

## Dashboard Panels

The following panels should be built in a Splunk dashboard to provide ongoing situational awareness for the Blue Team.

### Panel 1 -- Attack Timeline (Timechart)

A timechart showing event counts across all detection indexes, broken down by phase. Uses the Full Kill Chain Timeline query above with `| timechart span=5m count by phase`.

### Panel 2 -- Top Attacker IPs (Single Value + Table)

A single-value indicator showing the count of unique external IPs triggering detection rules, paired with a table of the top 10 source IPs by alert volume. Useful in larger environments but validates the known attacker IP in the lab.

### Panel 3 -- Brute Force Monitor (Line Chart + Statistics)

A line chart showing failed authentication attempts over time per source IP across both Linux (auth.log) and Windows (EventID 4625) sources. Accompanied by a stats table showing current brute force sessions in progress.

### Panel 4 -- Web Attack Heatmap

A heatmap of web attack types (SQLi, XSS, LFI, command injection) plotted against time of day and target URI path. Driven by the Apache detection queries with an additional classification eval.

### Panel 5 -- Privilege Escalation Alerts (Event Feed)

A real-time event feed showing privilege escalation indicators from both Linux (SUID abuse, sudo exploitation, cron modification) and Windows (service creation, UAC bypass, token impersonation). Each row links to the raw event for analyst triage.

### Panel 6 -- Persistence Mechanisms Detected (Table)

A summary table of all detected persistence mechanisms including new user accounts, scheduled tasks, WMI subscriptions, SSH key additions, and service installations. Columns: time, host, mechanism type, detail, user context.

### Panel 7 -- Network Anomaly Summary (Stats Table)

A table combining DNS tunneling indicators, large outbound transfers, and suspicious C2 connections. Pulls from Zeek data and Sysmon Event 3 queries to highlight network-level post-exploitation activity.

### Panel 8 -- Correlation Alert Feed (Critical)

A high-priority feed showing only the results of the five correlation searches. These represent the highest-confidence detections where multiple phases of the attack chain have been confirmed. Each alert should trigger a Splunk alert action (email, webhook, or notable event in Splunk ES).
