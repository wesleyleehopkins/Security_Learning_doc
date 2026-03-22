# Zeek Detection Scripts & Log Queries -- Red Team Correlation

## Overview

This document provides Zeek (formerly Bro) detection logic mapped to a penetration test attack chain executed against a lab network. Each section contains `zeek-cut` queries against standard Zeek logs and, where applicable, custom Zeek scripts that detect the corresponding attacker behavior.

**Lab Network:** `192.168.56.0/24`

| Host | Role | IP Address |
|------|------|------------|
| Kali Linux | Attacker | 192.168.56.103 |
| Ubuntu Server | Target | 192.168.56.102 |
| Windows 10 | Target | 192.168.56.101 |

**Zeek Version Assumed:** 6.x+ (field names follow current Zeek conventions)

---

## Zeek Log Files Reference

| Log File | Description | Relevant Attack Phases |
|-----------|-------------|----------------------|
| `conn.log` | All TCP/UDP/ICMP connections | 2 (Scanning), 5 (Metasploit), 8 (Post-Exploitation) |
| `dns.log` | DNS queries and responses | 8 (DNS tunneling, C2 lookups) |
| `http.log` | HTTP requests and responses | 2 (Web scanning), 3 (Web exploitation), 5 (HTTP stagers), 8 (Tool staging) |
| `ssh.log` | SSH handshake and auth metadata | 4 (Brute force), 8 (SSH tunneling) |
| `smb.log` | SMB/CIFS operations | 2 (Enumeration), 4 (Password attacks), 8 (Lateral movement) |
| `ssl.log` | TLS/SSL handshake details | 5 (Encrypted C2), 8 (Encrypted exfil) |
| `files.log` | File content analysis and hashes | 3 (Malicious uploads), 5 (Payload delivery), 8 (Tool staging) |
| `notice.log` | Zeek notices and alerts | All phases (custom notice output) |
| `weird.log` | Anomalous protocol behavior | 5 (Meterpreter), 8 (Tunneling artifacts) |

---

## Phase 2: Active Scanning

### Port Scan Detection from conn.log

Identify a single source connecting to many distinct destination ports on a target within a short window.

```bash
# Count unique destination ports per source-destination pair
zeek-cut id.orig_h id.resp_h id.resp_p < conn.log \
  | sort | uniq \
  | awk '{print $1, $2}' | sort | uniq -c | sort -rn \
  | awk '$1 > 50 {print "SCAN: " $1 " ports from " $2 " -> " $3}'
```

```bash
# Connections from the known attacker IP to either target
zeek-cut ts id.orig_h id.resp_h id.resp_p proto conn_state < conn.log \
  | awk '$2 == "192.168.56.103" && ($3 == "192.168.56.101" || $3 == "192.168.56.102")'
```

```bash
# SYN scan fingerprint: look for S0 (SYN with no reply) and REJ (rejected) states
zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log \
  | awk '$4 == "S0" || $4 == "REJ"' \
  | awk '{print $1, $2}' | sort | uniq -c | sort -rn | head -20
```

```bash
# ICMP sweep detection (ping sweep before port scan)
zeek-cut ts id.orig_h id.resp_h proto < conn.log \
  | awk '$4 == "icmp" && $2 == "192.168.56.103"' \
  | awk '{print $3}' | sort -u
```

### HTTP Log Analysis for Nikto / Gobuster

```bash
# Identify scanner user-agent strings
zeek-cut ts id.orig_h user_agent < http.log \
  | grep -iE '(nikto|gobuster|dirb|dirbuster|wfuzz|ffuf|sqlmap|nmap)'
```

```bash
# High 404 rate from a single source (directory brute-forcing)
zeek-cut id.orig_h status_code < http.log \
  | awk '$2 == 404 {print $1}' | sort | uniq -c | sort -rn \
  | awk '$1 > 100 {print "DIR_BRUTE: " $1 " 404s from " $2}'
```

```bash
# Request rate per source (abnormally high = automated tool)
zeek-cut ts id.orig_h < http.log \
  | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
```

### SMB Log Analysis for enum4linux

```bash
# SMB tree connect operations (share enumeration)
zeek-cut ts id.orig_h id.resp_h path < smb_mapping.log \
  | awk '$2 == "192.168.56.103"'
```

```bash
# High volume of SMB operations from attacker
zeek-cut ts id.orig_h id.resp_h action < smb_cmd.log \
  | awk '$2 == "192.168.56.103"' | awk '{print $4}' | sort | uniq -c | sort -rn
```

---

## Phase 3: Web Exploitation

### SQL Injection, XSS, and Command Injection in HTTP URIs

```bash
# SQLi patterns in URIs
zeek-cut ts id.orig_h uri < http.log \
  | grep -iE "(union\+select|or\+1=1|'\+or\+'|select\+.*from|information_schema|sleep\(|benchmark\(|waitfor\+delay)"
```

```bash
# XSS patterns in URIs
zeek-cut ts id.orig_h uri < http.log \
  | grep -iE '(<script|%3cscript|javascript:|onerror=|onload=|alert\(|document\.cookie)'
```

```bash
# Command injection patterns in URIs
zeek-cut ts id.orig_h uri < http.log \
  | grep -iE '(\||\;|%7c|%3b|\$\(|%24%28|`|%60)' \
  | grep -iE '(whoami|id|uname|cat\+|passwd|ifconfig|wget|curl|nc\+|bash|/bin/sh)'
```

```bash
# Path traversal attempts
zeek-cut ts id.orig_h uri < http.log \
  | grep -iE '(\.\./|\.\.%2f|%2e%2e/|%2e%2e%2f|/etc/passwd|/etc/shadow|/proc/self)'
```

### Malicious File Uploads via files.log

```bash
# File uploads associated with HTTP POST requests
zeek-cut ts tx_hosts rx_hosts source mime_type filename < files.log \
  | awk '$4 == "HTTP"' \
  | grep -iE '\.(php|jsp|asp|aspx|phtml|sh|py|pl|exe|elf|dll)$'
```

```bash
# Executable MIME types transferred over HTTP
zeek-cut ts tx_hosts rx_hosts mime_type filename < files.log \
  | grep -iE '(application/x-executable|application/x-dosexec|application/x-sharedlib|application/x-php|text/x-php|text/x-shellscript)'
```

---

## Phase 4: Password Attacks

### SSH Brute Force Detection from ssh.log

```bash
# Failed SSH authentication attempts per source
zeek-cut ts id.orig_h id.resp_h auth_success auth_attempts < ssh.log \
  | awk '$4 == "F" || $5 > 3' \
  | awk '{print $2, $3}' | sort | uniq -c | sort -rn
```

```bash
# SSH sessions with high auth_attempts values (multiple passwords in one connection)
zeek-cut ts id.orig_h id.resp_h auth_attempts auth_success client < ssh.log \
  | awk '$4 > 1 {print}'
```

```bash
# Timeline of SSH attempts from attacker to targets
zeek-cut ts id.orig_h id.resp_h auth_success < ssh.log \
  | awk '$2 == "192.168.56.103"' | sort
```

### SMB Authentication Failures

```bash
# Failed SMB authentication events
zeek-cut ts id.orig_h id.resp_h status < smb_cmd.log \
  | grep -i 'STATUS_LOGON_FAILURE'
```

```bash
# Count of SMB auth failures per source
zeek-cut id.orig_h status < smb_cmd.log \
  | grep -i 'STATUS_LOGON_FAILURE' \
  | awk '{print $1}' | sort | uniq -c | sort -rn
```

---

## Phase 5: Metasploit

### Detecting Meterpreter Traffic Patterns in conn.log

Meterpreter sessions typically show a long-lived TCP connection to an unusual port with bidirectional interactive traffic.

```bash
# Long-duration connections from targets back to attacker (reverse shells / Meterpreter)
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
  | awk '$3 == "192.168.56.103" && $5 > 60 && $6 > 0 && $7 > 0' \
  | sort -t'	' -k5 -rn | head -20
```

```bash
# Connections to common Meterpreter default ports
zeek-cut ts id.orig_h id.resp_h id.resp_p duration proto < conn.log \
  | awk '$4 == 4444 || $4 == 4443 || $4 == 5555 || $4 == 8443' \
  | awk '$2 != "192.168.56.103" {print "REVERSE_CONN:", $0}'
```

```bash
# Weird log entries indicating protocol anomalies (Meterpreter over HTTP can trigger these)
zeek-cut ts id.orig_h id.resp_h name addl < weird.log \
  | awk '$2 == "192.168.56.101" || $2 == "192.168.56.102"'
```

### HTTP Stager Detection

```bash
# HTTP requests to attacker-hosted stagers
zeek-cut ts id.orig_h id.resp_h method uri status_code resp_fuids < http.log \
  | awk '$3 == "192.168.56.103"'
```

```bash
# Suspicious short URI paths that return executables (common stager pattern)
zeek-cut ts id.orig_h id.resp_h uri resp_mime_types resp_fuids < http.log \
  | grep -iE '(application/x-dosexec|application/x-executable|application/octet-stream)' \
  | awk '$3 == "192.168.56.103"'
```

### Suspicious EXE/ELF Downloads in files.log

```bash
# Executable files downloaded from the attacker
zeek-cut ts tx_hosts rx_hosts source mime_type filename sha1 < files.log \
  | awk '$2 == "192.168.56.103"' \
  | grep -iE '(x-dosexec|x-executable|x-sharedlib|octet-stream)'
```

```bash
# All files transferred from the attacker IP
zeek-cut ts tx_hosts rx_hosts mime_type total_bytes filename < files.log \
  | awk '$2 == "192.168.56.103"'
```

---

## Phase 8: Post-Exploitation

### Reverse Shell Detection (Outbound Long-Lived TCP)

```bash
# Outbound connections from targets to attacker on high ports with interactive characteristics
# Interactive: bidirectional traffic, duration > 30s, small packet sizes typical of shell I/O
zeek-cut ts id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes orig_pkts resp_pkts < conn.log \
  | awk '$3 == "192.168.56.103" && $4 > 1023 && $6 > 30 && $7 > 100 && $8 > 100 && $9 > 10 && $10 > 10' \
  | sort -t'	' -k6 -rn
```

```bash
# Ratio-based detection: interactive shells have roughly balanced send/receive ratios
zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
  | awk '$4 > 60 && $5 > 0 && $6 > 0 {
      ratio = ($5 > $6) ? $5/$6 : $6/$5;
      if (ratio < 10 && $3 == "192.168.56.103")
        print "SHELL_SUSPECT:", $0, "ratio=" ratio
    }'
```

### SSH Tunneling / SOCKS Proxy Detection

```bash
# SSH connections with unusually high data transfer (tunnel indicator)
zeek-cut ts id.orig_h id.resp_h duration orig_bytes resp_bytes < ssh.log conn.log \
  | awk '$2 == "192.168.56.103" || $3 == "192.168.56.103"' \
  | awk '$5 > 1000000 || $6 > 1000000 {print "SSH_TUNNEL:", $0}'
```

```bash
# Long-lived SSH sessions that transfer significantly more data than a typical admin session
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
  | awk '$4 == 22 && $5 > 3600 && ($6 > 500000 || $7 > 500000)'
```

```bash
# Correlate: connections to localhost SOCKS port appearing after SSH session starts
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log \
  | awk '$2 == "127.0.0.1" && ($4 == 1080 || $4 == 9050 || $4 == 8080)'
```

### Chisel WebSocket Detection in http.log

```bash
# WebSocket upgrade requests (Chisel uses WebSocket for tunneling)
zeek-cut ts id.orig_h id.resp_h uri method < http.log \
  | grep -iE 'upgrade|websocket'
```

```bash
# Chisel default URI patterns
zeek-cut ts id.orig_h id.resp_h host uri user_agent < http.log \
  | grep -iE '(chisel|/tunnel|/ws)'
```

```bash
# Long-lived HTTP connections (WebSocket tunnels stay open)
zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes < conn.log \
  | awk '($4 == 80 || $4 == 443 || $4 == 8080) && $5 > 300 && $6 > 10000 && $7 > 10000' \
  | awk '$3 == "192.168.56.103" || $2 == "192.168.56.103"'
```

### DNS Tunneling Detection

```bash
# Queries with unusually long domain names (DNS tunneling encodes data in labels)
zeek-cut ts id.orig_h query qtype < dns.log \
  | awk '{if (length($3) > 60) print "LONG_QUERY:", $0}'
```

```bash
# High query volume to a single domain (tunneling generates many queries)
zeek-cut query < dns.log \
  | awk -F'.' '{print $(NF-1)"."$NF}' \
  | sort | uniq -c | sort -rn | head -20
```

```bash
# TXT record queries (commonly used for DNS tunneling data exfil)
zeek-cut ts id.orig_h query qtype < dns.log \
  | awk '$4 == "TXT"' | sort | head -50
```

```bash
# NULL, CNAME, or MX record abuse for tunneling
zeek-cut ts id.orig_h query qtype qtype_name < dns.log \
  | awk '$4 == 10 || $4 == 5 || $4 == 0 {print "UNUSUAL_QTYPE:", $0}'
```

```bash
# Entropy estimation: labels with many unique characters suggest encoded data
zeek-cut query < dns.log \
  | awk '{
      n = split($1, labels, ".");
      for (i = 1; i < n-1; i++) {
        label = labels[i];
        if (length(label) > 20) print "HIGH_ENTROPY_LABEL:", label, $1
      }
    }'
```

### Data Exfiltration Detection

```bash
# Large outbound transfers from targets to attacker
zeek-cut ts id.orig_h id.resp_h orig_bytes resp_bytes < conn.log \
  | awk '($1 != "") && $3 == "192.168.56.103" && $4 > 1000000 {
      printf "EXFIL: %s -> %s  sent=%s bytes\n", $2, $3, $4
    }'
```

```bash
# SMB file read operations (attacker pulling files from targets)
zeek-cut ts id.orig_h id.resp_h action path name size < smb_files.log \
  | awk '$2 == "192.168.56.103"'
```

```bash
# SMB file write operations (attacker staging tools on targets)
zeek-cut ts id.orig_h id.resp_h action path name size < smb_files.log \
  | grep -i 'write\|create' \
  | awk '$2 == "192.168.56.103"'
```

### Tool Staging Detection (HTTP Downloads of Known Tool Filenames)

```bash
# Known offensive tool filenames in HTTP URIs or files.log
zeek-cut ts id.orig_h id.resp_h uri < http.log \
  | grep -iE '(linpeas|winpeas|pspy|chisel|socat|ncat|nc\.exe|mimikatz|lazagne|bloodhound|sharphound|rubeus|seatbelt|certify|powerview|powerup|sherlock|watson|juicypotato|printspoofer|godpotato|ligolo|crackmapexec)'
```

```bash
# Same check against files.log filenames
zeek-cut ts tx_hosts rx_hosts filename < files.log \
  | grep -iE '(linpeas|winpeas|pspy|chisel|socat|mimikatz|lazagne|bloodhound|sharphound|rubeus|seatbelt|powerview|juicypotato|printspoofer|godpotato|ligolo)'
```

```bash
# Executable downloads to target machines from any external source
zeek-cut ts tx_hosts rx_hosts mime_type total_bytes filename < files.log \
  | awk '($4 ~ /executable|dosexec|octet-stream|x-sh/) && ($3 == "192.168.56.101" || $3 == "192.168.56.102")'
```

---

## Custom Zeek Scripts

### 1. Port Scan Detector (Threshold-Based)

```zeek
##! Detect port scans by tracking unique destination ports per source-destination pair.
##! Generates a notice when the threshold is exceeded within the observation window.

@load base/frameworks/notice

module PortScanDetector;

export {
    redef enum Notice::Type += {
        Port_Scan_Detected
    };

    ## Number of unique destination ports before triggering.
    const scan_threshold: count = 50 &redef;

    ## Time window for tracking connection attempts.
    const scan_interval: interval = 5min &redef;
}

# Track unique destination ports per source-destination pair.
global scan_tracker: table[addr, addr] of set[port] &create_expire=scan_interval;

# Track whether we already fired a notice for this pair.
global scan_noticed: set[addr, addr] &create_expire=scan_interval;

event connection_attempt(c: connection)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local dp   = c$id$resp_p;

    # Only track TCP SYN-like attempts.
    if ( c$conn$proto != tcp )
        return;

    if ( [orig, resp] !in scan_tracker )
        scan_tracker[orig, resp] = set();

    add scan_tracker[orig, resp][dp];

    if ( |scan_tracker[orig, resp]| >= scan_threshold &&
         [orig, resp] !in scan_noticed )
        {
        add scan_noticed[orig, resp];

        NOTICE([
            $note=Port_Scan_Detected,
            $src=orig,
            $dst=resp,
            $msg=fmt("Port scan detected: %s -> %s (%d unique ports in %s)",
                     orig, resp, |scan_tracker[orig, resp]|, scan_interval),
            $sub=fmt("%d ports", |scan_tracker[orig, resp]|),
            $identifier=cat(orig, resp)
        ]);
        }
    }
```

### 2. DNS Tunneling Detector (Label Length + Query Rate)

```zeek
##! Detect DNS tunneling by monitoring query label lengths and per-domain
##! query rates. Tunneling tools encode payload data into DNS labels,
##! producing abnormally long labels and high query volumes to a single domain.

@load base/frameworks/notice

module DNSTunnelDetector;

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Long_Label,
        DNS_Tunnel_High_Query_Rate
    };

    ## Maximum label length before flagging (RFC 1035 allows 63, but
    ## legitimate labels rarely exceed 30 characters).
    const label_length_threshold: count = 40 &redef;

    ## Number of queries to a single base domain within the window
    ## before triggering.
    const query_rate_threshold: count = 200 &redef;

    ## Observation window for query rate tracking.
    const rate_interval: interval = 5min &redef;
}

# Track query counts per source + base domain.
global query_counts: table[addr, string] of count &create_expire=rate_interval &default=0;

# Avoid duplicate notices per source + domain.
global rate_noticed: set[addr, string] &create_expire=rate_interval;

# Extract the base domain (last two labels) from a query name.
function get_base_domain(query: string): string
    {
    local parts = split_string(query, /\./);
    local n = |parts|;
    if ( n >= 2 )
        return fmt("%s.%s", parts[n - 2], parts[n - 1]);
    return query;
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local orig = c$id$orig_h;

    # --- Label length check ---
    local labels = split_string(query, /\./);
    for ( i in labels )
        {
        if ( |labels[i]| > label_length_threshold )
            {
            NOTICE([
                $note=DNS_Tunnel_Long_Label,
                $src=orig,
                $msg=fmt("DNS label length %d exceeds threshold (%d): %s",
                         |labels[i]|, label_length_threshold, query),
                $sub=query,
                $identifier=cat(orig, query)
            ]);
            break;
            }
        }

    # --- Query rate check ---
    local base = get_base_domain(query);
    ++query_counts[orig, base];

    if ( query_counts[orig, base] >= query_rate_threshold &&
         [orig, base] !in rate_noticed )
        {
        add rate_noticed[orig, base];

        NOTICE([
            $note=DNS_Tunnel_High_Query_Rate,
            $src=orig,
            $msg=fmt("High DNS query rate: %s sent %d queries to %s in %s",
                     orig, query_counts[orig, base], base, rate_interval),
            $sub=base,
            $identifier=cat(orig, base)
        ]);
        }
    }
```

### 3. Reverse Shell Heuristic Detector

```zeek
##! Detect potential reverse shells by identifying outbound TCP connections
##! to high ports that exhibit interactive traffic patterns: long duration,
##! bidirectional data flow, and many small packets in both directions.

@load base/frameworks/notice

module ReverseShellDetector;

export {
    redef enum Notice::Type += {
        Reverse_Shell_Suspected
    };

    ## Minimum connection duration (seconds) to consider.
    const min_duration: interval = 30sec &redef;

    ## Minimum packets in each direction for "interactive" classification.
    const min_pkts_each_dir: count = 10 &redef;

    ## Minimum bytes in each direction.
    const min_bytes_each_dir: count = 100 &redef;

    ## Maximum byte-to-packet ratio (small packets indicate interactive I/O).
    const max_avg_payload: count = 500 &redef;

    ## Destination port range considered suspicious for reverse shells.
    const min_suspicious_port: port = 1024/tcp &redef;

    ## Hosts to monitor (set to your internal network).
    const monitored_nets: set[subnet] = { 192.168.56.0/24 } &redef;
}

event connection_state_remove(c: connection)
    {
    if ( c$conn$proto != tcp )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local dp   = c$id$resp_p;

    # Only flag outbound connections from monitored hosts.
    if ( orig !in monitored_nets )
        return;

    # Skip connections to other monitored hosts on well-known ports.
    if ( dp < min_suspicious_port )
        return;

    # Require minimum duration.
    if ( ! c$conn?$duration || c$conn$duration < min_duration )
        return;

    local orig_bytes = c$conn?$orig_bytes ? c$conn$orig_bytes : 0;
    local resp_bytes = c$conn?$resp_bytes ? c$conn$resp_bytes : 0;
    local orig_pkts  = c$conn?$orig_pkts  ? c$conn$orig_pkts  : 0;
    local resp_pkts  = c$conn?$resp_pkts  ? c$conn$resp_pkts  : 0;

    if ( orig_pkts < min_pkts_each_dir || resp_pkts < min_pkts_each_dir )
        return;

    if ( orig_bytes < min_bytes_each_dir || resp_bytes < min_bytes_each_dir )
        return;

    # Check average payload size -- interactive shells send small packets.
    local avg_orig = orig_bytes / orig_pkts;
    local avg_resp = resp_bytes / resp_pkts;

    if ( avg_orig > max_avg_payload || avg_resp > max_avg_payload )
        return;

    NOTICE([
        $note=Reverse_Shell_Suspected,
        $src=orig,
        $dst=resp,
        $msg=fmt("Suspected reverse shell: %s -> %s:%s (duration=%s, orig=%d bytes/%d pkts, resp=%d bytes/%d pkts)",
                 orig, resp, dp, c$conn$duration,
                 orig_bytes, orig_pkts, resp_bytes, resp_pkts),
        $sub=fmt("avg_payload: orig=%d resp=%d", avg_orig, avg_resp),
        $conn=c,
        $identifier=cat(orig, resp, dp)
    ]);
    }
```

### 4. SSH Brute Force Detector

```zeek
##! Detect SSH brute force attacks by tracking failed authentication
##! attempts per source-destination pair over a sliding window.

@load base/frameworks/notice
@load base/protocols/ssh

module SSHBruteForce;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force_Attempt,
        SSH_Brute_Force_Success_After_Failures
    };

    ## Number of failed SSH attempts before generating a notice.
    const failure_threshold: count = 5 &redef;

    ## Window for tracking failures.
    const tracking_interval: interval = 10min &redef;
}

# Track failures per source-destination pair.
global ssh_failures: table[addr, addr] of count &create_expire=tracking_interval &default=0;

# Track whether a brute-force notice has already been generated.
global bf_noticed: set[addr, addr] &create_expire=tracking_interval;

event ssh_auth_attempted(c: connection, authenticated: bool)
    {
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    if ( ! authenticated )
        {
        ++ssh_failures[orig, resp];

        if ( ssh_failures[orig, resp] >= failure_threshold &&
             [orig, resp] !in bf_noticed )
            {
            add bf_noticed[orig, resp];

            NOTICE([
                $note=SSH_Brute_Force_Attempt,
                $src=orig,
                $dst=resp,
                $msg=fmt("SSH brute force: %s -> %s (%d failures in %s)",
                         orig, resp, ssh_failures[orig, resp],
                         tracking_interval),
                $sub=fmt("%d failures", ssh_failures[orig, resp]),
                $conn=c,
                $identifier=cat(orig, resp)
            ]);
            }
        }
    else
        {
        # Successful auth after prior failures: compromised credential.
        if ( ssh_failures[orig, resp] >= failure_threshold )
            {
            NOTICE([
                $note=SSH_Brute_Force_Success_After_Failures,
                $src=orig,
                $dst=resp,
                $msg=fmt("SSH login success AFTER %d failures: %s -> %s",
                         ssh_failures[orig, resp], orig, resp),
                $conn=c,
                $identifier=cat(orig, resp, "success")
            ]);
            }
        }
    }
```

---

## Deployment Notes

### Adding Scripts to local.zeek

Place custom scripts in the Zeek site directory and load them from `local.zeek`:

```bash
# Typical Zeek site directory
/opt/zeek/share/zeek/site/

# Copy scripts
cp port-scan-detector.zeek /opt/zeek/share/zeek/site/
cp dns-tunnel-detector.zeek /opt/zeek/share/zeek/site/
cp reverse-shell-detector.zeek /opt/zeek/share/zeek/site/
cp ssh-bruteforce-detector.zeek /opt/zeek/share/zeek/site/
```

Append to `/opt/zeek/share/zeek/site/local.zeek`:

```zeek
# Red Team Detection Scripts
@load ./port-scan-detector
@load ./dns-tunnel-detector
@load ./reverse-shell-detector
@load ./ssh-bruteforce-detector
```

### Validating Configuration

```bash
# Check for syntax errors without deploying
zeek -a /opt/zeek/share/zeek/site/local.zeek

# Parse-only check on individual scripts
zeek -a ./port-scan-detector.zeek
```

### Deploying with zeekctl

```bash
# If using zeekctl for cluster management
zeekctl check    # Validate configuration
zeekctl install  # Push configuration to workers
zeekctl restart  # Restart all Zeek nodes
zeekctl status   # Verify nodes are running
```

### Testing Against PCAPs

```bash
# Replay a PCAP through Zeek with custom scripts to verify detections
zeek -r /path/to/lab-capture.pcap /opt/zeek/share/zeek/site/local.zeek

# Check generated notice.log for detections
zeek-cut ts note msg sub < notice.log | sort
```

### Tuning Thresholds

All scripts use `&redef`-able constants. Override values in `local.zeek` without editing the scripts:

```zeek
# Example: tighten the port scan threshold and widen the SSH brute force window
redef PortScanDetector::scan_threshold = 30;
redef PortScanDetector::scan_interval = 2min;
redef SSHBruteForce::failure_threshold = 3;
redef SSHBruteForce::tracking_interval = 15min;
```

### Security Onion Integration

Security Onion runs Zeek as part of its sensor stack. To add custom scripts:

```bash
# Security Onion 2.x stores Zeek customizations under the salt pillar
# Place scripts in the local Zeek directory:
/opt/so/saltstack/local/salt/zeek/policy/

# Add load directives to the local configuration:
# /opt/so/saltstack/local/salt/zeek/policy/local.zeek

# Apply changes through the salt stack:
sudo so-zeek-restart

# Or for the full stack:
sudo so-restart --zeek
```

Monitor detections in Security Onion:

```bash
# Notices appear in Kibana / Elasticsearch under zeek.notice
# Filter by notice type:
#   zeek.notice.note: "PortScanDetector::Port_Scan_Detected"
#   zeek.notice.note: "DNSTunnelDetector::DNS_Tunnel_Long_Label"
#   zeek.notice.note: "ReverseShellDetector::Reverse_Shell_Suspected"
#   zeek.notice.note: "SSHBruteForce::SSH_Brute_Force_Attempt"

# Or query notice.log directly on the sensor:
zeek-cut ts note src dst msg < /nsm/zeek/logs/current/notice.log
```

### Log Rotation and Retention

```bash
# Zeek rotates logs hourly by default. Archived logs are in:
/opt/zeek/logs/YYYY-MM-DD/

# For post-incident correlation, search across archived logs:
zcat /opt/zeek/logs/2026-03-*/conn.*.log.gz \
  | zeek-cut ts id.orig_h id.resp_h id.resp_p duration \
  | awk '$2 == "192.168.56.103"'
```
