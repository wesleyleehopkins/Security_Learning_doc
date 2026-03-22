# ELK Stack Detection Queries — Red Team Correlation

## Overview

This document provides Elasticsearch queries, Logstash filter configurations, and Kibana dashboard specifications for detecting each phase of the red team attack chain in the 192.168.56.0/24 pentest lab. The ELK stack (Elasticsearch, Logstash, Kibana) — whether deployed standalone or as part of Security Onion — serves as the central log aggregation and analysis platform. All queries use Lucene/KQL syntax compatible with Kibana's search bar and saved searches.

## Logstash Filter Configuration

### Zeek JSON Log Parsing

Zeek outputs JSON logs when configured with `@load policy/tuning/json-logs.zeek`. This Logstash filter parses all Zeek log types and normalizes fields.

```ruby
filter {
  if [type] == "zeek" {
    json {
      source => "message"
    }

    # Normalize timestamp
    date {
      match => ["ts", "UNIX"]
      target => "@timestamp"
    }

    # Parse connection log fields
    if [_path] == "conn" {
      mutate {
        rename => {
          "id.orig_h" => "source_ip"
          "id.orig_p" => "source_port"
          "id.resp_h" => "dest_ip"
          "id.resp_p" => "dest_port"
          "orig_bytes" => "bytes_sent"
          "resp_bytes" => "bytes_received"
        }
      }
      # GeoIP enrichment for external IPs
      geoip {
        source => "dest_ip"
        target => "dest_geo"
      }
    }

    # Parse HTTP log fields
    if [_path] == "http" {
      mutate {
        rename => {
          "id.orig_h" => "source_ip"
          "id.resp_h" => "dest_ip"
          "host" => "http_host"
          "uri" => "http_uri"
          "method" => "http_method"
          "status_code" => "http_status"
          "user_agent" => "http_user_agent"
          "resp_mime_types" => "http_mime_type"
        }
      }
    }

    # Parse DNS log fields
    if [_path] == "dns" {
      mutate {
        rename => {
          "id.orig_h" => "source_ip"
          "query" => "dns_query"
          "qtype_name" => "dns_query_type"
          "answers" => "dns_answers"
        }
      }
    }

    # Add log type tag
    mutate {
      add_field => { "log_source" => "zeek" }
      add_field => { "zeek_log_type" => "%{_path}" }
    }
  }
}
```

### OSSEC Alert Parsing

```ruby
filter {
  if [type] == "ossec" {
    json {
      source => "message"
    }

    # Parse OSSEC alert fields
    mutate {
      rename => {
        "rule.id" => "ossec_rule_id"
        "rule.level" => "ossec_severity"
        "rule.description" => "ossec_description"
        "agent.name" => "ossec_agent"
        "agent.ip" => "agent_ip"
        "full_log" => "ossec_full_log"
      }
    }

    # Parse timestamp
    date {
      match => ["timestamp", "yyyy MMM dd HH:mm:ss"]
      target => "@timestamp"
    }

    # Tag high-severity alerts
    if [ossec_severity] and [ossec_severity] >= 10 {
      mutate {
        add_tag => ["high_severity"]
      }
    }

    mutate {
      add_field => { "log_source" => "ossec" }
    }
  }
}
```

### Sysmon via Winlogbeat

```ruby
filter {
  if [agent.type] == "winlogbeat" {
    # Sysmon events are under winlog.event_data
    if [winlog][provider_name] == "Microsoft-Windows-Sysmon" {
      mutate {
        add_field => { "log_source" => "sysmon" }
        add_field => { "sysmon_event_id" => "%{[winlog][event_id]}" }
      }

      # Event ID 1: Process Creation
      if [winlog][event_id] == 1 {
        mutate {
          rename => {
            "[winlog][event_data][Image]" => "process_name"
            "[winlog][event_data][CommandLine]" => "command_line"
            "[winlog][event_data][ParentImage]" => "parent_process"
            "[winlog][event_data][ParentCommandLine]" => "parent_command_line"
            "[winlog][event_data][User]" => "process_user"
            "[winlog][event_data][Hashes]" => "process_hashes"
          }
        }
      }

      # Event ID 3: Network Connection
      if [winlog][event_id] == 3 {
        mutate {
          rename => {
            "[winlog][event_data][DestinationIp]" => "dest_ip"
            "[winlog][event_data][DestinationPort]" => "dest_port"
            "[winlog][event_data][Image]" => "process_name"
          }
        }
      }

      # Event ID 13: Registry Value Set
      if [winlog][event_id] == 13 {
        mutate {
          rename => {
            "[winlog][event_data][TargetObject]" => "registry_key"
            "[winlog][event_data][Details]" => "registry_value"
            "[winlog][event_data][Image]" => "process_name"
          }
        }
      }
    }
  }
}
```

### Apache Access Logs

```ruby
filter {
  if [type] == "apache-access" {
    grok {
      match => {
        "message" => '%{IPORHOST:source_ip} - %{DATA:user} \[%{HTTPDATE:timestamp}\] "%{WORD:http_method} %{URIPATHPARAM:http_uri} HTTP/%{NUMBER:http_version}" %{NUMBER:http_status} %{NUMBER:http_bytes} "%{DATA:http_referrer}" "%{DATA:http_user_agent}"'
      }
    }

    date {
      match => ["timestamp", "dd/MMM/yyyy:HH:mm:ss Z"]
      target => "@timestamp"
    }

    # Detect suspicious user agents
    if [http_user_agent] =~ /sqlmap|nikto|dirb|dirbuster|gobuster|wfuzz|hydra|nmap/i {
      mutate {
        add_tag => ["suspicious_tool"]
      }
    }

    # Detect SQL injection attempts in URI
    if [http_uri] =~ /(\%27|'|union|select|insert|drop|update|delete|exec|xp_|0x|char\()/i {
      mutate {
        add_tag => ["sqli_attempt"]
      }
    }

    mutate {
      add_field => { "log_source" => "apache" }
    }
  }
}
```

### auth.log Parsing

```ruby
filter {
  if [type] == "auth" {
    grok {
      match => {
        "message" => [
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sshd\[%{POSINT:pid}\]: %{DATA:ssh_event} for %{DATA:username} from %{IP:source_ip} port %{NUMBER:source_port} ssh2",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sshd\[%{POSINT:pid}\]: %{DATA:ssh_event} for invalid user %{DATA:username} from %{IP:source_ip} port %{NUMBER:source_port} ssh2",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} sudo: %{DATA:username} : %{GREEDYDATA:sudo_command}",
          "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:hostname} %{DATA:service}\[%{POSINT:pid}\]: %{GREEDYDATA:auth_message}"
        ]
      }
    }

    date {
      match => ["timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss"]
      target => "@timestamp"
    }

    # Tag failed authentication
    if [ssh_event] =~ /Failed/ {
      mutate {
        add_tag => ["auth_failure"]
        add_field => { "auth_result" => "failure" }
      }
    }

    if [ssh_event] =~ /Accepted/ {
      mutate {
        add_field => { "auth_result" => "success" }
      }
    }

    mutate {
      add_field => { "log_source" => "auth" }
    }
  }
}
```

## Elasticsearch Queries (Lucene/KQL)

### Phase 2: Scanning

**Query 1 — Port scan detection from Zeek conn.log:**

Detects a single source IP connecting to many destination ports in a short time window.

```
zeek_log_type:conn AND source_ip:192.168.56.103 AND dest_ip:192.168.56.102
```

Use a `date_histogram` aggregation on `@timestamp` with a `terms` sub-aggregation on `dest_port`. A source connecting to more than 100 unique ports in 60 seconds indicates a port scan.

**Query 2 — SYN scan detection (connection state):**

```
zeek_log_type:conn AND source_ip:192.168.56.103 AND conn_state:S0
```

`S0` connection state in Zeek means SYN sent, no reply — the hallmark of SYN scanning. A high volume of S0 connections from a single source is a definitive scan indicator.

**Query 3 — Nmap service version detection:**

```
zeek_log_type:conn AND source_ip:192.168.56.103 AND conn_state:(SF OR S1) AND NOT dest_port:(22 OR 80 OR 443 OR 445)
```

Nmap's version scan completes full connections (SF state) to many ports. This query finds completed connections to unusual ports.

**Query 4 — Directory brute force from Apache logs:**

```
log_source:apache AND source_ip:192.168.56.103 AND http_status:404
```

A high volume of 404 responses from a single IP indicates directory enumeration (dirb, gobuster, feroxbuster). Aggregate by time and count; normal traffic rarely exceeds 5-10 404s per minute.

**Query 5 — Directory brute force with tool detection:**

```
log_source:apache AND http_user_agent:(*gobuster* OR *dirb* OR *dirbuster* OR *nikto* OR *wfuzz* OR *feroxbuster*)
```

Many directory brute-force tools use identifiable User-Agent strings.

### Phase 3: Web Exploitation

**Query 6 — SQL injection patterns in HTTP URI:**

```
zeek_log_type:http AND dest_ip:192.168.56.102 AND (http_uri:*UNION* OR http_uri:*SELECT* OR http_uri:*%27* OR http_uri:*OR%201%3D1* OR http_uri:*'OR'* OR http_uri:*--*)
```

Detects common SQL injection keywords and encoded characters in HTTP requests.

**Query 7 — SQL injection via Apache logs (decoded):**

```
log_source:apache AND tags:sqli_attempt AND source_ip:192.168.56.103
```

Uses the tag applied by the Logstash filter for pre-identified SQLi attempts.

**Query 8 — XSS payload detection:**

```
zeek_log_type:http AND (http_uri:*<script>* OR http_uri:*%3Cscript%3E* OR http_uri:*javascript%3A* OR http_uri:*onerror%3D* OR http_uri:*onload%3D* OR http_uri:*alert(*)
```

Detects reflected XSS attempts in URL parameters.

**Query 9 — File upload anomalies:**

```
zeek_log_type:http AND http_method:POST AND dest_ip:192.168.56.102 AND dest_port:80 AND (http_uri:*upload* OR http_uri:*file*)
```

Combined with a filter on `http_mime_type` for executable MIME types:

```
zeek_log_type:files AND source_ip:192.168.56.103 AND (mime_type:*php* OR mime_type:*executable* OR mime_type:*x-sh* OR mime_type:*x-python*)
```

**Query 10 — Web shell access detection:**

```
log_source:apache AND http_uri:(*cmd* OR *shell* OR *c99* OR *r57* OR *webshell*) AND http_status:200 AND source_ip:192.168.56.103
```

Detects access to known web shell filenames or URI patterns that return HTTP 200.

### Phase 4: Password Attacks

**Query 11 — SSH authentication failure spike:**

```
log_source:auth AND auth_result:failure AND source_ip:192.168.56.103
```

Aggregate by 1-minute intervals. More than 10 failures per minute from a single source strongly indicates brute force (Hydra, Medusa, or Metasploit auxiliary modules).

**Query 12 — Brute force followed by success:**

```
log_source:auth AND source_ip:192.168.56.103 AND (auth_result:failure OR auth_result:success)
```

Sort by `@timestamp`. The pattern of many consecutive failures followed by a single success is the signature of a successful brute-force attack. Alert when `auth_result:success` appears after 5+ failures from the same source within 10 minutes.

**Query 13 — SMB/Windows authentication failure spike:**

```
log_source:sysmon AND winlog.event_id:4625 AND source.ip:192.168.56.103
```

Windows Event ID 4625 records failed logon attempts. High volume from the attacker IP indicates password spraying or brute force against Windows.

**Query 14 — Credential dumping tool indicators:**

```
log_source:sysmon AND sysmon_event_id:1 AND (command_line:*mimikatz* OR command_line:*sekurlsa* OR command_line:*lsadump* OR command_line:*procdump* OR command_line:*lsass* OR process_name:*mimikatz*)
```

Detects execution of Mimikatz or tools that dump credentials from LSASS.

### Phase 5-7: Exploitation & Privilege Escalation

**Query 15 — Suspicious process creation (Sysmon Event ID 1):**

```
log_source:sysmon AND sysmon_event_id:1 AND (command_line:*powershell* AND (command_line:*-enc* OR command_line:*-e * OR command_line:*downloadstring* OR command_line:*IEX* OR command_line:*bypass*))
```

Detects encoded PowerShell commands, download cradles, and execution policy bypasses commonly used in exploitation.

**Query 16 — Meterpreter/reverse shell process chains:**

```
log_source:sysmon AND sysmon_event_id:1 AND parent_process:(*apache* OR *httpd* OR *w3wp* OR *php* OR *python*) AND (process_name:*cmd* OR process_name:*powershell* OR process_name:*bash* OR process_name:*sh*)
```

A web server spawning a command shell is a strong indicator of web exploitation leading to code execution.

**Query 17 — Service modification for persistence or privilege escalation:**

```
log_source:sysmon AND sysmon_event_id:1 AND (command_line:*sc create* OR command_line:*sc config* OR command_line:*New-Service* OR command_line:*Set-Service*)
```

Detects creation or modification of Windows services, a common technique for both persistence (creating a backdoor service) and privilege escalation (modifying a service to run as SYSTEM).

**Query 18 — Registry changes for UAC bypass:**

```
log_source:sysmon AND sysmon_event_id:13 AND (registry_key:*\\Software\\Classes\\mscfile\\shell\\open\\command* OR registry_key:*\\Software\\Classes\\ms-settings\\shell\\open\\command* OR registry_key:*\\Environment\\windir* OR registry_key:*\\fodhelper*)
```

Common UAC bypass techniques involve modifying registry keys under HKCU to hijack the execution of auto-elevated binaries like `eventvwr.exe`, `fodhelper.exe`, or `computerdefaults.exe`.

**Query 19 — Linux privilege escalation via SUID/sudo:**

```
log_source:auth AND (sudo_command:*bash* OR sudo_command:*sh* OR sudo_command:*su* OR sudo_command:*passwd* OR sudo_command:*chmod* OR sudo_command:*chown*)
```

Detects suspicious sudo usage that may indicate privilege escalation through misconfigured sudo rules.

**Query 20 — Kernel exploit indicators:**

```
log_source:sysmon AND sysmon_event_id:1 AND (command_line:*exploit* OR command_line:*dirty* OR command_line:*overlayfs* OR command_line:*pkexec* OR command_line:*pwnkit* OR process_name:*exploit*)
```

Detects execution of known kernel exploit binaries.

### Phase 8: Post-Exploitation

**Query 21 — Persistence indicators (scheduled tasks/cron):**

```
log_source:sysmon AND sysmon_event_id:1 AND (command_line:*schtasks* AND command_line:*/create*) OR (command_line:*crontab* OR command_line:*/etc/cron*)
```

Detects creation of scheduled tasks (Windows) or cron jobs (Linux) for persistence.

**Query 22 — Persistence via registry Run keys:**

```
log_source:sysmon AND sysmon_event_id:13 AND registry_key:(*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce* OR *\\CurrentVersion\\RunServices*)
```

Detects modifications to Run/RunOnce registry keys, a classic persistence mechanism.

**Query 23 — Lateral movement via SMB:**

```
zeek_log_type:smb_files AND source_ip:192.168.56.102 AND dest_ip:192.168.56.101 AND (filename:*exe* OR filename:*dll* OR filename:*bat* OR filename:*ps1*)
```

Detects executable files being transferred between internal hosts via SMB, a strong indicator of lateral movement.

**Query 24 — Lateral movement via WinRM/PSRemoting:**

```
zeek_log_type:conn AND source_ip:(192.168.56.102 OR 192.168.56.103) AND dest_ip:192.168.56.101 AND dest_port:5985
```

WinRM connections from the attacker or a compromised host to the Windows target.

**Query 25 — Data exfiltration via DNS tunneling:**

```
zeek_log_type:dns AND source_ip:(192.168.56.101 OR 192.168.56.102) AND dns_query_type:TXT
```

DNS TXT queries from internal hosts may indicate DNS tunneling for data exfiltration. Also look for unusually long domain names:

```
zeek_log_type:dns AND dns_query:/[a-zA-Z0-9]{30,}\./
```

Queries with subdomains longer than 30 characters often indicate encoded data being exfiltrated.

**Query 26 — Data exfiltration via HTTP POST:**

```
zeek_log_type:http AND source_ip:(192.168.56.101 OR 192.168.56.102) AND http_method:POST AND NOT dest_ip:192.168.56.0/24
```

HTTP POST requests from internal hosts to external destinations may indicate data exfiltration. Combine with byte count analysis to flag large uploads.

**Query 27 — New outbound connections (C2 indicators):**

```
zeek_log_type:conn AND source_ip:(192.168.56.101 OR 192.168.56.102) AND NOT dest_ip:192.168.56.0/24 AND dest_port:(443 OR 80 OR 8080 OR 8443)
```

After establishing a baseline, any new outbound connections from targets to external IPs warrant investigation as potential C2 channels.

## Kibana Dashboard JSON

### Key Visualizations

**1. Authentication Failures Timeline**

- **Type:** Line chart / Area chart
- **Index pattern:** `auth-*` and `winlogbeat-*`
- **X-axis:** `@timestamp` (date histogram, 1-minute interval)
- **Y-axis:** Count of documents
- **Filter:** `auth_result:failure OR winlog.event_id:4625`
- **Split series:** By `source_ip` (terms aggregation)
- **Purpose:** Shows the time distribution of authentication failures. Brute-force attacks appear as sharp spikes. Multiple source IPs spiking simultaneously may indicate password spraying.

**2. Network Connections Heatmap**

- **Type:** Heatmap
- **Index pattern:** `zeek-*`
- **X-axis:** `dest_port` (terms, top 50)
- **Y-axis:** `source_ip` (terms, top 20)
- **Value:** Count of connections
- **Filter:** `zeek_log_type:conn`
- **Purpose:** Visualizes which hosts are connecting to which ports. Port scans appear as a single source IP lighting up across many destination ports. Lateral movement shows as new source-destination pairs on management ports.

**3. Process Creation Tree**

- **Type:** Data table with drill-down
- **Index pattern:** `winlogbeat-*`
- **Columns:** `@timestamp`, `process_user`, `parent_process`, `process_name`, `command_line`
- **Filter:** `log_source:sysmon AND sysmon_event_id:1`
- **Sort:** `@timestamp` descending
- **Purpose:** Shows process execution chains. Analysts can trace how an attacker's commands flowed: web server to shell to privilege escalation tool. Filter by `parent_process:*cmd*` or `parent_process:*powershell*` to focus on interactive attacker sessions.

**4. File Integrity Changes**

- **Type:** Timeline / Event list
- **Index pattern:** `ossec-*`
- **Columns:** `@timestamp`, `ossec_agent`, `ossec_rule_id`, `ossec_description`, `ossec_full_log`
- **Filter:** `ossec_rule_id:(550 OR 553 OR 554 OR 591)`
- **Purpose:** Displays OSSEC file integrity monitoring (FIM) alerts. Rule 550 covers file modifications, 553/554 cover ownership/permission changes, and 591 covers new files. Critical files to monitor: `/etc/passwd`, `/etc/shadow`, `/etc/crontab`, `.ssh/authorized_keys`, Windows `System32` directory.

**5. Alert Summary**

- **Type:** Pie chart + data table
- **Index pattern:** `suricata-*`, `ossec-*`
- **Pie chart:** Breakdown by `alert.category` or `ossec_rule_id`
- **Data table:** Top 20 alerts by count, with columns for severity, rule name, source IP, destination IP
- **Filter:** Last 24 hours
- **Purpose:** Executive-level overview of alert distribution. Shows which attack categories are generating the most alerts, helping analysts prioritize investigation.

## Alerting Rules (Kibana Alerting / ElastAlert)

### ElastAlert YAML Rules

**Rule 1 — Port Scan Detection:**

```yaml
name: "Port Scan Detected"
type: cardinality
index: zeek-*
timeframe:
  seconds: 60
query_key: source_ip
cardinality_field: dest_port
max_cardinality: 100
filter:
  - term:
      zeek_log_type: conn
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  Port scan detected from {0}.
  {1} unique destination ports contacted in 60 seconds.
alert_text_args:
  - source_ip
  - cardinality_dest_port
```

**Rule 2 — SSH Brute Force:**

```yaml
name: "SSH Brute Force Attempt"
type: frequency
index: auth-*
num_events: 10
timeframe:
  minutes: 5
filter:
  - term:
      auth_result: failure
  - term:
      log_source: auth
query_key: source_ip
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  SSH brute force detected from {0}.
  {1} failed authentication attempts in 5 minutes.
alert_text_args:
  - source_ip
  - num_matches
```

**Rule 3 — Successful Login After Brute Force:**

```yaml
name: "Brute Force Success - Immediate Investigation Required"
type: flatline
index: auth-*
timeframe:
  minutes: 1
threshold: 0
filter:
  - term:
      auth_result: success
  - term:
      log_source: auth
depends_on_past_match:
  rule: "SSH Brute Force Attempt"
  timeframe:
    minutes: 10
alert:
  - email
email:
  - soc-team@lab.local
priority: 1
alert_text: |
  CRITICAL: Successful login detected from {0} within 10 minutes of brute force activity.
  Username: {1}
  Immediate investigation required.
alert_text_args:
  - source_ip
  - username
```

**Rule 4 — SQL Injection Attempt:**

```yaml
name: "SQL Injection Detected in HTTP Traffic"
type: any
index: apache-*
filter:
  - query:
      query_string:
        query: "tags:sqli_attempt"
query_key: source_ip
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  SQL injection attempt detected from {0}.
  URI: {1}
  User-Agent: {2}
alert_text_args:
  - source_ip
  - http_uri
  - http_user_agent
```

**Rule 5 — Reverse Shell Connection:**

```yaml
name: "Reverse Shell Connection Detected"
type: any
index: zeek-*
filter:
  - term:
      zeek_log_type: conn
  - terms:
      dest_port: [4444, 4445, 4446, 5555, 6666, 1337, 31337]
  - term:
      conn_state: SF
alert:
  - email
email:
  - soc-team@lab.local
priority: 1
alert_text: |
  CRITICAL: Possible reverse shell connection.
  Source: {0}:{1} -> Destination: {2}:{3}
  Duration: {4} seconds, Bytes transferred: {5}
alert_text_args:
  - source_ip
  - source_port
  - dest_ip
  - dest_port
  - duration
  - bytes_sent
```

**Rule 6 — Suspicious PowerShell Execution:**

```yaml
name: "Suspicious PowerShell Execution"
type: any
index: winlogbeat-*
filter:
  - term:
      sysmon_event_id: "1"
  - query:
      query_string:
        query: 'command_line:(*-enc* OR *downloadstring* OR *IEX* OR *bypass* OR *hidden* OR *-nop*) AND process_name:*powershell*'
alert:
  - email
email:
  - soc-team@lab.local
priority: 1
alert_text: |
  Suspicious PowerShell execution on {0}.
  User: {1}
  Command: {2}
  Parent Process: {3}
alert_text_args:
  - computer_name
  - process_user
  - command_line
  - parent_process
```

**Rule 7 — New Windows Service Created:**

```yaml
name: "New Windows Service Created"
type: any
index: winlogbeat-*
filter:
  - term:
      sysmon_event_id: "1"
  - query:
      query_string:
        query: 'command_line:(*sc create* OR *New-Service*)'
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  New Windows service created on {0}.
  Command: {1}
  User: {2}
  Parent: {3}
alert_text_args:
  - computer_name
  - command_line
  - process_user
  - parent_process
```

**Rule 8 — Registry Persistence Modification:**

```yaml
name: "Registry Run Key Modified - Persistence Indicator"
type: any
index: winlogbeat-*
filter:
  - term:
      sysmon_event_id: "13"
  - query:
      query_string:
        query: 'registry_key:(*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce*)'
alert:
  - email
email:
  - soc-team@lab.local
priority: 1
alert_text: |
  Registry persistence mechanism detected on {0}.
  Key: {1}
  Value: {2}
  Process: {3}
alert_text_args:
  - computer_name
  - registry_key
  - registry_value
  - process_name
```

**Rule 9 — Lateral Movement via SMB File Transfer:**

```yaml
name: "Executable File Transferred via SMB"
type: any
index: zeek-*
filter:
  - term:
      zeek_log_type: smb_files
  - query:
      query_string:
        query: 'filename:(*.exe OR *.dll OR *.bat OR *.ps1 OR *.vbs)'
  - query:
      query_string:
        query: 'source_ip:192.168.56.0/24 AND dest_ip:192.168.56.0/24'
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  Executable file transferred via SMB between internal hosts.
  Source: {0} -> Destination: {1}
  Filename: {2}
  This may indicate lateral movement.
alert_text_args:
  - source_ip
  - dest_ip
  - filename
```

**Rule 10 — DNS Tunneling Detection:**

```yaml
name: "Possible DNS Tunneling Detected"
type: any
index: zeek-*
filter:
  - term:
      zeek_log_type: dns
  - script:
      script: "doc['dns_query.keyword'].value.length() > 50"
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  Possible DNS tunneling detected.
  Source: {0}
  Query: {1}
  Query Type: {2}
  Long domain names in DNS queries may indicate encoded data exfiltration.
alert_text_args:
  - source_ip
  - dns_query
  - dns_query_type
```

**Rule 11 — UAC Bypass Attempt:**

```yaml
name: "UAC Bypass Registry Modification"
type: any
index: winlogbeat-*
filter:
  - term:
      sysmon_event_id: "13"
  - query:
      query_string:
        query: 'registry_key:(*mscfile\\shell\\open\\command* OR *ms-settings\\shell\\open\\command* OR *fodhelper*)'
alert:
  - email
email:
  - soc-team@lab.local
priority: 1
alert_text: |
  CRITICAL: UAC bypass attempt detected on {0}.
  Registry Key: {1}
  Value: {2}
  Process: {3}
  This technique is commonly used to escalate privileges without triggering UAC prompts.
alert_text_args:
  - computer_name
  - registry_key
  - registry_value
  - process_name
```

**Rule 12 — Large Data Transfer (Exfiltration):**

```yaml
name: "Large Outbound Data Transfer - Possible Exfiltration"
type: metric_aggregation
index: zeek-*
buffer_time:
  minutes: 10
metric_agg_key: source_ip
metric_agg_type: sum
doc_type: _doc
query_key: source_ip
filter:
  - term:
      zeek_log_type: conn
  - range:
      bytes_sent:
        gte: 1000
  - query:
      query_string:
        query: 'NOT dest_ip:192.168.56.0/24'
metric_agg_metric_name: bytes_sent
max_threshold: 52428800
alert:
  - email
email:
  - soc-team@lab.local
alert_text: |
  Large outbound data transfer detected.
  Source: {0}
  Total bytes sent: {1} in 10 minutes.
  Possible data exfiltration. Investigate immediately.
alert_text_args:
  - source_ip
  - metric_bytes_sent
```
