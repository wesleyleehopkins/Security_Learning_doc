# Security Onion Integration — Red Team Correlation

## Overview

Security Onion serves as the central monitoring platform for the pentest lab, providing full-packet capture, network-based intrusion detection (Suricata), network security monitoring (Zeek), and log management via the Elastic Stack. This document covers how to deploy and configure Security Onion to observe and detect every phase of the red team attack chain across the 192.168.56.0/24 lab network.

## Architecture

### Network Diagram

```
┌─────────────────────────────────────────────────────┐
│              Host-Only Network: 192.168.56.0/24     │
│                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────┐│
│  │  Kali Linux  │  │   Ubuntu     │  │  Windows   ││
│  │  (Attacker)  │  │  (Target)    │  │  (Target)  ││
│  │ .103         │  │ .102         │  │ .101       ││
│  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘│
│         │                 │                 │       │
│         └────────┬────────┴────────┬────────┘       │
│                  │                 │                 │
│          ┌───────┴─────────────────┴───────┐        │
│          │     Security Onion (.110)       │        │
│          │     Standalone Deployment       │        │
│          │     - Suricata (IDS)            │        │
│          │     - Zeek (NSM)                │        │
│          │     - Elasticsearch             │        │
│          │     - Kibana (SOC Console)      │        │
│          │     - PCAP Storage              │        │
│          │     - OSSEC Manager             │        │
│          └─────────────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

### Standalone Deployment

Security Onion is deployed in **Standalone** mode on a dedicated VM at 192.168.56.110. In Standalone mode, a single node runs all services: sensor components (Suricata, Zeek, Stenographer for PCAP), server components (Elasticsearch, Logstash, Kibana, Redis), and the Security Onion Console (SOC) web interface.

**VM Requirements:**
- 4+ CPU cores (8 recommended for full PCAP + IDS + Zeek)
- 8 GB RAM minimum (16 GB recommended)
- 200 GB disk for PCAP storage, Elasticsearch indices, and logs
- Two network interfaces:
  - **Management interface (eth0):** 192.168.56.110 — used for web UI access and OSSEC agent communication
  - **Sniffing interface (eth1):** No IP assigned, set to promiscuous mode on the host-only network

**Promiscuous Mode Configuration:**

The sniffing interface must be in promiscuous mode to capture all traffic on the host-only network segment. In VirtualBox, enable this under the VM network adapter settings:

```
Settings > Network > Adapter 2 > Advanced > Promiscuous Mode: Allow All
```

For VMware, enable promiscuous mode on the virtual switch or port group associated with the host-only network.

**Installation:**

```bash
# After booting the Security Onion ISO
sudo so-setup
# Select: Standalone
# Management interface: eth0 (192.168.56.110)
# Sniffing interface: eth1
# Accept defaults for Suricata + Zeek
```

## Suricata/Snort Configuration

### Adding Local Rules

Security Onion uses Suricata by default. Custom rules for detecting lab attack phases are maintained in the local rules file.

**Local rules path:**
```
/opt/so/rules/nids/local.rules
```

To add rules that detect specific attack signatures (SQL injection, reverse shells, credential brute force), edit the local rules file:

```bash
sudo vi /opt/so/rules/nids/local.rules
```

Example rules to add (see `snort-detections.md` for the full rule set):

```
# Detect Nmap SYN scan
alert tcp any any -> $HOME_NET any (msg:"ET SCAN Nmap SYN Scan"; flags:S; threshold:type both, track by_src, count 50, seconds 10; sid:1000001; rev:1;)

# Detect SQLi in HTTP traffic
alert http any any -> $HOME_NET any (msg:"LOCAL SQLi UNION SELECT detected"; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; sid:1000010; rev:1;)

# Detect reverse shell on common ports
alert tcp $HOME_NET any -> any 4444 (msg:"LOCAL Possible Reverse Shell to port 4444"; flow:established,to_server; sid:1000020; rev:1;)
```

After adding rules, update the Suricata configuration:

```bash
sudo so-rule-update
```

### so-rule-update Process

`so-rule-update` performs the following:
1. Downloads updated rule sets from configured sources (ET Open, etc.)
2. Merges local rules from `/opt/so/rules/nids/local.rules`
3. Applies any modifications defined in `/opt/so/rules/nids/modify.conf`
4. Applies any suppressions from `/opt/so/rules/nids/disablesid.conf`
5. Restarts Suricata to load the new combined rule set

```bash
# Full rule update
sudo so-rule-update

# Verify Suricata is running after update
sudo so-status | grep suricata
```

### Tuning Thresholds for Lab Environment

In a small lab, default thresholds may generate excessive noise or miss low-volume attacks. Adjust thresholds in `/opt/so/rules/nids/threshold.conf`:

```
# Reduce threshold for port scan detection in small lab
suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.56.103

# Set rate-based threshold for SSH brute force
event_filter gen_id 1, sig_id 2001219, type both, track by_src, count 5, seconds 60

# Lower threshold for HTTP attacks since lab traffic volume is small
event_filter gen_id 1, sig_id 1000010, type threshold, track by_src, count 3, seconds 120
```

Disable noisy rules that are not relevant to the lab:

```bash
# /opt/so/rules/nids/disablesid.conf
# Disable rules that fire on normal lab traffic
1:2210000  # Suricata STREAM rules (noisy in lab)
1:2100498  # GPL attack response (false positives)
```

## Zeek Configuration

### Local.zeek Additions

Custom Zeek scripts and configuration additions are placed in the local Zeek policy file:

```
/opt/so/saltstack/local/salt/zeek/policy/local.zeek
```

Add detection scripts referenced in `zeek-detections.md`:

```zeek
# /opt/so/saltstack/local/salt/zeek/policy/local.zeek

# Enable additional protocol analyzers
@load protocols/ssh/detect-bruteforcing
@load protocols/http/detect-sqli
@load protocols/smb/log-cmds
@load protocols/ftp/software
@load protocols/dns/detect-external-names

# Enable file extraction for uploads
@load frameworks/files/extract-all-files

# Enable notice framework for alerting
@load frameworks/notice

# Load custom scripts for lab detection
@load ./detect-portscan.zeek
@load ./detect-lateral-movement.zeek
@load ./detect-exfiltration.zeek
@load ./detect-persistence.zeek
```

### Custom Script Deployment Path

Custom Zeek scripts for the lab are placed in:

```
/opt/so/saltstack/local/salt/zeek/policy/
```

After adding or modifying scripts, apply the changes:

```bash
sudo salt-call state.apply zeek
# or restart Zeek directly
sudo so-zeek-restart
```

### Enabling Additional Zeek Modules

Key modules to enable for detecting the lab attack chain:

```zeek
# SSH brute force detection with lab-appropriate thresholds
redef SSH::password_guesses_limit = 5;

# SMB command logging for lateral movement detection
redef SMB::logged_cmds += { "tree_connect", "tree_disconnect", "nt_create", "read", "write", "close" };

# File extraction settings
redef FileExtract::prefix = "/opt/so/zeek/extracted/";

# DNS query logging (detect C2 DNS tunneling)
redef DNS::max_pending = 50;

# Notice policy — send all notices to notice.log and the Elastic pipeline
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}
```

## Elasticsearch/Kibana Dashboards

### Key Index Patterns

Configure the following index patterns in Kibana (accessible at `https://192.168.56.110`):

| Index Pattern | Description |
|---|---|
| `*:so-suricata-*` | Suricata IDS alerts and flow data |
| `*:so-zeek-*` | All Zeek log types (conn, http, dns, ssh, smb, files, notice) |
| `*:so-ossec-*` | OSSEC/Wazuh host-based alerts |
| `*:so-syslog-*` | Syslog events forwarded from targets |
| `*:so-beats-*` | Winlogbeat/Filebeat data from endpoints |

### Dashboard Descriptions for Each Attack Phase

**1. Reconnaissance & Scanning Dashboard**
- Suricata scan alerts grouped by source IP
- Zeek conn.log summary: unique destination ports per source IP over time
- DNS query volume by source (detects DNS enumeration)
- Top talkers bar chart filtered to 192.168.56.103

**2. Web Exploitation Dashboard**
- HTTP status code distribution (focus on 200 vs 403/404/500)
- Suricata HTTP alerts timeline (SQLi, XSS, file upload signatures)
- Zeek http.log: requests with suspicious URI patterns
- Apache access log entries from Filebeat showing attack payloads

**3. Credential Attack Dashboard**
- SSH authentication failure rate over time (Zeek ssh.log + auth.log)
- SMB authentication failure spikes (Zeek smb_mapping.log)
- OSSEC alerts for PAM failures and account lockouts
- Brute force followed by success correlation

**4. Post-Exploitation & Lateral Movement Dashboard**
- New network connections between internal hosts
- Zeek conn.log: connections to previously unseen ports
- SMB file access patterns (Zeek smb_files.log)
- Sysmon process creation events (Event ID 1) from Winlogbeat
- Registry modification events (Sysmon Event ID 13)

**5. Data Exfiltration Dashboard**
- Outbound data transfer volume by destination
- DNS query length distribution (detect DNS tunneling)
- HTTP POST request sizes over time
- Connections to external IPs not in baseline

### Saved Search Queries for SOC Analysts

```
# Find all Suricata alerts from the attacker
event.module:suricata AND source.ip:192.168.56.103

# Zeek SSH brute force attempts
event.dataset:zeek.ssh AND zeek.ssh.auth_success:false

# HTTP requests with SQL injection patterns
event.dataset:zeek.http AND (url.original:*UNION* OR url.original:*SELECT* OR url.original:*%27*)

# Lateral movement: internal-to-internal SMB
event.dataset:zeek.smb_mapping AND source.ip:192.168.56.0/24 AND destination.ip:192.168.56.0/24

# New listening services detected
event.dataset:zeek.conn AND zeek.conn.local_resp:true AND NOT destination.port:(22 OR 80 OR 443 OR 445 OR 139 OR 3389)
```

### Alert Configuration in Kibana

Create Kibana detection rules under **Security > Rules**:

1. **Port Scan Threshold:** Trigger when a single source IP connects to more than 50 unique destination ports within 60 seconds.
2. **Brute Force Alert:** Trigger when SSH/SMB authentication failures exceed 10 in 5 minutes from a single source.
3. **Reverse Shell Alert:** Trigger on any Suricata alert matching SID range 1000020-1000030.
4. **Lateral Movement Alert:** Trigger on internal-to-internal connections on ports 445, 5985, 5986 from non-baseline source IPs.
5. **Data Exfiltration Alert:** Trigger when outbound transfer volume exceeds 50 MB in 10 minutes to a single destination.

## SOC Analyst Workflow

### Step-by-Step Detection Workflow

**Step 1: Check Alerts Dashboard for Suricata Hits**

Navigate to the SOC web interface at `https://192.168.56.110` and open the Alerts dashboard.

```
SOC Console > Alerts
- Filter: time range last 24 hours
- Sort by severity (descending)
- Group by: rule.name
```

Look for clusters of alerts indicating:
- Scanning activity (multiple ET SCAN rules firing)
- Web attack signatures (SQLi, XSS, path traversal)
- Reverse shell connections (LOCAL rules on ports 4444, 4445, 4446)
- Known exploit signatures (EternalBlue, MS17-010)

**Step 2: Pivot to Zeek Logs for Context**

From any Suricata alert, pivot to Zeek logs for richer context:

```
SOC Console > Hunt
- Query: source.ip:192.168.56.103 AND @timestamp:[alert_time - 5m TO alert_time + 5m]
- Filter by event.dataset: zeek.conn, zeek.http, zeek.ssh, zeek.smb_mapping
```

Zeek provides:
- Full connection metadata (duration, bytes transferred, connection state)
- HTTP request/response details (URI, user-agent, status code, MIME type)
- SSH session details (authentication success/failure, client/server versions)
- SMB file access and share mapping details
- DNS queries for C2 domain resolution

**Step 3: PCAP Retrieval for Deep-Dive**

For detailed packet analysis, retrieve the relevant PCAP:

```bash
# From the Security Onion CLI
sudo so-pcap 192.168.56.103 192.168.56.102 2026-03-15

# Or use the SOC web interface:
# Click on any alert > Actions > PCAP
# This retrieves the full packet capture for that flow from Stenographer
```

Open the PCAP in Wireshark or NetworkMiner for:
- Full payload inspection of exploit traffic
- Credential extraction from cleartext protocols
- File carving from HTTP uploads/downloads
- Reverse shell command reconstruction

**Step 4: Hunt Queries for Lateral Movement**

Proactive hunt for lateral movement indicators:

```
# Internal to internal connections on management ports
event.dataset:zeek.conn AND source.ip:192.168.56.0/24 AND destination.ip:192.168.56.0/24 AND destination.port:(445 OR 135 OR 5985 OR 3389 OR 22)

# PsExec / service-based execution indicators
event.dataset:zeek.smb_files AND zeek.smb.filename:(*PSEXESVC* OR *svc* OR *cmd*)

# WMI lateral movement
event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:IWbemServices

# Pass-the-hash: NTLM authentication from unexpected sources
event.dataset:zeek.ntlm AND source.ip:192.168.56.102

# Scheduled task creation via RPC
event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:ITaskSchedulerService
```

## so-* Command Reference

### so-status

Displays the status of all Security Onion services.

```bash
sudo so-status
```

Output shows running/stopped state for: Suricata, Zeek, Elasticsearch, Logstash, Kibana, Stenographer, Redis, Fleet, OSSEC, and others. Use this after any configuration change to verify services are healthy.

### so-rule-update

Updates and reloads IDS rules (Suricata).

```bash
sudo so-rule-update
```

Pulls rules from configured sources, merges local rules, applies modifications and suppressions, then restarts Suricata. Run after editing `/opt/so/rules/nids/local.rules`.

### so-import

Imports a PCAP file for offline analysis through the full Security Onion pipeline.

```bash
sudo so-import-pcap /path/to/capture.pcap
```

The imported PCAP is processed by Suricata (generating alerts) and Zeek (generating logs), and results appear in the SOC console. Useful for replaying attack captures for analysis and training.

### so-pcap

Retrieves stored packet captures from Stenographer based on filter criteria.

```bash
# Retrieve PCAP for a specific IP pair and date
sudo so-pcap 192.168.56.103 192.168.56.102 2026-03-15

# Retrieve PCAP for a specific port
sudo so-pcap --port 4444 2026-03-15

# Retrieve PCAP for a time window
sudo so-pcap --start "2026-03-15 10:00" --end "2026-03-15 11:00"
```

### so-replay

Replays a PCAP file on the sniffing interface for sensor testing.

```bash
sudo so-replay /path/to/capture.pcap
```

Useful for testing new Suricata rules or Zeek scripts against known attack traffic without generating live attacks.

### Additional Useful Commands

```bash
# Check disk usage for PCAP and Elasticsearch
sudo so-disk-usage

# View Suricata statistics
sudo so-suricata-stats

# Restart all Security Onion services
sudo so-restart

# Check Security Onion configuration
sudo so-config-show

# View Zeek logs in real-time
sudo tail -f /opt/so/log/zeek/current/conn.log
```

## Integration with OSSEC

### Overview

OSSEC (or its fork Wazuh, which Security Onion uses) provides host-based intrusion detection. Agents installed on the Ubuntu and Windows targets forward alerts to the Security Onion OSSEC manager, which then indexes them in Elasticsearch.

### Installing OSSEC Agents

**On Ubuntu target (192.168.56.102):**

```bash
# Add the Wazuh repository and install the agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install wazuh-agent

# Configure the agent to point to Security Onion
sed -i 's/MANAGER_IP/192.168.56.110/' /var/ossec/etc/ossec.conf

# Start the agent
systemctl start wazuh-agent
```

**On Windows target (192.168.56.101):**

Download and install the Wazuh agent MSI, specifying the manager IP as 192.168.56.110 during installation. The agent monitors Windows Event Logs, Sysmon, file integrity, and registry changes.

### Forwarding OSSEC Alerts into Security Onion ELK Stack

Security Onion's Standalone deployment includes an OSSEC/Wazuh manager. Alerts from agents are automatically written to `/var/ossec/logs/alerts/alerts.json` and ingested by Logstash into Elasticsearch under the `*:so-ossec-*` index pattern.

**Key OSSEC rules for detecting lab attacks:**

| Rule ID | Description | Attack Phase |
|---|---|---|
| 5710-5712 | SSH authentication failure/success | Credential attacks |
| 5901 | PAM: user login session opened | Initial access |
| 550 | File integrity change | Persistence, privilege escalation |
| 591 | File addition to the system | Persistence (backdoor dropped) |
| 18100-18199 | Windows audit failure | Credential attacks on Windows |
| 92000-92999 | Custom rules for Sysmon | Post-exploitation |

**Custom OSSEC rules for lab-specific detection:**

Add to `/var/ossec/etc/rules/local_rules.xml` on the Security Onion manager:

```xml
<group name="local,pentest_lab">
  <!-- Detect new cron job creation (persistence) -->
  <rule id="100001" level="10">
    <if_sid>550</if_sid>
    <match>/etc/crontab|/var/spool/cron</match>
    <description>Crontab modified - possible persistence mechanism</description>
  </rule>

  <!-- Detect authorized_keys modification -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>.ssh/authorized_keys</match>
    <description>SSH authorized_keys modified - possible persistence</description>
  </rule>

  <!-- Detect new service creation on Windows -->
  <rule id="100003" level="10">
    <if_sid>18100</if_sid>
    <match>Service Control Manager</match>
    <description>New Windows service created - possible persistence</description>
  </rule>

  <!-- Detect /etc/passwd modification -->
  <rule id="100004" level="14">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow</match>
    <description>Critical system file modified - possible privilege escalation</description>
  </rule>
</group>
```

After adding rules, restart the OSSEC manager:

```bash
sudo so-ossec-restart
```

OSSEC alerts then appear in Kibana under the `*:so-ossec-*` index and can be correlated with Suricata and Zeek data in the SOC console for a complete view of each attack phase.
