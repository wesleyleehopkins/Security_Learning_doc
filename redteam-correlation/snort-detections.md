# Snort/Suricata Detection Rules — Red Team Correlation

## Overview

This file provides Snort/Suricata IDS rules mapped to each phase of the pentest lab attack chain conducted against the 192.168.56.0/24 lab network. Each rule is designed to detect specific techniques used during the engagement, enabling blue team defenders to build detection coverage that mirrors real adversary tradecraft.

**Lab Network Layout:**

| Host | IP Address | Role |
|------|-----------|------|
| Kali Linux | 192.168.56.103 | Attacker |
| Ubuntu Server | 192.168.56.102 | Target |
| Windows Host | 192.168.56.101 | Target |

All rules use SIDs starting at 1000001 (local rule range) and revision 1. Variables `$HOME_NET` and `$EXTERNAL_NET` should be configured in `snort.conf` to reflect the lab network.

---

## Phase 2: Active Scanning

### Nmap SYN Scan Detection

High-rate SYN packets with no follow-through indicate a SYN scan (`nmap -sS`). The threshold triggers after 30 SYN packets in 10 seconds from a single source.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"SCAN Nmap SYN scan detected"; \
    flags:S,12; \
    flow:stateless; \
    threshold:type threshold, track by_src, count 30, seconds 10; \
    classtype:attempted-recon; \
    sid:1000001; rev:1; )
```

### Nmap Service Version Detection

Nmap service probes send specific payloads during `-sV` scanning. This catches the common NULL probe response pattern and the nmap probe marker.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"SCAN Nmap service version detection probe"; \
    flow:to_server,established; \
    content:"SF:"; \
    content:"Nmap"; \
    classtype:attempted-recon; \
    sid:1000002; rev:1; )
```

### Nmap UDP Scan

UDP scans produce a burst of zero-length or minimal-payload UDP packets across many ports.

```
alert udp $EXTERNAL_NET any -> $HOME_NET any ( \
    msg:"SCAN Nmap UDP scan detected"; \
    dsize:0; \
    threshold:type threshold, track by_src, count 25, seconds 10; \
    classtype:attempted-recon; \
    sid:1000003; rev:1; )
```

### Nikto Web Vulnerability Scanner

Nikto identifies itself in its User-Agent string by default.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"SCAN Nikto web vulnerability scanner detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"Nikto"; http_header; \
    classtype:web-application-attack; \
    sid:1000004; rev:1; )
```

### Gobuster / Dirb Directory Brute Force

Rapid sequential GET requests to non-existent paths produce a flood of 404 responses. This rule detects high-rate 404s returning to a single host.

```
alert tcp $HOME_NET $HTTP_PORTS -> $EXTERNAL_NET any ( \
    msg:"SCAN Directory brute force detected - excessive 404 responses"; \
    flow:to_client,established; \
    content:"HTTP/1."; content:"404"; within:15; \
    threshold:type threshold, track by_dst, count 50, seconds 30; \
    classtype:web-application-attack; \
    sid:1000005; rev:1; )
```

### Gobuster User-Agent Detection

Gobuster includes its name in the default User-Agent header.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"SCAN Gobuster directory brute force tool detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"gobuster"; nocase; http_header; \
    classtype:web-application-attack; \
    sid:1000006; rev:1; )
```

### Enum4linux SMB Enumeration

Enum4linux queries for shares, users, and policies over SMB/RPC. This catches the rapid sequence of RPC enumeration calls.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ( \
    msg:"SCAN Enum4linux SMB enumeration detected"; \
    flow:to_server,established; \
    content:"|ff|SMB"; offset:4; depth:4; \
    content:"|25 00|"; distance:0; \
    threshold:type threshold, track by_src, count 15, seconds 30; \
    classtype:attempted-recon; \
    sid:1000007; rev:1; )
```

### Nessus Vulnerability Scanner

Nessus uses a recognizable User-Agent string during authenticated and unauthenticated scans.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"SCAN Nessus vulnerability scanner detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"Nessus"; nocase; http_header; \
    classtype:attempted-recon; \
    sid:1000008; rev:1; )
```

---

## Phase 3: Web Exploitation

### SQL Injection — UNION SELECT

The UNION SELECT keyword combination is a hallmark of SQL injection attempts used to extract data from adjacent columns.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP SQL injection UNION SELECT attempt"; \
    flow:to_server,established; \
    content:"UNION"; nocase; http_uri; \
    content:"SELECT"; nocase; distance:0; http_uri; \
    classtype:web-application-attack; \
    sid:1000009; rev:1; )
```

### SQL Injection — OR 1=1 Bypass

Classic authentication bypass payload injected into login forms or URI parameters.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP SQL injection OR 1=1 authentication bypass"; \
    flow:to_server,established; \
    pcre:"/(\%27|')\s*(OR|or)\s+\d+\s*(\%3D|=)\s*\d+/i"; \
    classtype:web-application-attack; \
    sid:1000010; rev:1; )
```

### SQL Injection — sqlmap User-Agent

Sqlmap identifies itself in the User-Agent header unless the operator overrides it.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP sqlmap automated SQL injection tool detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"sqlmap"; http_header; \
    classtype:web-application-attack; \
    sid:1000011; rev:1; )
```

### Cross-Site Scripting (XSS) Payload

Detects `<script>` tags injected through URI parameters or POST bodies.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP XSS script tag injection attempt"; \
    flow:to_server,established; \
    content:"<script"; nocase; \
    pcre:"/<script[^>]*>/i"; \
    classtype:web-application-attack; \
    sid:1000012; rev:1; )
```

### Command Injection — Semicolon with whoami

Detects OS command injection attempts chaining commands with a semicolon followed by common recon commands.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP OS command injection - semicolon whoami"; \
    flow:to_server,established; \
    content:";"; \
    content:"whoami"; distance:0; nocase; \
    classtype:web-application-attack; \
    sid:1000013; rev:1; )
```

### Command Injection — Pipe with cat

Pipe-based injection to read local files via `cat`.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP OS command injection - pipe cat"; \
    flow:to_server,established; \
    content:"|"; \
    content:"cat"; distance:0; nocase; \
    content:"/etc/"; distance:0; \
    classtype:web-application-attack; \
    sid:1000014; rev:1; )
```

### Malicious File Upload — PHP Extension

Detects HTTP POST requests uploading files with a `.php` extension, which may indicate webshell deployment.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP Malicious PHP file upload attempt"; \
    flow:to_server,established; \
    content:"POST"; http_method; \
    content:"Content-Disposition|3a|"; \
    content:"filename="; distance:0; \
    content:".php"; distance:0; \
    classtype:web-application-attack; \
    sid:1000015; rev:1; )
```

### Local File Inclusion (LFI)

Path traversal sequences in the URI indicate an attempt to read files outside the web root.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP Local file inclusion path traversal attempt"; \
    flow:to_server,established; \
    content:".."; http_uri; \
    content:"/"; within:1; http_uri; \
    content:".."; distance:0; http_uri; \
    pcre:"/\.\.\//"; \
    classtype:web-application-attack; \
    sid:1000016; rev:1; )
```

### Remote File Inclusion (RFI)

Detects a parameter value referencing an external URL, a strong indicator of remote file inclusion.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"WEB-APP Remote file inclusion - external URL in parameter"; \
    flow:to_server,established; \
    content:"=http"; nocase; http_uri; \
    pcre:"/(\?|&)\w+=https?:\/\//i"; \
    classtype:web-application-attack; \
    sid:1000017; rev:1; )
```

---

## Phase 4: Password Attacks

### SSH Brute Force

Multiple SSH connection attempts from a single source in a short window indicate credential stuffing or brute force.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( \
    msg:"BRUTE-FORCE SSH login brute force detected"; \
    flow:to_server,established; \
    content:"SSH-"; \
    threshold:type threshold, track by_src, count 10, seconds 60; \
    classtype:attempted-admin; \
    sid:1000018; rev:1; )
```

### SMB Brute Force

Repeated SMB session setup requests indicate password spraying or brute force against Windows shares.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ( \
    msg:"BRUTE-FORCE SMB login brute force detected"; \
    flow:to_server,established; \
    content:"|ff|SMB"; offset:4; depth:4; \
    content:"|73|"; distance:0; \
    threshold:type threshold, track by_src, count 10, seconds 60; \
    classtype:attempted-admin; \
    sid:1000019; rev:1; )
```

### RDP Brute Force

Rapid RDP connection initiation requests targeting port 3389.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 ( \
    msg:"BRUTE-FORCE RDP login brute force detected"; \
    flow:to_server; \
    content:"|03 00|"; depth:2; \
    threshold:type threshold, track by_src, count 8, seconds 60; \
    classtype:attempted-admin; \
    sid:1000020; rev:1; )
```

### HTTP Login Brute Force

Excessive POST requests to common login endpoints suggest form-based brute force.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"BRUTE-FORCE HTTP login brute force detected"; \
    flow:to_server,established; \
    content:"POST"; http_method; \
    pcre:"/\/(login|auth|signin|wp-login|admin)/i"; http_uri; \
    threshold:type threshold, track by_src, count 15, seconds 30; \
    classtype:attempted-admin; \
    sid:1000021; rev:1; )
```

### Hydra User-Agent Detection

THC-Hydra includes a recognizable User-Agent string by default during HTTP brute force attacks.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"BRUTE-FORCE Hydra HTTP brute force tool detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"Hydra"; nocase; http_header; \
    classtype:attempted-admin; \
    sid:1000022; rev:1; )
```

---

## Phase 5: Metasploit

### Meterpreter Reverse TCP Handshake

The Meterpreter reverse TCP stager sends a 4-byte length prefix followed by a stage payload. This rule catches the initial callback pattern on common handler ports.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 ( \
    msg:"EXPLOIT Meterpreter reverse TCP handshake to port 4444"; \
    flow:to_server,established; \
    dsize:4; \
    content:"|00|"; depth:1; \
    classtype:trojan-activity; \
    sid:1000023; rev:1; )
```

### Meterpreter HTTP Stager

Meterpreter's HTTP transport requests a random 4-character URI checksum that resolves to a specific value (92 for Windows). The URI pattern and lack of standard browser headers are distinctive.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ( \
    msg:"EXPLOIT Meterpreter HTTP stager URI checksum pattern"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    pcre:"/^\/[A-Za-z0-9_-]{4,5}$/"; http_uri; \
    content:!"Referer"; http_header; \
    content:!"Accept-Language"; http_header; \
    classtype:trojan-activity; \
    sid:1000024; rev:1; )
```

### Meterpreter HTTPS Stager

Detects outbound HTTPS connections on port 443 to the attacker IP with the Meterpreter TLS fingerprint (self-signed certificates with specific issuer patterns).

```
alert tcp $HOME_NET any -> 192.168.56.103 443 ( \
    msg:"EXPLOIT Meterpreter HTTPS stager callback to attacker"; \
    flow:to_server,established; \
    content:"|16 03|"; depth:2; \
    threshold:type limit, track by_src, count 1, seconds 300; \
    classtype:trojan-activity; \
    sid:1000025; rev:1; )
```

### Msfvenom PE Payload Download over HTTP

Detects Windows PE executables (MZ header) being delivered over HTTP from the attacker IP.

```
alert tcp 192.168.56.103 $HTTP_PORTS -> $HOME_NET any ( \
    msg:"EXPLOIT Msfvenom PE payload download from attacker"; \
    flow:to_client,established; \
    content:"MZ"; depth:2; \
    file_data; content:"This program"; within:200; \
    classtype:trojan-activity; \
    sid:1000026; rev:1; )
```

### Msfvenom ELF Payload Download over HTTP

Detects Linux ELF binaries being served over HTTP from the attacker host.

```
alert tcp 192.168.56.103 $HTTP_PORTS -> $HOME_NET any ( \
    msg:"EXPLOIT Msfvenom ELF payload download from attacker"; \
    flow:to_client,established; \
    content:"|7f|ELF"; depth:4; \
    classtype:trojan-activity; \
    sid:1000027; rev:1; )
```

### EternalBlue / MS17-010 SMB Exploit

EternalBlue sends a specific SMBv1 transaction request targeting the vulnerability in the Windows SMB server.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 ( \
    msg:"EXPLOIT EternalBlue MS17-010 SMB exploit attempt"; \
    flow:to_server,established; \
    content:"|ff|SMB|33 00 00 00 00 18|"; depth:12; \
    content:"|68 00|"; distance:0; \
    content:"|00 00 00 00 00 00 00 4a 00|"; distance:0; \
    classtype:attempted-admin; \
    sid:1000028; rev:1; )
```

### Metasploit Auxiliary Scanner User-Agent

MSF auxiliary HTTP modules use a default Ruby User-Agent string.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS ( \
    msg:"SCAN Metasploit auxiliary scanner User-Agent detected"; \
    flow:to_server,established; \
    content:"User-Agent|3a|"; http_header; \
    content:"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"; http_header; \
    classtype:trojan-activity; \
    sid:1000029; rev:1; )
```

---

## Phase 8: Post-Exploitation

### Reverse Shell — Bash /dev/tcp Callback

Detects the classic bash reverse shell one-liner where the target opens a TCP socket back to the attacker.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"BACKDOOR Bash reverse shell via /dev/tcp detected"; \
    flow:to_server,established; \
    content:"/dev/tcp/"; \
    classtype:trojan-activity; \
    sid:1000030; rev:1; )
```

### Netcat File Transfer

Netcat transfers typically involve a raw TCP connection on a non-standard port with binary payload. This rule watches for outbound connections to the attacker on common staging ports.

```
alert tcp $HOME_NET any -> 192.168.56.103 4444:4450 ( \
    msg:"BACKDOOR Netcat file transfer to attacker detected"; \
    flow:to_server,established; \
    dsize:>512; \
    threshold:type limit, track by_src, count 1, seconds 60; \
    classtype:trojan-activity; \
    sid:1000031; rev:1; )
```

### HTTP POST Data Exfiltration

Large outbound POST requests to the attacker host indicate data exfiltration over HTTP.

```
alert tcp $HOME_NET any -> 192.168.56.103 $HTTP_PORTS ( \
    msg:"EXFIL HTTP POST data exfiltration to attacker"; \
    flow:to_server,established; \
    content:"POST"; http_method; \
    dsize:>5000; \
    classtype:policy-violation; \
    sid:1000032; rev:1; )
```

### DNS Tunneling — Long Subdomain Labels

DNS tunneling encodes data in subdomain labels. Labels exceeding 50 characters are anomalous and suggest tunneling tools such as dnscat2 or iodine.

```
alert udp $HOME_NET any -> any 53 ( \
    msg:"EXFIL DNS tunneling detected - abnormally long subdomain label"; \
    content:"|00 01 00 00|"; \
    pcre:"/[\x32-\x3f][a-zA-Z0-9+\/=-]{50,}/"; \
    classtype:policy-violation; \
    sid:1000033; rev:1; )
```

### Chisel WebSocket Tunnel

Chisel establishes a WebSocket tunnel using an HTTP Upgrade request. This detects the characteristic Chisel handshake.

```
alert tcp $HOME_NET any -> $EXTERNAL_NET any ( \
    msg:"TUNNEL Chisel WebSocket tunnel handshake detected"; \
    flow:to_server,established; \
    content:"Upgrade|3a| websocket"; nocase; http_header; \
    content:"/chisel"; http_uri; \
    classtype:policy-violation; \
    sid:1000034; rev:1; )
```

### SMB Exfiltration to Attacker Share

Detects outbound SMB tree connect requests from a target to the attacker host, indicating data exfiltration to an attacker-controlled share.

```
alert tcp $HOME_NET any -> 192.168.56.103 445 ( \
    msg:"EXFIL SMB tree connect to attacker share"; \
    flow:to_server,established; \
    content:"|ff|SMB"; offset:4; depth:4; \
    content:"|75|"; distance:0; \
    classtype:policy-violation; \
    sid:1000035; rev:1; )
```

### Tool Staging — wget Download from Attacker

Targets pulling tools from the attacker's HTTP server using wget.

```
alert tcp $HOME_NET any -> 192.168.56.103 any ( \
    msg:"STAGING wget download from attacker host"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    content:"User-Agent|3a|"; http_header; \
    content:"Wget"; http_header; \
    classtype:trojan-activity; \
    sid:1000036; rev:1; )
```

### Tool Staging — curl Download from Attacker

Targets pulling tools from the attacker using curl.

```
alert tcp $HOME_NET any -> 192.168.56.103 any ( \
    msg:"STAGING curl download from attacker host"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    content:"User-Agent|3a|"; http_header; \
    content:"curl/"; http_header; \
    classtype:trojan-activity; \
    sid:1000037; rev:1; )
```

### Tool Staging — certutil Download from Attacker

Windows certutil is commonly abused to download payloads from remote servers.

```
alert tcp $HOME_NET any -> 192.168.56.103 any ( \
    msg:"STAGING certutil download from attacker host"; \
    flow:to_server,established; \
    content:"GET"; http_method; \
    content:"User-Agent|3a|"; http_header; \
    content:"CertUtil"; http_header; \
    classtype:trojan-activity; \
    sid:1000038; rev:1; )
```

### Python HTTP Server on Non-Standard Port

Attacker-hosted Python SimpleHTTPServer or http.server instances typically run on ports 8000, 8080, or 8888 and include a distinctive Server header.

```
alert tcp 192.168.56.103 8000:8888 -> $HOME_NET any ( \
    msg:"STAGING Python HTTP server on non-standard port from attacker"; \
    flow:to_client,established; \
    content:"Server|3a|"; http_header; \
    content:"SimpleHTTP"; http_header; \
    classtype:policy-violation; \
    sid:1000039; rev:1; )
```

---

## Rule Summary

| SID | Phase | Detection |
|-----|-------|-----------|
| 1000001 | 2 | Nmap SYN scan |
| 1000002 | 2 | Nmap service version detection |
| 1000003 | 2 | Nmap UDP scan |
| 1000004 | 2 | Nikto scanner |
| 1000005 | 2 | Directory brute force (404 flood) |
| 1000006 | 2 | Gobuster User-Agent |
| 1000007 | 2 | Enum4linux SMB enumeration |
| 1000008 | 2 | Nessus scanner |
| 1000009 | 3 | SQL injection UNION SELECT |
| 1000010 | 3 | SQL injection OR 1=1 |
| 1000011 | 3 | sqlmap User-Agent |
| 1000012 | 3 | XSS script tag injection |
| 1000013 | 3 | Command injection (semicolon + whoami) |
| 1000014 | 3 | Command injection (pipe + cat) |
| 1000015 | 3 | Malicious PHP file upload |
| 1000016 | 3 | Local file inclusion (path traversal) |
| 1000017 | 3 | Remote file inclusion (external URL) |
| 1000018 | 4 | SSH brute force |
| 1000019 | 4 | SMB brute force |
| 1000020 | 4 | RDP brute force |
| 1000021 | 4 | HTTP login brute force |
| 1000022 | 4 | Hydra User-Agent |
| 1000023 | 5 | Meterpreter reverse TCP |
| 1000024 | 5 | Meterpreter HTTP stager |
| 1000025 | 5 | Meterpreter HTTPS stager |
| 1000026 | 5 | Msfvenom PE payload download |
| 1000027 | 5 | Msfvenom ELF payload download |
| 1000028 | 5 | EternalBlue MS17-010 |
| 1000029 | 5 | Metasploit auxiliary scanner UA |
| 1000030 | 8 | Bash reverse shell (/dev/tcp) |
| 1000031 | 8 | Netcat file transfer |
| 1000032 | 8 | HTTP POST exfiltration |
| 1000033 | 8 | DNS tunneling (long labels) |
| 1000034 | 8 | Chisel WebSocket tunnel |
| 1000035 | 8 | SMB exfiltration to attacker |
| 1000036 | 8 | wget staging from attacker |
| 1000037 | 8 | curl staging from attacker |
| 1000038 | 8 | certutil staging from attacker |
| 1000039 | 8 | Python HTTP server from attacker |

---

## Deployment Notes

### Adding Rules to Snort

1. **Copy rules to the local rules file:**

   Append all rules above to your local rules file, typically located at:
   ```
   /etc/snort/rules/local.rules
   ```
   Or for Suricata:
   ```
   /etc/suricata/rules/local.rules
   ```

2. **Ensure local.rules is included in the configuration:**

   In `snort.conf`, verify this line is present and uncommented:
   ```
   include $RULE_PATH/local.rules
   ```
   In `suricata.yaml`, confirm `local.rules` appears under `rule-files:`.

3. **Set network variables in snort.conf:**
   ```
   ipvar HOME_NET 192.168.56.0/24
   ipvar EXTERNAL_NET any
   portvar HTTP_PORTS [80,443,8080,8443,8000,8888]
   ```

### Testing the Configuration

Before restarting the sensor, validate the rules parse correctly:

```bash
# Snort validation
sudo snort -T -c /etc/snort/snort.conf

# Suricata validation
sudo suricata -T -c /etc/suricata/suricata.yaml
```

Fix any syntax errors reported before proceeding. Common issues include missing semicolons, mismatched quotes, and invalid content modifiers.

### Enabling in Security Onion

For Security Onion deployments:

1. Place custom rules in `/opt/so/rules/nids/local.rules`.
2. Run `sudo so-rule-update` to push the rules to all sensors.
3. Verify rules are loaded: `sudo so-nsm-status` and check the Suricata logs at `/nsm/sensor-*/suricata/suricata.log`.
4. Monitor alerts in Kibana under the **Alerts** dashboard or query via `so-elastic-query`.

### Tuning Recommendations

- **Threshold values** (count and seconds) should be adjusted based on baseline traffic. Start with the values provided and lower thresholds if false negatives occur.
- **Attacker-specific rules** (those referencing 192.168.56.103 directly) should be generalized with `$EXTERNAL_NET` if deploying outside the lab.
- **Suppress false positives** using the `suppress` directive in `threshold.conf` rather than disabling rules entirely.
- Rules using `http_header`, `http_uri`, and `http_method` content modifiers require HTTP inspection preprocessors to be enabled (they are by default in both Snort and Suricata).
