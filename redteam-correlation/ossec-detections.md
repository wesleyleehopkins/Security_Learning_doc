# OSSEC Detection Rules -- Red Team Correlation

## Overview

This document provides OSSEC HIDS detection rules mapped to a penetration test attack chain executed against a lab network. Each rule correlates to a specific offensive phase, enabling Blue Team operators to validate detection coverage, tune alert thresholds, and build incident timelines from OSSEC alerts.

**Lab Network: 192.168.56.0/24**

| Host | Role | IP Address |
|------|------|------------|
| Kali Linux | Attacker | 192.168.56.103 |
| Ubuntu Server | Target (Linux) | 192.168.56.102 |
| Windows 10 | Target (Windows) | 192.168.56.101 |

**OSSEC Server:** Runs on a dedicated management host or co-located on the Ubuntu target for lab purposes.

**Rule ID Range:** 100100 -- 100199 (local custom rules to avoid conflicts with default OSSEC rule sets).

---

## Agent Configuration

The following `ossec.conf` snippets configure the OSSEC agent on the Ubuntu target (192.168.56.102) for file integrity monitoring, log collection, and rootcheck.

### Syscheck (File Integrity Monitoring)

```xml
<syscheck>
  <frequency>300</frequency>
  <alert_new_files>yes</alert_new_files>
  <auto_ignore>no</auto_ignore>

  <!-- Critical system configuration files -->
  <directories check_all="yes" realtime="yes">/etc/passwd,/etc/shadow,/etc/sudoers,/etc/crontab,/etc/group</directories>

  <!-- Systemd service files (persistence) -->
  <directories check_all="yes" realtime="yes">/etc/systemd/system</directories>

  <!-- SSH authorized_keys for all users -->
  <directories check_all="yes" realtime="yes">/home/*/.ssh</directories>
  <directories check_all="yes" realtime="yes">/root/.ssh</directories>

  <!-- Shell profiles (login persistence) -->
  <directories check_all="yes" realtime="yes">/home/*/.bashrc,/home/*/.profile</directories>

  <!-- Temp directories (tool drops, SUID backdoors, exploits) -->
  <directories check_all="yes" realtime="yes">/tmp</directories>
  <directories check_all="yes" realtime="yes">/dev/shm</directories>

  <!-- Custom scripts directory (cron targets) -->
  <directories check_all="yes" realtime="yes">/opt/scripts</directories>

  <!-- Web root (web shells) -->
  <directories check_all="yes" realtime="yes">/var/www</directories>

  <!-- Cron directories -->
  <directories check_all="yes" realtime="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/var/spool/cron/crontabs</directories>

  <!-- Ignore noise -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/resolv.conf</ignore>
  <ignore>/tmp/.ICE-unix</ignore>
</syscheck>
```

### Log Monitoring (localfile)

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/access.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/apache2/error.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/cron.log</location>
</localfile>

<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/kern.log</location>
</localfile>
```

### Rootcheck

```xml
<rootcheck>
  <disabled>no</disabled>
  <frequency>3600</frequency>
  <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
  <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
  <system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
  <check_unixaudit>yes</check_unixaudit>
  <check_files>yes</check_files>
  <check_trojans>yes</check_trojans>
  <check_dev>yes</check_dev>
  <check_ports>yes</check_ports>
  <check_if>yes</check_if>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
</rootcheck>
```

---

## File Integrity Monitoring (FIM)

The syscheck configuration above targets directories that directly map to the attack chain. The rationale for each monitored path:

| Directory | Attack Phase | Rationale |
|-----------|-------------|-----------|
| `/etc/passwd, /etc/shadow, /etc/group` | Privilege Escalation, Post-Exploitation | New user creation, password changes, group membership manipulation |
| `/etc/sudoers` | Privilege Escalation | Sudoers modification to grant NOPASSWD access |
| `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/crontabs/` | Persistence | Cron-based reverse shells and scheduled task backdoors |
| `/etc/systemd/system/` | Post-Exploitation | Systemd service persistence units |
| `/home/*/.ssh/` | Post-Exploitation | SSH authorized_keys injection for persistent access |
| `/home/*/.bashrc` | Post-Exploitation | Login-triggered reverse shell via .bashrc |
| `/tmp/` | Privilege Escalation | Tool drops (LinPEAS, exploits), SUID binaries, LD_PRELOAD libraries |
| `/dev/shm/` | Privilege Escalation | In-memory tool staging (tmpfs, no disk write) |
| `/opt/scripts/` | Privilege Escalation | Cron job script modification (writable script called by root cron) |
| `/var/www/` | Web Exploitation | Web shell uploads via vulnerable upload forms |

FIM generates OSSEC rule IDs 550--554 by default. The custom rules below add context when FIM events occur in attack-relevant paths.

---

## Custom Detection Rules

All rules below go in `/var/ossec/rules/local_rules.xml`. They use the reserved local range starting at 100100.

---

### Phase 3: Web Exploitation

#### Rule 100100 -- SQL Injection Attempt in Apache Logs

```xml
<rule id="100100" level="12">
  <if_sid>31100</if_sid>
  <url>UNION|SELECT|INSERT|DROP|UPDATE|DELETE|CONCAT|LOAD_FILE|INTO OUTFILE|INTO DUMPFILE|information_schema|BENCHMARK|SLEEP\(</url>
  <description>SQL injection attempt detected in web request.</description>
  <group>web,attack,sqli,phase3</group>
</rule>
```

#### Rule 100101 -- Command Injection in Web Request

```xml
<rule id="100101" level="14">
  <if_sid>31100</if_sid>
  <url>;|%3B|\||%7C|`|%60|$\(|%24%28</url>
  <regex>cat /etc|id;|whoami|uname|/bin/bash|/bin/sh|nc -|ncat |python -c|perl -e|curl |wget </regex>
  <description>OS command injection attempt detected in web request.</description>
  <group>web,attack,command_injection,phase3</group>
</rule>
```

#### Rule 100102 -- Web Shell Upload Detected (New PHP in Uploads)

```xml
<rule id="100102" level="14">
  <if_sid>554</if_sid>
  <match>var/www/html/uploads</match>
  <regex>\.php$|\.php\d$|\.phtml$|\.phar$</regex>
  <description>New PHP file created in web uploads directory -- possible web shell.</description>
  <group>web,attack,webshell,syscheck,phase3</group>
</rule>
```

#### Rule 100103 -- Web Shell Keyword in Apache Logs

```xml
<rule id="100103" level="13">
  <if_sid>31100</if_sid>
  <url>cmd=|exec=|shell=|command=|c99|r57|b374k|weevely|wso</url>
  <description>Known web shell parameter or signature in web request.</description>
  <group>web,attack,webshell,phase3</group>
</rule>
```

---

### Phase 4: Password Attacks

#### Rule 100110 -- SSH Brute Force (10 Failures in 120s)

```xml
<rule id="100110" level="10" frequency="10" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <description>SSH brute force attack detected (10 failures in 2 minutes).</description>
  <group>authentication_failures,ssh,brute_force,phase4</group>
</rule>
```

#### Rule 100111 -- SSH Brute Force Escalation (20 Failures in 120s)

```xml
<rule id="100111" level="13" frequency="20" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <description>Aggressive SSH brute force attack -- 20 failures in 2 minutes.</description>
  <group>authentication_failures,ssh,brute_force,phase4</group>
</rule>
```

#### Rule 100112 -- Successful SSH Login After Brute Force

```xml
<rule id="100112" level="14">
  <if_sid>5715</if_sid>
  <if_matched_sid>100110</if_matched_sid>
  <same_source_ip />
  <description>Successful SSH login following brute force attempt -- likely credential compromise.</description>
  <group>authentication_success,ssh,brute_force,phase4</group>
</rule>
```

#### Rule 100113 -- SSH Login from Attacker IP

```xml
<rule id="100113" level="10">
  <if_sid>5715</if_sid>
  <srcip>192.168.56.103</srcip>
  <description>SSH login from known attacker IP 192.168.56.103.</description>
  <group>authentication_success,ssh,threat_intel,phase4</group>
</rule>
```

---

### Phase 6: Linux Privilege Escalation

#### Rule 100120 -- SUID File Created in /tmp

```xml
<rule id="100120" level="14">
  <if_sid>554</if_sid>
  <match>/tmp/</match>
  <description>New file created in /tmp -- check for SUID bit (possible privilege escalation backdoor).</description>
  <group>syscheck,privilege_escalation,suid,phase6</group>
</rule>
```

#### Rule 100121 -- Sudo Shell Escape via GTFOBins Techniques

```xml
<rule id="100121" level="14">
  <if_sid>5401</if_sid>
  <regex>sudo\s+(vim|vi|nano|find|awk|env|less|more|man|nmap|python|perl|ruby|lua|git|zip|tar|ftp|socat)\s</regex>
  <description>Sudo invocation of binary with known shell escape (GTFOBins technique).</description>
  <group>privilege_escalation,sudo,gtfobins,phase6</group>
</rule>
```

#### Rule 100122 -- Sudo Shell Escape Execution Patterns

```xml
<rule id="100122" level="14">
  <if_sid>5402</if_sid>
  <match>:!/bin/sh|:!/bin/bash|:set shell=|!/bin/sh|-exec /bin/sh|--interactive|SHELL=/bin/bash</match>
  <description>Shell escape pattern detected in sudo session.</description>
  <group>privilege_escalation,sudo,shell_escape,phase6</group>
</rule>
```

#### Rule 100123 -- Cron Script Modification in /opt/scripts

```xml
<rule id="100123" level="13">
  <if_sid>550</if_sid>
  <match>/opt/scripts/</match>
  <description>File modified in /opt/scripts -- possible cron job hijack for privilege escalation.</description>
  <group>syscheck,privilege_escalation,cron_hijack,phase6</group>
</rule>
```

#### Rule 100124 -- LD_PRELOAD Shared Library in /tmp

```xml
<rule id="100124" level="14">
  <if_sid>554</if_sid>
  <match>/tmp/</match>
  <regex>\.so$|\.so\.\d</regex>
  <description>Shared library (.so) created in /tmp -- possible LD_PRELOAD privilege escalation.</description>
  <group>syscheck,privilege_escalation,ld_preload,phase6</group>
</rule>
```

#### Rule 100125 -- chmod +x on File in /tmp

```xml
<rule id="100125" level="12">
  <if_sid>550</if_sid>
  <match>/tmp/</match>
  <description>File permissions changed in /tmp -- possible tool drop made executable.</description>
  <group>syscheck,privilege_escalation,tool_drop,phase6</group>
</rule>
```

#### Rule 100126 -- LinPEAS / LinEnum Execution

```xml
<rule id="100126" level="13">
  <decoded_as>syslog</decoded_as>
  <match>linpeas|linenum|linux-exploit-suggester|les.sh|unix-privesc-check|pspy</match>
  <description>Privilege escalation enumeration tool executed (LinPEAS/LinEnum/pspy).</description>
  <group>privilege_escalation,enumeration,phase6</group>
</rule>
```

#### Rule 100127 -- Kernel Exploit Compilation in /tmp

```xml
<rule id="100127" level="14">
  <decoded_as>syslog</decoded_as>
  <regex>gcc\s.*-o\s+/tmp/|gcc\s+/tmp/.*\.c|cc\s.*-o\s+/tmp/</regex>
  <description>GCC compilation targeting /tmp -- probable kernel exploit compilation.</description>
  <group>privilege_escalation,kernel_exploit,phase6</group>
</rule>
```

#### Rule 100128 -- SUID/SGID Bit Set via chmod

```xml
<rule id="100128" level="14">
  <decoded_as>syslog</decoded_as>
  <regex>chmod\s+[u+]*[24][0-7]{3}\s|chmod\s+u\+s\s|chmod\s+g\+s\s</regex>
  <description>SUID or SGID bit set on a file -- privilege escalation indicator.</description>
  <group>privilege_escalation,suid,phase6</group>
</rule>
```

---

### Phase 8: Post-Exploitation

#### Rule 100140 -- SSH Authorized Keys Modification

```xml
<rule id="100140" level="14">
  <if_sid>550</if_sid>
  <match>authorized_keys</match>
  <description>SSH authorized_keys file modified -- possible key injection for persistent access.</description>
  <group>syscheck,persistence,ssh_key_injection,phase8</group>
</rule>
```

#### Rule 100141 -- New User Account Created

```xml
<rule id="100141" level="13">
  <if_sid>5901</if_sid>
  <description>New user account created -- verify this was authorized.</description>
  <group>account_creation,persistence,phase8</group>
</rule>
```

#### Rule 100142 -- New User Created via useradd/adduser Command

```xml
<rule id="100142" level="13">
  <decoded_as>syslog</decoded_as>
  <match>useradd|adduser</match>
  <regex>new user:|name=</regex>
  <description>User creation command executed (useradd/adduser).</description>
  <group>account_creation,persistence,phase8</group>
</rule>
```

#### Rule 100143 -- .bashrc Modified with Reverse Shell Indicator

```xml
<rule id="100143" level="15">
  <if_sid>550</if_sid>
  <match>.bashrc</match>
  <description>.bashrc file modified -- check for reverse shell persistence.</description>
  <group>syscheck,persistence,bashrc,phase8</group>
</rule>
```

#### Rule 100144 -- Reverse Shell Pattern in Logs (/dev/tcp)

```xml
<rule id="100144" level="15">
  <decoded_as>syslog</decoded_as>
  <match>/dev/tcp/</match>
  <description>Bash /dev/tcp reverse shell pattern detected in logs.</description>
  <group>persistence,reverse_shell,phase8</group>
</rule>
```

#### Rule 100145 -- New Systemd Service Created

```xml
<rule id="100145" level="13">
  <if_sid>554</if_sid>
  <match>/etc/systemd/system/</match>
  <regex>\.service$</regex>
  <description>New systemd service unit file created -- possible persistence mechanism.</description>
  <group>syscheck,persistence,systemd,phase8</group>
</rule>
```

#### Rule 100146 -- Crontab Modified with Network Callback

```xml
<rule id="100146" level="15">
  <decoded_as>syslog</decoded_as>
  <match>CRON|crontab</match>
  <regex>/dev/tcp|nc -e|ncat|mkfifo|python.*socket|socat</regex>
  <description>Crontab entry contains reverse shell or network callback pattern.</description>
  <group>persistence,cron,reverse_shell,phase8</group>
</rule>
```

#### Rule 100147 -- Outbound Connection to Attacker IP

```xml
<rule id="100147" level="14">
  <decoded_as>syslog</decoded_as>
  <match>192.168.56.103</match>
  <regex>CONNECT|ESTABLISHED|SYN_SENT</regex>
  <description>Outbound network connection to attacker IP 192.168.56.103 detected.</description>
  <group>command_and_control,network,phase8</group>
</rule>
```

#### Rule 100148 -- Crontab File Modified via FIM

```xml
<rule id="100148" level="13">
  <if_sid>550</if_sid>
  <regex>/var/spool/cron/crontabs/|/etc/crontab|/etc/cron\.d/</regex>
  <description>Crontab file modified -- verify for unauthorized scheduled tasks.</description>
  <group>syscheck,persistence,cron,phase8</group>
</rule>
```

---

## Active Response Configuration

Active response rules allow OSSEC to take automated defensive action when specific alerts fire. The configuration below goes in the OSSEC server `ossec.conf`.

### Define the Firewall Drop Command

```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>
```

### Block Attacker IP on SSH Brute Force

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100110,100111</rules_id>
  <timeout>3600</timeout>
  <repeated_offenders>1800,3600,7200</repeated_offenders>
</active-response>
```

This blocks the source IP via iptables for 1 hour on first trigger. Repeated offenders receive escalating bans (30 min, 1 hr, 2 hr on subsequent triggers).

### Block on Command Injection or Web Shell Activity

```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101,100102,100103</rules_id>
  <timeout>86400</timeout>
</active-response>
```

Blocks source IP for 24 hours when command injection or web shell activity is detected.

### Email Alert on Critical Persistence Indicators

```xml
<active-response>
  <command>mail-alert</command>
  <location>server</location>
  <rules_id>100140,100143,100144,100145,100146</rules_id>
</active-response>
```

Sends an email alert to the configured address whenever SSH key injection, .bashrc reverse shells, systemd persistence, or cron-based callbacks are detected.

### Host Isolation on Confirmed Compromise

```xml
<command>
  <name>host-deny</name>
  <executable>host-deny.sh</executable>
  <expect>srcip</expect>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>host-deny</command>
  <location>local</location>
  <rules_id>100112</rules_id>
  <timeout>0</timeout>
</active-response>
```

Permanently adds the attacker IP to `/etc/hosts.deny` when a successful SSH login follows a brute force attack (rule 100112), indicating confirmed credential compromise.

---

## Deployment Notes

### 1. Add Custom Rules

All custom rules go in the local rules file on the OSSEC server:

```
/var/ossec/rules/local_rules.xml
```

Wrap all rules inside the `<group>` element:

```xml
<group name="local,attack,pentest_correlation,">

  <!-- Paste all rules from this document here -->

</group>
```

### 2. Verify Rule Syntax

Before restarting OSSEC, validate the rules:

```bash
/var/ossec/bin/ossec-logtest
```

Paste a sample log line and confirm the expected rule fires. For example, to test SQL injection detection, paste an Apache access log entry containing `UNION SELECT` and verify rule 100100 triggers.

### 3. Restart OSSEC

```bash
/var/ossec/bin/ossec-control restart
```

Or on systemd-managed installations:

```bash
systemctl restart ossec
```

### 4. Verify Agent Connection

Confirm the Ubuntu agent is connected and sending events:

```bash
/var/ossec/bin/agent_control -l
```

The agent for 192.168.56.102 should show status `Active`.

### 5. Test FIM Triggers

Create a test file in a monitored directory and confirm syscheck detects it:

```bash
touch /tmp/test_fim_detection
```

Wait for the syscheck interval (300 seconds as configured) or trigger an immediate scan:

```bash
/var/ossec/bin/agent_control -r -u <agent_id>
```

### 6. Review Alerts

Monitor alerts in real time:

```bash
tail -f /var/ossec/logs/alerts/alerts.log
```

Or query specific rule IDs:

```bash
grep "Rule: 100" /var/ossec/logs/alerts/alerts.log
```

### 7. Rule Tuning

After running the attack chain, review alert volumes:

- **False positives:** Increase the `level` threshold or add `<if_sid>` conditions to narrow scope.
- **Missed detections:** Lower the `level`, adjust `<frequency>` and `<timeframe>` for rate-based rules, or broaden `<match>/<regex>` patterns.
- **Noise reduction:** Use `<if_sid>` to chain rules and reduce standalone firing. Add `<ignore>` entries to syscheck for known-good file changes.

### 8. Rule ID Reference

| Rule ID | Level | Phase | Detection |
|---------|-------|-------|-----------|
| 100100 | 12 | 3 | SQL injection in web logs |
| 100101 | 14 | 3 | OS command injection |
| 100102 | 14 | 3 | Web shell upload (PHP in uploads) |
| 100103 | 13 | 3 | Web shell keyword in request |
| 100110 | 10 | 4 | SSH brute force (10 failures/2min) |
| 100111 | 13 | 4 | SSH brute force escalation (20/2min) |
| 100112 | 14 | 4 | SSH login after brute force |
| 100113 | 10 | 4 | SSH login from attacker IP |
| 100120 | 14 | 6 | New file in /tmp |
| 100121 | 14 | 6 | Sudo GTFOBins shell escape |
| 100122 | 14 | 6 | Shell escape execution pattern |
| 100123 | 13 | 6 | Cron script modified in /opt/scripts |
| 100124 | 14 | 6 | Shared library (.so) in /tmp |
| 100125 | 12 | 6 | chmod in /tmp |
| 100126 | 13 | 6 | LinPEAS/LinEnum execution |
| 100127 | 14 | 6 | Kernel exploit compilation |
| 100128 | 14 | 6 | SUID/SGID bit set |
| 100140 | 14 | 8 | SSH authorized_keys modified |
| 100141 | 13 | 8 | New user account created |
| 100142 | 13 | 8 | useradd/adduser command |
| 100143 | 15 | 8 | .bashrc modified |
| 100144 | 15 | 8 | /dev/tcp reverse shell pattern |
| 100145 | 13 | 8 | New systemd service created |
| 100146 | 15 | 8 | Crontab with network callback |
| 100147 | 14 | 8 | Connection to attacker IP |
| 100148 | 13 | 8 | Crontab file modified (FIM) |
