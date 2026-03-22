# YARA Rules — Red Team Correlation

## Overview

YARA rules for detecting pentest tools, payloads, and persistence artifacts on disk or in memory. Mapped to the lab attack chain targeting Ubuntu (.102) and Windows (.101) from Kali (.103).

---

## Tool Detection Rules

### Rule 1: LinPEAS

```yara
rule linpeas_script {
    meta:
        description = "Detects linpeas.sh privilege escalation enumeration script"
        author = "Red Team Correlation Lab"
        severity = "high"
        reference = "https://github.com/carlospolop/PEASS-ng"
    strings:
        $header = "#!/bin/sh" ascii
        $s1 = "linpeas" ascii nocase
        $s2 = "Linux Privilege Escalation" ascii
        $s3 = "SUID" ascii
        $s4 = "Interesting Files" ascii
        $s5 = "╔══════════" ascii
        $func1 = "checkContainerType" ascii
        $func2 = "checkSudoVersion" ascii
    condition:
        $header at 0 and ($s1 or $s2) and 2 of ($s3, $s4, $s5, $func1, $func2)
}
```

### Rule 2: winPEAS

```yara
rule winpeas_binary {
    meta:
        description = "Detects winPEAS executable"
        author = "Red Team Correlation Lab"
        severity = "high"
    strings:
        $s1 = "winPEAS" ascii wide nocase
        $s2 = "Windows Privilege Escalation" ascii wide
        $s3 = "AlwaysInstallElevated" ascii wide
        $s4 = "Unquoted Service" ascii wide
        $s5 = "TokenPrivileges" ascii wide
        $pe = { 4D 5A }
    condition:
        $pe at 0 and $s1 and 2 of ($s2, $s3, $s4, $s5)
}
```

### Rule 3: Mimikatz

```yara
rule mimikatz_binary {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "gentilkiwi" ascii wide
        $s3 = "sekurlsa::logonpasswords" ascii wide
        $s4 = "lsadump::sam" ascii wide
        $s5 = "kerberos::golden" ascii wide
        $s6 = "privilege::debug" ascii wide
        $s7 = "token::elevate" ascii wide
        $pe = { 4D 5A }
    condition:
        $pe at 0 and 3 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7)
}
```

### Rule 4: Meterpreter PE Payload

```yara
rule meterpreter_pe {
    meta:
        description = "Detects Meterpreter reverse TCP PE payload"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $pe = { 4D 5A }
        $s1 = "metsrv" ascii wide
        $s2 = "stdapi" ascii wide
        $s3 = "ReflectiveLoader" ascii
        $s4 = { 6D 65 74 65 72 70 72 65 74 65 72 }
        $ws2 = "ws2_32" ascii
        $net1 = { C0 A8 38 67 }
    condition:
        $pe at 0 and ($s1 or $s2 or $s3 or $s4) and ($ws2 or $net1)
}
```

### Rule 5: Meterpreter ELF Payload

```yara
rule meterpreter_elf {
    meta:
        description = "Detects Meterpreter reverse TCP ELF payload"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $elf = { 7F 45 4C 46 }
        $s1 = "metsrv" ascii
        $s2 = "stdapi" ascii
        $net1 = { C0 A8 38 67 }
        $sock = "socket" ascii
        $conn = "connect" ascii
    condition:
        $elf at 0 and ($s1 or $s2) and ($net1 or ($sock and $conn))
}
```

### Rule 6: msfvenom Reverse Shell (generic staged)

```yara
rule msfvenom_reverse_shell {
    meta:
        description = "Detects msfvenom generated reverse shell payloads"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $lab_ip = { C0 A8 38 67 }
        $lab_ip_alt = "192.168.56.103" ascii
        $port_4444 = { 11 5C }
        $shell_spawn = "/bin/sh" ascii
        $cmd_spawn = "cmd.exe" ascii
        $sock_call = { 6A 02 5F 6A 01 5E 6A 06 }
    condition:
        ($lab_ip or $lab_ip_alt) and ($port_4444 or $shell_spawn or $cmd_spawn or $sock_call)
}
```

### Rule 7: Chisel Tunneling Binary

```yara
rule chisel_binary {
    meta:
        description = "Detects Chisel tunneling tool"
        author = "Red Team Correlation Lab"
        severity = "high"
    strings:
        $s1 = "chisel" ascii nocase
        $s2 = "jpillora/chisel" ascii
        $s3 = "server" ascii
        $s4 = "client" ascii
        $s5 = "reverse" ascii
        $go = "Go build" ascii
        $socks = "socks" ascii
    condition:
        ($s1 or $s2) and $go and 2 of ($s3, $s4, $s5, $socks)
}
```

### Rule 8: PrintSpoofer / Potato Privilege Escalation

```yara
rule potato_privesc {
    meta:
        description = "Detects PrintSpoofer, JuicyPotato, GodPotato privilege escalation tools"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $pe = { 4D 5A }
        $a1 = "PrintSpoofer" ascii wide
        $a2 = "JuicyPotato" ascii wide
        $a3 = "GodPotato" ascii wide
        $a4 = "SweetPotato" ascii wide
        $b1 = "SeImpersonatePrivilege" ascii wide
        $b2 = "CreateProcessWithTokenW" ascii wide
        $b3 = "ImpersonateNamedPipeClient" ascii wide
    condition:
        $pe at 0 and (any of ($a*)) and (any of ($b*))
}
```

### Rule 9: PowerUp.ps1

```yara
rule powerup_ps1 {
    meta:
        description = "Detects PowerUp.ps1 privilege escalation script"
        author = "Red Team Correlation Lab"
        severity = "high"
    strings:
        $s1 = "PowerUp" ascii nocase
        $s2 = "Get-UnquotedService" ascii
        $s3 = "Get-ModifiableServiceFile" ascii
        $s4 = "Invoke-AllChecks" ascii
        $s5 = "Get-RegistryAlwaysInstallElevated" ascii
        $s6 = "Write-ServiceBinary" ascii
    condition:
        $s1 and 3 of ($s2, $s3, $s4, $s5, $s6)
}
```

### Rule 10: Seatbelt

```yara
rule seatbelt_binary {
    meta:
        description = "Detects Seatbelt .NET security enumeration tool"
        author = "Red Team Correlation Lab"
        severity = "high"
    strings:
        $pe = { 4D 5A }
        $s1 = "Seatbelt" ascii wide
        $s2 = "GhostPack" ascii wide
        $s3 = "TokenPrivileges" ascii wide
        $s4 = "CredEnum" ascii wide
        $s5 = "InterestingProcesses" ascii wide
        $s6 = "WindowsVault" ascii wide
    condition:
        $pe at 0 and $s1 and 2 of ($s2, $s3, $s4, $s5, $s6)
}
```

---

## Web Shell Rules

### Rule 11: PHP Web Shell (generic)

```yara
rule php_webshell_generic {
    meta:
        description = "Detects common PHP web shell patterns"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $php = "<?php" ascii nocase
        $a1 = "eval($_POST" ascii nocase
        $a2 = "eval($_GET" ascii nocase
        $a3 = "eval($_REQUEST" ascii nocase
        $a4 = "system($_GET" ascii nocase
        $a5 = "system($_POST" ascii nocase
        $a6 = "passthru($_GET" ascii nocase
        $a7 = "exec($_POST" ascii nocase
        $a8 = "shell_exec($_GET" ascii nocase
        $a9 = "assert($_POST" ascii nocase
        $a10 = "preg_replace" ascii nocase
        $b1 = "base64_decode" ascii nocase
        $b2 = "str_rot13" ascii nocase
        $b3 = "gzinflate" ascii nocase
    condition:
        $php and (any of ($a*) or (2 of ($b*)))
}
```

### Rule 12: PHP Web Shell (obfuscated)

```yara
rule php_webshell_obfuscated {
    meta:
        description = "Detects obfuscated PHP web shells using encoding"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $php = "<?php" ascii nocase
        $s1 = "chr(" ascii
        $s2 = "base64_decode" ascii
        $s3 = "str_replace" ascii
        $s4 = "gzuncompress" ascii
        $s5 = "eval(" ascii
        $long_string = /\$[a-zA-Z_]+\s*=\s*\"[A-Za-z0-9+\/=]{100,}\"/
    condition:
        $php and $s5 and ($long_string or 2 of ($s1, $s2, $s3, $s4))
}
```

---

## Payload Rules

### Rule 13: Bash Reverse Shell Pattern

```yara
rule bash_reverse_shell {
    meta:
        description = "Detects bash reverse shell patterns in scripts"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $a1 = "/dev/tcp/" ascii
        $a2 = "bash -i" ascii
        $a3 = "0>&1" ascii
        $b1 = "nc -e /bin" ascii
        $b2 = "ncat -e /bin" ascii
        $c1 = "mkfifo" ascii
        $c2 = "/tmp/f" ascii
        $d1 = "python -c" ascii
        $d2 = "socket.socket" ascii
        $d3 = "subprocess.call" ascii
        $d4 = "pty.spawn" ascii
    condition:
        ($a1 and ($a2 or $a3)) or ($b1 or $b2) or ($c1 and $c2) or ($d1 and 2 of ($d2, $d3, $d4))
}
```

### Rule 14: LD_PRELOAD Malicious Shared Library

```yara
rule ld_preload_malicious_so {
    meta:
        description = "Detects shared libraries designed for LD_PRELOAD privilege escalation"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $elf = { 7F 45 4C 46 }
        $s1 = "setuid" ascii
        $s2 = "setgid" ascii
        $s3 = "system" ascii
        $s4 = "/bin/sh" ascii
        $s5 = "/bin/bash" ascii
        $init = "_init" ascii
        $constructor = "__attribute__" ascii
    condition:
        $elf at 0 and ($init or $constructor) and $s1 and $s2 and ($s4 or $s5)
}
```

### Rule 15: SUID Backdoor Binary

```yara
rule suid_backdoor_binary {
    meta:
        description = "Detects small ELF binaries that set UID and spawn a shell (SUID backdoor)"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $elf = { 7F 45 4C 46 }
        $s1 = "setuid" ascii
        $s2 = "setgid" ascii
        $s3 = "/bin/sh" ascii
        $s4 = "/bin/bash" ascii
        $s5 = "execve" ascii
    condition:
        $elf at 0 and filesize < 50KB and $s1 and ($s3 or $s4) and ($s2 or $s5)
}
```

### Rule 16: Malicious MSI Package

```yara
rule malicious_msi_package {
    meta:
        description = "Detects MSI packages containing reverse shell or payload execution"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $msi = { D0 CF 11 E0 A1 B1 1A E1 }
        $s1 = "cmd.exe" ascii wide
        $s2 = "powershell" ascii wide nocase
        $s3 = "msiexec" ascii wide
        $s4 = "192.168.56.103" ascii wide
        $s5 = "Invoke-Expression" ascii wide nocase
        $s6 = "IEX" ascii wide
        $s7 = "DownloadString" ascii wide
    condition:
        $msi at 0 and 2 of ($s1, $s2, $s3, $s4, $s5, $s6, $s7)
}
```

### Rule 17: Malicious DLL Payload

```yara
rule malicious_dll_payload {
    meta:
        description = "Detects DLL payloads with reverse shell or injection capabilities"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $pe = { 4D 5A }
        $dll = "DllMain" ascii
        $s1 = "VirtualAlloc" ascii
        $s2 = "CreateThread" ascii
        $s3 = "WaitForSingleObject" ascii
        $net1 = "WSAStartup" ascii
        $net2 = "ws2_32" ascii
        $lab_ip = "192.168.56.103" ascii
        $shell = "cmd.exe" ascii wide
    condition:
        $pe at 0 and $dll and 2 of ($s1, $s2, $s3) and ($net1 or $net2 or $lab_ip or $shell)
}
```

---

## Persistence Artifact Rules

### Rule 18: Cron Reverse Shell Persistence

```yara
rule cron_reverse_shell {
    meta:
        description = "Detects cron entries containing reverse shell commands"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = "nc " ascii
        $s4 = "ncat " ascii
        $s5 = "* * * *" ascii
        $s6 = "@reboot" ascii
        $s7 = "crontab" ascii
    condition:
        ($s5 or $s6 or $s7) and ($s1 or $s2 or $s3 or $s4)
}
```

### Rule 19: Systemd Reverse Shell Persistence

```yara
rule systemd_reverse_shell {
    meta:
        description = "Detects systemd service files with reverse shell ExecStart"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $unit = "[Unit]" ascii
        $service = "[Service]" ascii
        $exec = "ExecStart" ascii
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = "nc " ascii
        $s4 = "python" ascii
        $s5 = "192.168.56.103" ascii
    condition:
        ($unit or $service) and $exec and 1 of ($s1, $s2, $s3, $s4, $s5)
}
```

### Rule 20: WMI Event Subscription Persistence

```yara
rule wmi_persistence_artifact {
    meta:
        description = "Detects WMI event subscription persistence artifacts"
        author = "Red Team Correlation Lab"
        severity = "critical"
    strings:
        $s1 = "__EventConsumer" ascii wide
        $s2 = "__EventFilter" ascii wide
        $s3 = "__FilterToConsumerBinding" ascii wide
        $s4 = "CommandLineEventConsumer" ascii wide
        $s5 = "ActiveScriptEventConsumer" ascii wide
        $s6 = "powershell" ascii wide nocase
        $s7 = "cmd.exe" ascii wide
    condition:
        2 of ($s1, $s2, $s3, $s4, $s5) and ($s6 or $s7)
}
```

---

## Deployment Notes

### OSSEC Integration

Add a custom OSSEC active-response or log analysis rule that invokes YARA scans on file creation events:

```xml
<localfile>
  <log_format>syslog</log_format>
  <command>yara -r /etc/yara/redteam-rules.yar /tmp 2>/dev/null</command>
  <frequency>300</frequency>
</localfile>
```

Place compiled rules in `/etc/yara/redteam-rules.yar` on each endpoint.

### Velociraptor Integration

Use the `Generic.Detection.Yara.Glob` artifact to deploy these rules:

- Compile all rules into a single `.yar` file.
- Upload the file as a Velociraptor tool resource.
- Create a hunt using `Generic.Detection.Yara.Glob` with glob patterns like `/tmp/**`, `/var/www/**`, and `C:\Users\**\*.exe`.

### ClamAV Integration

Convert YARA rules to ClamAV-compatible signatures or use ClamAV's built-in YARA support:

```bash
# Place .yar files in ClamAV's database directory
cp redteam-rules.yar /var/lib/clamav/
# Reload ClamAV
clamdscan --reload
# Scan target directories
clamscan -r --yara-rules=/var/lib/clamav/redteam-rules.yar /tmp /var/www /home
```

### Manual Scanning

```bash
# Scan a single file
yara redteam-rules.yar /path/to/suspicious_file

# Recursive scan of a directory
yara -r redteam-rules.yar /tmp/

# Scan a running process memory
yara -p 4 redteam-rules.yar /proc/<PID>/mem

# Scan with metadata output
yara -m -r redteam-rules.yar /var/www/html/
```
