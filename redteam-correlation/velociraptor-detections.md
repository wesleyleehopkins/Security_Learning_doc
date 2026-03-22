# Velociraptor Hunt Artifacts — Red Team Correlation

## Overview

VQL (Velociraptor Query Language) artifacts and hunts for detecting pentest lab attack chain indicators. Targets Ubuntu (.102) and Windows (.101) endpoints with the attacker at Kali (.103).

---

## Linux Hunt Artifacts (Ubuntu .102)

### 1. SUID Binary Enumeration and Anomaly Detection

```vql
SELECT FullPath, Mode, Size, Mtime,
       hash(path=FullPath, hashselect="SHA256") AS SHA256
FROM glob(globs="/usr/bin/*,/usr/sbin/*,/usr/local/bin/*,/bin/*,/sbin/*,/tmp/*")
WHERE Mode =~ "^-..[sS]"
   OR Mode =~ "^-.....[sS]"
ORDER BY Mtime DESC
```

### 2. Sudo Misconfiguration Check

```vql
SELECT * FROM foreach(
  row={
    SELECT FullPath FROM glob(globs="/etc/sudoers,/etc/sudoers.d/*")
  },
  query={
    SELECT FullPath, Line FROM parse_lines(filename=FullPath)
    WHERE Line =~ "NOPASSWD"
       OR Line =~ "ALL.*ALL.*ALL"
       OR Line =~ "!authenticate"
  }
)
```

### 3. Cron Job Analysis (Reverse Shell Detection)

```vql
SELECT * FROM foreach(
  row={
    SELECT FullPath FROM glob(globs="/var/spool/cron/crontabs/*,/etc/cron.d/*,/etc/crontab")
  },
  query={
    SELECT FullPath, Line FROM parse_lines(filename=FullPath)
    WHERE Line =~ "/dev/tcp"
       OR Line =~ "bash -i"
       OR Line =~ "nc\\s+-e"
       OR Line =~ "192\\.168\\.56\\.103"
       OR Line =~ "mkfifo"
  }
)
```

### 4. SSH Authorized Keys Audit

```vql
SELECT FullPath,
       read_file(filename=FullPath, length=10000) AS Content,
       Mtime, Atime
FROM glob(globs="/home/*/.ssh/authorized_keys,/root/.ssh/authorized_keys")
```

### 5. /tmp Artifact Scanning

```vql
SELECT FullPath, Mode, Size, Mtime, IsExecutable,
       hash(path=FullPath, hashselect="SHA256") AS SHA256,
       magic(path=FullPath) AS FileType
FROM glob(globs="/tmp/**,/dev/shm/**,/var/tmp/**")
WHERE IsExecutable
   OR FullPath =~ "\\.(sh|py|pl|elf|so|bin)$"
   OR Size > 100000
ORDER BY Mtime DESC
```

### 6. .bashrc Backdoor Detection

```vql
SELECT * FROM foreach(
  row={
    SELECT FullPath FROM glob(globs="/home/*/.bashrc,/home/*/.bash_profile,/root/.bashrc,/root/.bash_profile")
  },
  query={
    SELECT FullPath, Line FROM parse_lines(filename=FullPath)
    WHERE Line =~ "/dev/tcp"
       OR Line =~ "nc\\s.*-e"
       OR Line =~ "python.*socket"
       OR Line =~ "bash -i"
       OR Line =~ "curl.*\\|.*bash"
       OR Line =~ "wget.*\\|.*sh"
  }
)
```

### 7. New User Account Detection

```vql
SELECT User, Description, Uid, Gid, HomeDir, Shell
FROM parse_records_with_regex(
  file="/etc/passwd",
  regex="(?P<User>[^:]+):x:(?P<Uid>\\d+):(?P<Gid>\\d+):(?P<Description>[^:]*):(?P<HomeDir>[^:]+):(?P<Shell>[^\\n]+)"
)
WHERE Uid >= 1000 AND Uid < 65534
   OR Uid = 0 AND User != "root"
```

### 8. Systemd Service Persistence

```vql
SELECT * FROM foreach(
  row={
    SELECT FullPath FROM glob(globs="/etc/systemd/system/*.service,/lib/systemd/system/*.service,/home/*/.config/systemd/user/*.service")
  },
  query={
    SELECT FullPath, Line FROM parse_lines(filename=FullPath)
    WHERE Line =~ "ExecStart.*(/dev/tcp|nc\\s|bash\\s-i|python|192\\.168\\.56\\.103)"
       OR Line =~ "ExecStart.*/tmp/"
  }
)
```

### 9. Linux Capability Enumeration

```vql
SELECT FullPath, Mode, Size,
       upload(file=FullPath) AS Binary
FROM glob(globs="/usr/bin/*,/usr/sbin/*,/usr/local/bin/*")
WHERE attrinfo(filename=FullPath).caps != ""
```

> Alternative using execve:

```vql
SELECT * FROM execve(argv=["getcap", "-r", "/"])
```

### 10. Running Process Analysis (Reverse Shell Patterns)

```vql
SELECT Pid, Ppid, Name, Username, CommandLine, CreateTime,
       {
         SELECT RemoteAddr, RemotePort FROM connections()
         WHERE Pid = ProcessPid
       } AS NetConnections
FROM process_tracker_pslist()
WHERE CommandLine =~ "/dev/tcp"
   OR CommandLine =~ "bash -i"
   OR CommandLine =~ "nc\\s.*-e"
   OR CommandLine =~ "python.*socket"
   OR CommandLine =~ "192\\.168\\.56\\.103"
   OR Name =~ "^(nc|ncat|socat|chisel)$"
```

---

## Windows Hunt Artifacts (Windows .101)

### 11. Unquoted Service Path Detection

```vql
SELECT Name, DisplayName, PathName, StartMode, State
FROM wmi(
  query="SELECT Name, DisplayName, PathName, StartMode, State FROM Win32_Service"
)
WHERE PathName =~ "^[^\"].+\\s.+\\.exe"
  AND NOT PathName =~ "^[A-Za-z]:\\\\Windows\\\\"
```

### 12. Service Binary Permission Check

```vql
SELECT Name, PathName,
       lookupSID(
         sid=upload_accessor(
           file=regex_replace(source=PathName, re="\\s.*$", replace=""),
           accessor="file"
         )
       ) AS Permissions
FROM wmi(
  query="SELECT Name, PathName FROM Win32_Service"
)
WHERE NOT PathName =~ "^.?[A-Za-z]:\\\\Windows\\\\"
```

> Simplified approach using icacls:

```vql
SELECT * FROM foreach(
  row={
    SELECT regex_replace(source=PathName, re="\"", replace="") AS CleanPath
    FROM wmi(query="SELECT PathName FROM Win32_Service")
    WHERE NOT PathName =~ "Windows"
  },
  query={
    SELECT * FROM execve(argv=["icacls", CleanPath])
    WHERE Stdout =~ "(BUILTIN\\\\Users|Everyone|Authenticated Users).*(F|M|W)"
  }
)
```

### 13. AlwaysInstallElevated Check

```vql
SELECT Key, ValueName, ValueData
FROM glob(
  globs="HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\*,HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\*",
  accessor="registry"
)
WHERE ValueName = "AlwaysInstallElevated"
  AND ValueData = 1
```

### 14. UAC Bypass Registry Artifacts

```vql
SELECT Key, ValueName, ValueData, Mtime
FROM glob(
  globs="HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command\\*,HKCU\\Software\\Classes\\mscfile\\shell\\open\\command\\*",
  accessor="registry"
)
```

### 15. Scheduled Task Analysis

```vql
SELECT Name, Path, State, LastRunTime, NextRunTime,
       Actions, Triggers, Principal
FROM scheduled_tasks()
WHERE NOT Path =~ "^\\\\Microsoft"
   OR Actions =~ "(powershell|cmd\\.exe|192\\.168\\.56\\.103|/tmp/|\\\\Temp\\\\)"
```

### 16. WMI Event Subscription Enumeration

```vql
LET consumers = SELECT * FROM wmi(
  query="SELECT * FROM __EventConsumer",
  namespace="ROOT/subscription"
)

LET filters = SELECT * FROM wmi(
  query="SELECT * FROM __EventFilter",
  namespace="ROOT/subscription"
)

LET bindings = SELECT * FROM wmi(
  query="SELECT * FROM __FilterToConsumerBinding",
  namespace="ROOT/subscription"
)

SELECT * FROM chain(
  q1={ SELECT "Consumer" AS Type, * FROM consumers },
  q2={ SELECT "Filter" AS Type, * FROM filters },
  q3={ SELECT "Binding" AS Type, * FROM bindings }
)
```

### 17. Run Key Persistence

```vql
SELECT Key, ValueName, ValueData, Mtime
FROM glob(
  globs="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*,HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*,HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*,HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*,HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\*",
  accessor="registry"
)
WHERE ValueData =~ "(powershell|cmd\\.exe|192\\.168\\.56\\.103|Temp|AppData)"
   OR Mtime > timestamp(epoch=now() - 86400 * 7)
```

### 18. DLL Hijacking Opportunity Scan

```vql
SELECT * FROM foreach(
  row={
    SELECT regex_replace(
      source=regex_replace(source=PathName, re="\"", replace=""),
      re="[^\\\\]+$",
      replace=""
    ) AS ServiceDir
    FROM wmi(query="SELECT PathName FROM Win32_Service")
    WHERE NOT PathName =~ "Windows"
  },
  query={
    SELECT ServiceDir, FullPath, Mode
    FROM glob(globs=ServiceDir + "*.dll")
    WHERE Mode =~ "w"
  }
)
```

### 19. SAM/SYSTEM Dump Evidence

```vql
SELECT FullPath, Size, Mtime, Atime,
       hash(path=FullPath, hashselect="SHA256") AS SHA256
FROM glob(globs="C:\\Users\\**\\sam,C:\\Users\\**\\system,C:\\Users\\**\\security,C:\\Temp\\**\\sam,C:\\Temp\\**\\system,C:\\Windows\\Temp\\**\\sam")
WHERE FullPath =~ "(?i)(sam|system|security)$"
  AND Size > 0
```

### 20. Sysmon Log Analysis for Tool Execution

```vql
SELECT EventTime, Computer,
       EventData.Image AS Image,
       EventData.CommandLine AS CommandLine,
       EventData.ParentImage AS ParentImage,
       EventData.User AS User,
       EventData.Hashes AS Hashes
FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx")
WHERE EventID = 1
  AND (
    CommandLine =~ "(?i)(mimikatz|winpeas|seatbelt|chisel|printspoofer|godpotato|juicypotato|powerup)"
    OR CommandLine =~ "192\\.168\\.56\\.103"
    OR CommandLine =~ "(?i)(Invoke-Expression|IEX|DownloadString|EncodedCommand)"
    OR Image =~ "(?i)\\\\(Temp|tmp)\\\\"
  )
ORDER BY EventTime DESC
LIMIT 500
```

---

## Network Hunt Artifacts

### 21. Connection Analysis (Active Connections to Attacker)

```vql
SELECT Pid, Name, Status, Family,
       LocalAddr, LocalPort,
       RemoteAddr, RemotePort,
       Timestamp
FROM connections()
WHERE RemoteAddr = "192.168.56.103"
   OR RemotePort IN (4444, 4443, 8443, 8080, 1234, 9001)
```

### 22. DNS Query Analysis

```vql
SELECT EventTime,
       EventData.QueryName AS QueryName,
       EventData.QueryType AS QueryType,
       EventData.QueryResults AS QueryResults
FROM parse_evtx(filename="C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DNS-Client%4Operational.evtx")
WHERE len(list=split(string=EventData.QueryName, sep=".")[0]) > 30
   OR EventData.QueryName =~ "192\\.168\\.56\\.103"
ORDER BY EventTime DESC
```

---

## Scheduled Hunts

| Hunt Name | Artifact/Query | Frequency | Targets |
|---|---|---|---|
| SUID Anomaly Scan | Query 1 (SUID Enumeration) | Every 6 hours | Linux endpoints |
| Cron Persistence Check | Query 3 (Cron Analysis) | Every 4 hours | Linux endpoints |
| /tmp Artifact Scan | Query 5 (/tmp Scanning) | Every 2 hours | Linux endpoints |
| Process Shell Detection | Query 10 (Process Analysis) | Every 1 hour | Linux endpoints |
| Unquoted Service Paths | Query 11 (Unquoted Service) | Daily | Windows endpoints |
| Registry Persistence | Query 17 (Run Keys) | Every 4 hours | Windows endpoints |
| WMI Persistence | Query 16 (WMI Subscriptions) | Every 6 hours | Windows endpoints |
| Sysmon Tool Execution | Query 20 (Sysmon Analysis) | Every 1 hour | Windows endpoints |
| Active C2 Connections | Query 21 (Connections) | Every 30 minutes | All endpoints |
| Authorized Keys Audit | Query 4 (SSH Keys) | Daily | Linux endpoints |

---

## Deployment Notes

### Server Setup

1. Deploy the Velociraptor server on a monitoring host within the 192.168.56.0/24 network (or with routing to it).
2. Install Velociraptor clients on both Ubuntu (.102) and Windows (.101) targets.
3. Enroll clients using the generated client configuration file.

### Creating Custom Artifacts

Save each VQL query as a custom artifact YAML file:

```yaml
name: Custom.RedTeam.LinuxSUID
description: Enumerate SUID binaries and detect anomalies
type: CLIENT
sources:
  - query: |
      SELECT FullPath, Mode, Size, Mtime,
             hash(path=FullPath, hashselect="SHA256") AS SHA256
      FROM glob(globs="/usr/bin/*,/usr/sbin/*,/usr/local/bin/*,/bin/*,/sbin/*,/tmp/*")
      WHERE Mode =~ "^-..[sS]"
         OR Mode =~ "^-.....[sS]"
      ORDER BY Mtime DESC
```

Upload custom artifacts via the Velociraptor GUI under **View Artifacts > Add Custom Artifact**.

### Hunt Workflow

1. Navigate to **Hunt Manager** in the Velociraptor GUI.
2. Click **New Hunt** and select the target artifact.
3. Configure target labels or OS type to scope the hunt.
4. Set the expiry time and resource limits (CPU/IOPS).
5. Launch the hunt and monitor results in the **Hunt Notebook**.
6. Export results as CSV or JSON for correlation with other detection sources.

### Integration with Other Detection Files

- Cross-reference YARA rule hits (from `yara-detections.md`) by deploying YARA scans via the `Generic.Detection.Yara.Glob` built-in artifact.
- Correlate network connection results (Query 21) with Wireshark captures (from `wireshark-detections.md`) for timeline reconstruction.
- Use Velociraptor's server-side VQL to aggregate findings across all endpoints into a unified detection dashboard.
