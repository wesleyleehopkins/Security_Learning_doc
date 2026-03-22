# PowerShell Security & Audit Detections — Red Team Correlation

## Overview

PowerShell auditing configuration and detection queries for identifying Windows privilege escalation and post-exploitation activity from the pentest lab. All detections reference the lab environment (attacker 192.168.56.103, Windows target 192.168.56.101) and map to Phases 7 and 8 of the attack chain.

---

## Enabling PowerShell Logging

### 1. Script Block Logging (Event ID 4104)

Records the content of all PowerShell script blocks as they are executed. This is the single most important logging source for PowerShell-based attacks.

**Group Policy Path:**
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging
```

**Registry (enable via command):**
```powershell
# Enable Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable logging of script block invocation start/stop events
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1
```

**Verification:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
```

### 2. Module Logging (Event ID 4103)

Records pipeline execution details including parameter bindings and command output.

**Group Policy Path:**
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging
```

**Registry:**
```powershell
# Enable Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Log all modules (wildcard)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*"
```

### 3. Transcription Logging

Writes a full text transcript of every PowerShell session to disk.

**Group Policy Path:**
```
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription
```

**Registry:**
```powershell
# Enable Transcription
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PSTranscripts"

# Create output directory
New-Item -ItemType Directory -Path "C:\PSTranscripts" -Force
```

### 4. Constrained Language Mode

Restricts PowerShell to basic functionality, blocking .NET, COM, and Win32 API calls.

**Registry (system-wide enforcement):**
```powershell
# Set environment variable for system-wide CLM
[System.Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
```

**AppLocker-based enforcement (preferred):**
Configure AppLocker with a PowerShell script rule that allows only signed scripts. CLM is automatically enforced when AppLocker is active and the script is not in an allowed path.

**Verification:**
```powershell
$ExecutionContext.SessionState.LanguageMode
# Should return "ConstrainedLanguage"
```

---

## Detection Queries by Attack Phase

### Phase 7: Windows Privilege Escalation

#### Detection 1: PowerUp Invoke-AllChecks Execution

```powershell
# Query Script Block Logging for PowerUp activity
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Invoke-AllChecks|Get-ServiceUnquoted|Get-ModifiableServiceFile|Get-ModifiableService|Get-ServiceDetail'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}} | Format-List
```

#### Detection 2: Unquoted Service Path Enumeration

```powershell
# Detect Get-UnquotedService or manual WMI queries for unquoted paths
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Get-UnquotedService|Get-WmiObject.*Win32_Service.*PathName|gwmi.*Win32_Service'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

#### Detection 3: Seatbelt Execution

```powershell
# Detect Seatbelt command groups in script block logs
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Seatbelt|SeatBelt\.exe|Invoke-Seatbelt'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Also check process creation for Seatbelt binary execution
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'Seatbelt|seatbelt'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

#### Detection 4: winPEAS Execution

```powershell
# Detect winPEAS via process creation
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'winpeas|winPEAS|winPEASany|winPEASx64|winPEASx86'
} | Select-Object TimeCreated, @{N='NewProcess';E={$_.Properties[5].Value}}, @{N='CommandLine';E={$_.Properties[8].Value}}

# Detect winPEAS output patterns in transcription logs
Get-ChildItem "C:\PSTranscripts" -Recurse -Filter "*.txt" | Select-String -Pattern "winPEAS|Interesting Services|Modifiable Services" | Select-Object Filename, LineNumber, Line
```

#### Detection 5: AlwaysInstallElevated Check

```powershell
# Detect registry query for AlwaysInstallElevated policy
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'AlwaysInstallElevated|Get-RegistryAlwaysInstallElevated'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect msiexec abuse following AlwaysInstallElevated
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'msiexec.*\/quiet|msiexec.*\/qn|msiexec.*\/i.*\.msi'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

#### Detection 6: Token Impersonation via Incognito

```powershell
# Detect Incognito-related PowerShell activity
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Invoke-TokenManipulation|Incognito|list_tokens|impersonate_token|ImpersonateLoggedOnUser'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect logon type 9 (NewCredentials) which indicates token impersonation
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
} | Where-Object {
    $_.Properties[8].Value -eq '9'
} | Select-Object TimeCreated, @{N='TargetUser';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}
```

#### Detection 7: Service Binary Replacement

```powershell
# Detect service configuration changes
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 7045
} | Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}

# Detect sc.exe config commands modifying binpath
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'sc\.exe.*config.*binpath|sc\.exe.*create'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}

# Detect PowerUp Write-ServiceBinary
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Write-ServiceBinary|Install-ServiceBinary|Invoke-ServiceAbuse'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

#### Detection 8: UAC Bypass via fodhelper/eventvwr

```powershell
# Detect UAC bypass registry manipulation (fodhelper technique)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'ms-settings\\Shell\\Open\\command|mscfile\\Shell\\Open\\command|fodhelper|eventvwr|sdclt.*bypass'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect Sysmon registry events for UAC bypass keys (if Sysmon installed)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 13  # Registry value set
} | Where-Object {
    $_.Message -match 'ms-settings\\Shell\\Open\\command|mscfile\\Shell\\Open\\command'
} | Select-Object TimeCreated, @{N='Details';E={$_.Message}}
```

---

### Phase 8: Post-Exploitation

#### Detection 9: File Downloads from Attacker IP

```powershell
# Detect Invoke-WebRequest / wget / curl downloads from attacker
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match '192\.168\.56\.103' -and
    $_.Message -match 'Invoke-WebRequest|wget|curl|Start-BitsTransfer|Net\.WebClient|DownloadFile|DownloadString'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect certutil downloads
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'certutil.*-urlcache.*-split.*-f|certutil.*-urlcache.*192\.168\.56\.103'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

#### Detection 10: Data Staging with Compress-Archive

```powershell
# Detect Compress-Archive for data staging
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Compress-Archive|System\.IO\.Compression|ZipFile|\.zip'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect command-line zip utilities
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match '7z\.exe|7za\.exe|rar\.exe|Compress-Archive|makecab'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}
```

#### Detection 11: WMI Event Subscription Creation

```powershell
# Detect WMI subscription creation via PowerShell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Set-WmiInstance|New-CimInstance|__EventFilter|__EventConsumer|__FilterToConsumerBinding|CommandLineEventConsumer|ActiveScriptEventConsumer'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect WMI subscription via WMI activity log
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    Id = 5861  # WMI permanent event subscription
} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message
```

#### Detection 12: PowerShell Reverse Shell Patterns

```powershell
# Detect common PS reverse shell patterns
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Net\.Sockets\.TCPClient|System\.Net\.Sockets|IO\.StreamReader|IO\.StreamWriter|GetStream\(\)|TCPClient\(' -or
    $_.Message -match 'New-Object.*Net\.Sockets\.TCPClient.*192\.168\.56\.103' -or
    $_.Message -match '\$stream.*\$reader.*\$writer|\$client.*\$stream'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

#### Detection 13: Base64 Encoded Commands

```powershell
# Detect encoded command execution
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Message -match 'powershell.*-[eE]nc[oded]*[cC]*[ommand]*\s+[A-Za-z0-9+/=]{20,}' -or
    $_.Message -match 'powershell.*-[wW]indow[sS]tyle\s+[hH]idden' -or
    $_.Message -match 'powershell.*-[nN]o[pP]rofile.*-[nN]on[iI]nteractive'
} | Select-Object TimeCreated, @{N='CommandLine';E={$_.Properties[8].Value}}

# Decode and display Base64 commands from script block logs
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'FromBase64String|::Decode|[Convert]::FromBase64'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

#### Detection 14: IEX Download Cradles

```powershell
# Detect Invoke-Expression download cradles
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'IEX\s*\(|Invoke-Expression.*DownloadString|Invoke-Expression.*Net\.WebClient' -or
    $_.Message -match 'iex\s*\(New-Object' -or
    $_.Message -match 'IEX\s*\(\s*\(New-Object\s+Net\.WebClient\)\.DownloadString' -or
    $_.Message -match "'IEX \(New-Object Net\.WebClient\)\.DownloadString\('" -or
    $_.Message -match 'sal.*New-Object\|iex'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

#### Detection 15: Credential Dumping via PowerShell

```powershell
# Detect credential dumping commands and tools
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Invoke-Mimikatz|sekurlsa|logonpasswords|Get-GPPPassword|Find-GPOPasswords' -or
    $_.Message -match 'Get-VaultCredential|Out-Minidump|Get-Process.*lsass|comsvcs.*MiniDump' -or
    $_.Message -match 'ntds\.dit|SYSTEM\.hiv|SAM\.hiv' -or
    $_.Message -match 'Get-ItemProperty.*SAM|Get-ItemProperty.*SECURITY'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}

# Detect LSASS access (requires Sysmon Event ID 10)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 10  # Process Access
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match 'lsass\.exe' -and $_.Message -match 'GrantedAccess.*0x1010|GrantedAccess.*0x1038|GrantedAccess.*0x1FFFFF'
} | Select-Object TimeCreated, @{N='Details';E={$_.Message}}
```

#### Detection 16: Lateral Movement Preparation

```powershell
# Detect lateral movement PowerShell commands
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'Enter-PSSession|Invoke-Command.*-ComputerName|New-PSSession' -or
    $_.Message -match 'Invoke-WmiMethod.*-ComputerName|Invoke-CimMethod' -or
    $_.Message -match 'Copy-Item.*-ToSession|Copy-Item.*\\\\192\.168\.56'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

---

## Windows Event ID Reference

| Event ID | Log Source | Description | Attack Phase | Priority |
|---|---|---|---|---|
| 4104 | PowerShell/Operational | Script Block Logging — full script content | Phase 7, 8 | Critical |
| 4103 | PowerShell/Operational | Module Logging — pipeline execution details | Phase 7, 8 | High |
| 4688 | Security | Process Creation with command line | Phase 7, 8 | Critical |
| 4624 | Security | Successful logon | Phase 7, 8 | High |
| 4625 | Security | Failed logon attempt | Phase 7 | Medium |
| 4648 | Security | Explicit credential logon (runas, PtH) | Phase 8 | High |
| 4672 | Security | Special privileges assigned to new logon | Phase 7 | High |
| 4698 | Security | Scheduled task created | Phase 7, 8 | Critical |
| 4699 | Security | Scheduled task deleted | Phase 8 | Medium |
| 4697 | Security | Service installed on the system | Phase 7, 8 | Critical |
| 7045 | System | New service installed | Phase 7, 8 | Critical |
| 7040 | System | Service start type changed | Phase 7 | Medium |
| 1102 | Security | Audit log cleared | Phase 8 | Critical |
| 4720 | Security | User account created | Phase 8 | High |
| 4732 | Security | Member added to local group | Phase 8 | High |
| 1 | Sysmon | Process creation (with hash, parent) | Phase 7, 8 | Critical |
| 3 | Sysmon | Network connection | Phase 7, 8 | High |
| 7 | Sysmon | Image loaded (DLL) | Phase 7 | Medium |
| 10 | Sysmon | Process access (LSASS dump) | Phase 8 | Critical |
| 11 | Sysmon | File creation | Phase 7, 8 | Medium |
| 12/13/14 | Sysmon | Registry events | Phase 7, 8 | High |
| 5861 | WMI-Activity/Operational | WMI permanent event subscription | Phase 8 | Critical |

---

## AMSI Detection

### How AMSI Integrates with PowerShell Logging

The Antimalware Scan Interface (AMSI) inspects PowerShell script content at runtime before execution. It operates as a pipeline between PowerShell and the installed antimalware provider (Windows Defender by default).

**Detection chain:**
1. User or malware invokes a PowerShell script
2. PowerShell passes the script block to AMSI via `AmsiScanBuffer`
3. AMSI forwards the content to the registered AV provider
4. AV provider returns AMSI_RESULT (clean, detected, or blocked)
5. If blocked, Event ID 1116 (Windows Defender) is logged

**What AMSI catches from the lab attack chain:**
- PowerUp `Invoke-AllChecks` (if signatures are current)
- Mimikatz PowerShell reflective loading
- Common reverse shell one-liners
- `Invoke-Expression` download cradles
- Base64-decoded payloads (AMSI inspects post-decode)

**What AMSI does NOT catch:**
- Compiled executables (Seatbelt.exe, winPEAS.exe)
- AMSI bypass techniques executed before loading tools
- .NET assemblies loaded via `[Reflection.Assembly]::Load()`
- Attacks that avoid PowerShell entirely (cmd.exe, certutil)

**Detecting AMSI Bypass Attempts:**
```powershell
# Detect known AMSI bypass patterns in script block logs
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
} | Where-Object {
    $_.Message -match 'AmsiInitFailed|amsiContext|AmsiUtils|amsi\.dll|SetValue.*AmsiEnable' -or
    $_.Message -match 'System\.Management\.Automation\.AmsiUtils' -or
    $_.Message -match 'Reflection.*NonPublic.*amsi'
} | Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Properties[2].Value}}
```

---

## Sample Detection Scripts

### Hunt Script 1: Find Suspicious Scheduled Tasks

```powershell
# Enumerate scheduled tasks created by non-system accounts or with suspicious actions
$tasks = Get-ScheduledTask | Where-Object {
    $_.State -ne 'Disabled'
}

foreach ($task in $tasks) {
    $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
    $actions = $task.Actions

    foreach ($action in $actions) {
        $execute = $action.Execute
        $args = $action.Arguments

        # Flag tasks executing from temp, user profile, or with suspicious commands
        $suspicious = $false
        $reasons = @()

        if ($execute -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32') {
            $suspicious = $true
            $reasons += "Executes scripting engine: $execute"
        }
        if ($execute -match '\\Temp\\|\\tmp\\|\\AppData\\|\\Users\\.*\\Desktop') {
            $suspicious = $true
            $reasons += "Executes from user-writable path"
        }
        if ($args -match '-enc|-encodedcommand|downloadstring|invoke-expression|iex|bypass') {
            $suspicious = $true
            $reasons += "Suspicious arguments: $args"
        }
        if ($args -match '192\.168\.56\.103') {
            $suspicious = $true
            $reasons += "References attacker IP"
        }

        if ($suspicious) {
            [PSCustomObject]@{
                TaskName  = $task.TaskName
                TaskPath  = $task.TaskPath
                Execute   = $execute
                Arguments = $args
                Author    = $task.Principal.UserId
                Reasons   = ($reasons -join "; ")
                LastRun   = $info.LastRunTime
            }
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Hunt Script 2: Enumerate Run Key Persistence

```powershell
# Check all standard Run key locations for persistence
$runKeyPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($path in $runKeyPaths) {
    if (Test-Path $path) {
        $entries = Get-ItemProperty $path -ErrorAction SilentlyContinue
        $names = $entries.PSObject.Properties | Where-Object {
            $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSProvider', 'PSDrive')
        }
        foreach ($entry in $names) {
            $value = $entry.Value
            $suspicious = $value -match 'powershell|cmd.*\/c|wscript|mshta|192\.168\.56\.103|\\Temp\\|\\tmp\\|\.ps1|downloadstring'

            [PSCustomObject]@{
                RegistryPath = $path
                Name         = $entry.Name
                Value        = $value
                Suspicious   = $suspicious
            }
        }
    }
}  | Format-Table -AutoSize -Wrap
```

### Hunt Script 3: Check for WMI Subscriptions

```powershell
# Enumerate all WMI event subscriptions (common persistence mechanism)
Write-Host "`n=== WMI Event Filters ===" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class __EventFilter | ForEach-Object {
    [PSCustomObject]@{
        Name  = $_.Name
        Query = $_.Query
        Language = $_.QueryLanguage
    }
} | Format-Table -AutoSize -Wrap

Write-Host "`n=== WMI Event Consumers ===" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class CommandLineEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name       = $_.Name
        Command    = $_.CommandLineTemplate
        Executable = $_.ExecutablePath
    }
} | Format-Table -AutoSize -Wrap

Get-WmiObject -Namespace "root\subscription" -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Name     = $_.Name
        Language = $_.ScriptingEngine
        Script   = $_.ScriptText
    }
} | Format-Table -AutoSize -Wrap

Write-Host "`n=== WMI Filter-to-Consumer Bindings ===" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\subscription" -Class __FilterToConsumerBinding | ForEach-Object {
    [PSCustomObject]@{
        Filter   = $_.Filter
        Consumer = $_.Consumer
    }
} | Format-Table -AutoSize -Wrap
```

### Hunt Script 4: Find Recently Modified Service Binaries

```powershell
# Find services with recently modified or suspicious binaries
$cutoffDate = (Get-Date).AddDays(-7)

Get-WmiObject Win32_Service | ForEach-Object {
    $svc = $_
    $path = $svc.PathName

    # Extract executable path (handle quoted paths and arguments)
    if ($path -match '^"([^"]+)"') {
        $exePath = $Matches[1]
    } elseif ($path -match '^(\S+)') {
        $exePath = $Matches[1]
    } else {
        $exePath = $path
    }

    if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
        $fileInfo = Get-Item $exePath -ErrorAction SilentlyContinue
        $modified = $fileInfo.LastWriteTime

        $suspicious = $false
        $reasons = @()

        if ($modified -gt $cutoffDate) {
            $suspicious = $true
            $reasons += "Modified within last 7 days ($modified)"
        }
        if ($exePath -match '\\Temp\\|\\tmp\\|\\AppData\\|\\Users\\') {
            $suspicious = $true
            $reasons += "Binary in user-writable location"
        }
        if (-not (Get-AuthenticodeSignature $exePath -ErrorAction SilentlyContinue).Status -eq 'Valid') {
            if ($suspicious) { $reasons += "Binary not digitally signed" }
        }

        if ($suspicious) {
            [PSCustomObject]@{
                ServiceName  = $svc.Name
                DisplayName  = $svc.DisplayName
                StartMode    = $svc.StartMode
                BinaryPath   = $exePath
                LastModified = $modified
                Reasons      = ($reasons -join "; ")
            }
        }
    }
} | Format-Table -AutoSize -Wrap
```

### Hunt Script 5: Scan for UAC Bypass Registry Artifacts

```powershell
# Check registry locations commonly abused for UAC bypass
$uacBypassKeys = @(
    @{Path="HKCU:\Software\Classes\ms-settings\Shell\Open\command"; Technique="fodhelper.exe"},
    @{Path="HKCU:\Software\Classes\mscfile\Shell\Open\command"; Technique="eventvwr.exe"},
    @{Path="HKCU:\Software\Classes\exefile\Shell\Open\command"; Technique="sdclt.exe"},
    @{Path="HKCU:\Environment"; ValueName="windir"; Technique="schtasks.exe"},
    @{Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"; Technique="sdclt.exe isolation"}
)

$findings = foreach ($key in $uacBypassKeys) {
    if (Test-Path $key.Path) {
        $props = Get-ItemProperty $key.Path -ErrorAction SilentlyContinue
        $defaultValue = $props.'(Default)'
        $delegateExec = $props.DelegateExecute

        [PSCustomObject]@{
            RegistryPath    = $key.Path
            Technique       = $key.Technique
            DefaultValue    = $defaultValue
            DelegateExecute = $delegateExec
            Status          = "KEY EXISTS - Possible UAC Bypass Artifact"
        }
    }
}

if ($findings) {
    Write-Host "`n[!] UAC Bypass artifacts detected:" -ForegroundColor Red
    $findings | Format-Table -AutoSize -Wrap
} else {
    Write-Host "`n[+] No UAC bypass registry artifacts found." -ForegroundColor Green
}
```
