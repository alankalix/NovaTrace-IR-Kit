# NovaTrace IR Kit - Technical Documentation

## Overview

This document provides a comprehensive technical explanation of all PowerShell logic, cmdlets, and methods used in NovaTrace IR Kit v1.0.0. It is intended for security professionals, developers, and auditors who want to understand exactly how the script operates.

---

## Table of Contents

1. [Script Architecture](#1-script-architecture)
2. [Initialization and Configuration](#2-initialization-and-configuration)
3. [Core Helper Functions](#3-core-helper-functions)
4. [Display and Progress Functions](#4-display-and-progress-functions)
5. [Artifact Collection Methods](#5-artifact-collection-methods)
6. [Windows APIs and .NET Classes Used](#6-windows-apis-and-net-classes-used)
7. [Registry Paths Accessed](#7-registry-paths-accessed)
8. [Event Log Queries](#8-event-log-queries)
9. [File System Locations](#9-file-system-locations)
10. [Security Considerations](#10-security-considerations)

---

## 1. Script Architecture

### 1.1 Overall Structure

The script is organized into logical regions using PowerShell's `#region` directive:

```
#region Initialization       - Setup, parameters, ZIP creation
#region Helper Functions     - Core utility functions
#region Display Functions    - UI and progress display
#region System Information   - OS, hardware, software collection
#region User Accounts        - Local users, groups, profiles
#region Processes/Services   - Running processes, services
#region Network              - Connections, DNS, configuration
#region Persistence          - Autorun locations, scheduled tasks
#region Execution Artifacts  - Prefetch, Amcache, ShimCache
#region Registry             - Raw hive collection
#region FileSystem           - Jump lists, LNK files, timeline
#region Browser              - Browser history databases
#region Event Logs           - EVTX file collection
#region Parsed Security      - Pre-parsed security events
#region Security Status      - Defender, firewall status
#region Finalization         - Manifest, cleanup, summary
```

### 1.2 Execution Flow

```
1. Parse parameters (-OutputPath)
2. Initialize variables and suppress output
3. Create ZIP archive using .NET compression
4. Display banner with system info
5. Execute 52 collection tasks via Invoke-Collect
6. Generate hash manifest and logs
7. Close ZIP archive
8. Display summary and cleanup
```

---

## 2. Initialization and Configuration

### 2.1 Parameter Handling

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)
```

**Purpose**: Accepts optional custom output directory. Uses `CmdletBinding()` for advanced function features.

### 2.2 Preference Variables

```powershell
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$env:POWERSHELL_UPDATECHECK = 'Off'
```

**Purpose**: Suppresses all non-essential output for clean execution. Critical for Live Response environments where output must be controlled.

### 2.3 .NET Assembly Loading

```powershell
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
```

**Purpose**: Loads .NET compression libraries for direct-to-ZIP writing without external dependencies.

### 2.4 Environment Detection

```powershell
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsLiveResponse = $PSScriptRoot -like "*Windows Defender Advanced Threat Protection*"
```

**Logic Explanation**:
- **Admin Check**: Uses Windows Security Principal to check if running with elevated privileges
- **Live Response Detection**: Defender EDR Live Response executes scripts from a specific ATP directory path

### 2.5 Output Path Logic

```powershell
if ($OutputPath) {
    $script:ZipPath = Join-Path $OutputPath $ZipName
} elseif ($IsLiveResponse) {
    $script:ZipPath = "C:\$ZipName"
} else {
    $script:ZipPath = Join-Path $PSScriptRoot $ZipName
}
```

**Priority**:
1. User-specified path (highest)
2. C:\ root for Live Response (required for getfile command)
3. Script directory (default)

### 2.6 ZIP Archive Creation

```powershell
$script:ZipArchive = [System.IO.Compression.ZipFile]::Open($script:ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
```

**Purpose**: Opens a new ZIP archive in Create mode. All artifacts are written directly to this archive, minimizing disk footprint.

---

## 3. Core Helper Functions

### 3.1 Write-Log Function

```powershell
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    $color = switch ($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} "OK" {"Green"} default {"Cyan"} }
    Write-Host $line -ForegroundColor $color
    $null = $script:LogEntries.Add($line)
    if ($Level -eq "ERROR") { $null = $script:ErrorEntries.Add($line) }
}
```

**Purpose**: Centralized logging with color-coded console output and in-memory log storage.

### 3.2 Invoke-Collect Function

```powershell
function Invoke-Collect {
    param([string]$Name, [scriptblock]$Action, [switch]$Admin, [switch]$Silent)
    $script:Stats.Total++
    $script:CurrentStep++
    if ($Admin -and -not $IsAdmin) {
        Write-Log "$Name - Skipped (requires admin)" "WARN"
        $script:Stats.Skipped++
        return
    }
    try {
        $result = & $Action
        $script:Stats.Success++
    } catch {
        Write-Log "$Name - $($_.Exception.Message)" "ERROR"
        $script:Stats.Failed++
    }
}
```

**Purpose**: Wrapper function that:
- Tracks collection statistics
- Handles admin privilege requirements
- Provides consistent error handling
- Updates progress display

### 3.3 Add-ToZip Function

```powershell
function Add-ToZip {
    param([string]$EntryPath, [string]$Content, [byte[]]$Bytes)
    $entry = $script:ZipArchive.CreateEntry($EntryPath, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    if ($Content) {
        $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::UTF8)
        $writer.Write($Content)
        $writer.Close()
    } elseif ($Bytes) {
        $stream.Write($Bytes, 0, $bytes.Length)
        $stream.Close()
    }
}
```

**Purpose**: Writes content directly to ZIP entry without intermediate files.

**Technical Details**:
- Uses `CompressionLevel::Optimal` for best compression
- Supports both string content and byte arrays
- UTF-8 encoding for text content

### 3.4 Save-ToCSV Function

```powershell
function Save-ToCSV {
    param([object]$Data, [string]$EntryPath)
    $csvContent = ($Data | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    Add-ToZip -EntryPath $EntryPath -Content $csvContent
    
    # Calculate hash from content bytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($csvContent)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($bytes)
    $hash = [BitConverter]::ToString($hashBytes) -replace '-', ''
}
```

**Purpose**: Converts PowerShell objects to CSV and writes to ZIP with hash tracking.

### 3.5 Copy-LockedFile Function

```powershell
function Copy-LockedFile {
    param([string]$Source, [string]$EntryPath)
    
    # Method 1: Direct read (works for most files)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Source)
        # Write directly to ZIP
        return $true
    } catch {}
    
    # Method 2: Copy-Item (standard copy)
    try { 
        Copy-Item -Path $Source -Destination $tempDest -Force
    } catch {}
    
    # Method 3: esentutl (for locked ESE databases)
    try { 
        & esentutl /y $Source /d $tempDest /o
    } catch {}
}
```

**Purpose**: Multi-method approach to copy locked/in-use files.

**Methods Used**:
1. **Direct .NET Read**: `[System.IO.File]::ReadAllBytes()` - fastest, works for unlocked files
2. **Copy-Item**: Standard PowerShell copy - handles some locked files
3. **esentutl**: Windows utility for copying ESE databases (SRUM, browser DBs) - handles locked databases

---

## 4. Display and Progress Functions

### 4.1 Show-Banner Function

Displays ASCII art header with system information:
- Hostname
- Admin status
- Current time
- Collection mode

### 4.2 Show-Progress Function

```powershell
function Show-Progress {
    param([string]$Task)
    $pct = [math]::Floor(($script:CurrentStep / $script:TotalSteps) * 100)
    $filled = [math]::Floor(40 * $pct / 100)
    $bar = "[" + ("=" * $filled) + ("-" * (40 - $filled)) + "]"
    Write-Host ("`r" + $progressText) -NoNewline
}
```

**Purpose**: Real-time progress bar with percentage and elapsed time.

---

## 5. Artifact Collection Methods

### 5.1 System Information Collection

| Artifact | Cmdlet/Method | Data Retrieved |
|----------|---------------|----------------|
| OS Info | `Get-CimInstance Win32_OperatingSystem` | Caption, Version, Build, InstallDate, LastBootTime |
| Computer Info | `Get-CimInstance Win32_ComputerSystem` | Manufacturer, Model, Domain, TotalPhysicalMemory |
| BIOS Info | `Get-CimInstance Win32_BIOS` | SerialNumber |
| Time Zone | `Get-TimeZone` | Id, BaseUtcOffset |
| Installed Software | `Get-ItemProperty HKLM:\...\Uninstall\*` | DisplayName, Version, Publisher, InstallDate |
| Hotfixes | `Get-HotFix` | HotFixID, Description, InstalledOn |
| Drivers | `Get-CimInstance Win32_SystemDriver` | Name, State, StartMode, PathName |
| Environment | `Get-ChildItem Env:` | All environment variables |
| USB History | Registry: `HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR` | Device class, serial, friendly name |
| Disks | `Get-CimInstance Win32_LogicalDisk` | DeviceID, Size, FreeSpace, FileSystem |

### 5.2 User Account Collection

| Artifact | Cmdlet/Method | Data Retrieved |
|----------|---------------|----------------|
| Local Users | `Get-LocalUser` | Name, Enabled, LastLogon, SID |
| Local Groups | `Get-LocalGroup` | Name, Description, SID |
| Group Members | `Get-LocalGroupMember` | Group, Member Name, Type, SID |
| User Profiles | `Get-CimInstance Win32_UserProfile` | LocalPath, SID, LastUseTime |
| Active Sessions | `quser` command | Username, Session, State |

### 5.3 Process Collection

```powershell
$wmiProcs = Get-CimInstance -ClassName Win32_Process
foreach ($proc in $wmiProcs) {
    # Get process owner
    $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner
    
    # Get parent process name
    $parentProc = $wmiProcs | Where-Object { $_.ProcessId -eq $proc.ParentProcessId }
    
    # Check digital signature
    $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath
}
```

**Data Collected**:
- PID, PPID, Parent Name
- Process Name, Path, Command Line
- Owner (Domain\User)
- Session ID, Creation Time
- Thread Count, Handle Count, Working Set
- Signature Status and Signer

### 5.4 Network Collection

| Artifact | Cmdlet/Method | Data Retrieved |
|----------|---------------|----------------|
| TCP Connections | `Get-NetTCPConnection` | Local/Remote Address:Port, State, PID |
| UDP Endpoints | `Get-NetUDPEndpoint` | Local Address:Port, PID |
| Listening Ports | `Get-NetTCPConnection -State Listen` | All listening services |
| DNS Cache | `Get-DnsClientCache` | Entry, Name, Type, TTL, Data |
| ARP Cache | `Get-NetNeighbor` | IP Address, MAC Address, State |
| Routes | `Get-NetRoute` | Destination, NextHop, Metric |
| IP Config | `Get-NetIPConfiguration` | Interface, IPv4, Gateway, DNS |
| SMB Shares | `Get-SmbShare` | Name, Path, Description |
| SMB Sessions | `Get-SmbSession` | Client, User, Open Files |
| Hosts File | `Get-Content $env:SystemRoot\System32\drivers\etc\hosts` | Local DNS overrides |

### 5.5 Persistence Collection

| Location | Method | Purpose |
|----------|--------|---------|
| Run Keys | Registry queries | Auto-start programs |
| Scheduled Tasks | `Get-ScheduledTask` | Task definitions |
| Task XML Files | File copy from `$env:SystemRoot\System32\Tasks` | Raw task XML |
| WMI Subscriptions | `Get-CimInstance -Namespace root\subscription` | Event filters, consumers, bindings |
| Startup Folder | `Get-ChildItem` on startup paths | Startup shortcuts |
| BITS Jobs | `Get-BitsTransfer -AllUsers` | Background transfers |
| Winlogon | Registry: `HKLM:\...\Winlogon` | Shell, Userinit values |
| IFEO | Registry: `HKLM:\...\Image File Execution Options` | Debugger hijacks |
| AppInit DLLs | Registry queries | DLL injection points |

### 5.6 Execution Artifacts

| Artifact | Source | Collection Method |
|----------|--------|-------------------|
| Prefetch | `$env:SystemRoot\Prefetch\*.pf` | File copy + metadata |
| Amcache.hve | `$env:SystemRoot\AppCompat\Programs\Amcache.hve` | `Copy-LockedFile` with esentutl fallback |
| ShimCache | Registry export | `reg export` command |
| BAM/DAM | Registry: `HKLM:\SYSTEM\...\bam\State\UserSettings` | Binary timestamp parsing |
| UserAssist | Registry: `HKU\*\...\UserAssist\*\Count` | ROT13 decoding |
| SRUM | `$env:SystemRoot\System32\sru\SRUDB.dat` | `Copy-LockedFile` |
| PowerShell History | `C:\Users\*\...\PSReadLine\ConsoleHost_history.txt` | File copy |
| Run MRU | Registry: `HKCU:\...\Explorer\RunMRU` | Recent commands |

### 5.7 Browser History Collection

```powershell
# Chrome
$chromePath = Join-Path $userFolder.FullName "AppData\Local\Google\Chrome\User Data"
$historyPath = Join-Path $profile.FullName "History"
Copy-LockedFile -Source $historyPath -EntryPath "..."

# Edge (same structure as Chrome)
$edgePath = Join-Path $userFolder.FullName "AppData\Local\Microsoft\Edge\User Data"

# Firefox
$firefoxPath = Join-Path $userFolder.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
$placesPath = Join-Path $profile.FullName "places.sqlite"
```

**Note**: Only history databases are collected. Passwords, cookies with credentials, and login data are explicitly NOT collected.

### 5.8 Event Log Collection

```powershell
# Export using wevtutil (preserves full fidelity)
wevtutil epl Security $tempEvtx
wevtutil epl System $tempEvtx
wevtutil epl Application $tempEvtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" $tempEvtx
# ... additional logs
```

**Logs Collected**:
- Security, System, Application
- PowerShell Operational
- Task Scheduler Operational
- Windows Defender Operational
- WinRM Operational
- Terminal Services (Local/Remote)
- Sysmon Operational (if installed)
- WMI Activity Operational
- BITS Client Operational

### 5.9 Parsed Security Events

```powershell
# Example: Logon Events parsing
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648} -MaxEvents 5000
foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}
    foreach ($d in $xml.Event.EventData.Data) { 
        $data[$d.Name] = $d.'#text' 
    }
    # Extract: TargetUserName, TargetDomainName, LogonType, IpAddress, etc.
}
```

**Event IDs Parsed**:
| Event ID | Description |
|----------|-------------|
| 4624 | Successful Logon |
| 4625 | Failed Logon |
| 4648 | Explicit Credentials |
| 4688 | Process Creation |
| 4768 | Kerberos TGT Request |
| 4769 | Kerberos Service Ticket |
| 4776 | NTLM Authentication |
| 4697 | Service Installation |
| 7045 | Service Installation (System log) |
| 4698 | Scheduled Task Created |
| 4702 | Scheduled Task Updated |
| 21-25 | RDP Session Events |

---

## 6. Windows APIs and .NET Classes Used

### 6.1 .NET Framework Classes

| Class | Purpose |
|-------|---------|
| `System.IO.Compression.ZipFile` | ZIP archive creation |
| `System.IO.Compression.ZipArchive` | ZIP entry management |
| `System.IO.Compression.CompressionLevel` | Compression settings |
| `System.IO.File` | Direct file byte reading |
| `System.IO.StreamWriter` | Writing to ZIP streams |
| `System.Text.Encoding` | UTF-8 text encoding |
| `System.Security.Cryptography.SHA256` | Hash calculation |
| `System.Collections.ArrayList` | Dynamic collections |
| `System.Security.Principal.WindowsPrincipal` | Admin check |
| `System.Security.Principal.WindowsIdentity` | Current user identity |

### 6.2 WMI/CIM Classes

| Class | Data Retrieved |
|-------|----------------|
| `Win32_OperatingSystem` | OS information |
| `Win32_ComputerSystem` | Computer information |
| `Win32_BIOS` | BIOS/firmware info |
| `Win32_Process` | Running processes |
| `Win32_Service` | Windows services |
| `Win32_LogicalDisk` | Disk information |
| `Win32_UserProfile` | User profiles |
| `Win32_SystemDriver` | Kernel drivers |
| `Win32_PageFileUsage` | Page file info |
| `__EventFilter` | WMI event filters |
| `__EventConsumer` | WMI consumers |
| `__FilterToConsumerBinding` | WMI bindings |

### 6.3 External Commands

| Command | Purpose |
|---------|---------|
| `wevtutil epl` | Export event logs to EVTX |
| `reg export` | Export registry keys |
| `esentutl /y /d /o` | Copy locked ESE databases |
| `quser` | List active user sessions |
| `netstat -ano` | Raw network connections |

---

## 7. Registry Paths Accessed

### 7.1 HKEY_LOCAL_MACHINE (HKLM)

```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR
HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings
HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

### 7.2 HKEY_CURRENT_USER (HKCU)

```
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
```

### 7.3 HKEY_USERS (HKU)

```
HKU:\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
```

### 7.4 Raw Hive Files Collected

```
%SystemRoot%\System32\config\SOFTWARE
%SystemRoot%\System32\config\SYSTEM
C:\Users\*\NTUSER.DAT
C:\Users\*\AppData\Local\Microsoft\Windows\UsrClass.dat
```

---

## 8. Event Log Queries

### 8.1 FilterHashtable Queries

```powershell
# Logon Events
@{LogName='Security'; Id=4624,4625,4648} -MaxEvents 5000

# Process Creation
@{LogName='Security'; Id=4688} -MaxEvents 5000

# Kerberos/NTLM
@{LogName='Security'; Id=4768,4769,4776} -MaxEvents 2000

# Service Installation
@{LogName='Security'; Id=4697} -MaxEvents 500
@{LogName='System'; Id=7045} -MaxEvents 500

# Scheduled Tasks
@{LogName='Security'; Id=4698,4702} -MaxEvents 500

# RDP Sessions
@{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25} -MaxEvents 1000
```

---

## 9. File System Locations

### 9.1 System Locations

| Path | Content |
|------|---------|
| `%SystemRoot%\Prefetch\` | Prefetch files (.pf) |
| `%SystemRoot%\AppCompat\Programs\` | Amcache.hve |
| `%SystemRoot%\System32\sru\` | SRUDB.dat |
| `%SystemRoot%\System32\Tasks\` | Scheduled task XML |
| `%SystemRoot%\System32\config\` | Registry hives |
| `%SystemRoot%\System32\drivers\etc\hosts` | Hosts file |
| `%SystemRoot%\System32\LogFiles\Firewall\` | Firewall log |
| `%SystemRoot%\Temp\` | System temp |
| `%ProgramData%\Microsoft\Windows Defender\Support\` | Defender logs |

### 9.2 User Profile Locations

| Path | Content |
|------|---------|
| `%USERPROFILE%\NTUSER.DAT` | User registry hive |
| `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` | User class registry |
| `%APPDATA%\Microsoft\Windows\Recent\` | Recent files (LNK) |
| `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Jump lists |
| `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\` | Jump lists |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` | User startup |
| `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\` | PowerShell history |
| `%LOCALAPPDATA%\Google\Chrome\User Data\` | Chrome data |
| `%LOCALAPPDATA%\Microsoft\Edge\User Data\` | Edge data |
| `%APPDATA%\Mozilla\Firefox\Profiles\` | Firefox data |
| `%LOCALAPPDATA%\ConnectedDevicesPlatform\` | Windows Timeline |

---

## 10. Security Considerations

### 10.1 What NovaTrace Does NOT Collect

| Excluded | Location | Reason |
|----------|----------|--------|
| SAM Hive | `%SystemRoot%\System32\config\SAM` | Contains password hashes |
| SECURITY Hive | `%SystemRoot%\System32\config\SECURITY` | Contains LSA secrets |
| Browser Passwords | Various locations | Credential theft prevention |
| Credential Manager | Windows Vault | Stored credentials |
| DPAPI Keys | `%APPDATA%\Microsoft\Protect\` | Encryption keys |
| Private Keys | Certificate stores | Authentication secrets |
| Memory Dumps | Various | May contain credentials |

### 10.2 Read-Only Operations

All collection operations are read-only:
- No files are modified
- No registry keys are changed
- No services are started/stopped
- No network connections are made

### 10.3 Hash Verification

Every collected file is hashed with SHA256:
```powershell
$hash = (Get-FileHash -Path $SourcePath -Algorithm SHA256).Hash
# or
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash($bytes)
```

Hashes are stored in `FileHashes.csv` for evidence integrity verification.

---

## Appendix A: Complete Cmdlet Reference

| Cmdlet | Module | Purpose |
|--------|--------|---------|
| `Get-CimInstance` | CimCmdlets | WMI queries |
| `Invoke-CimMethod` | CimCmdlets | WMI method calls |
| `Get-LocalUser` | Microsoft.PowerShell.LocalAccounts | Local users |
| `Get-LocalGroup` | Microsoft.PowerShell.LocalAccounts | Local groups |
| `Get-LocalGroupMember` | Microsoft.PowerShell.LocalAccounts | Group members |
| `Get-Process` | Microsoft.PowerShell.Management | Process list |
| `Get-Service` | Microsoft.PowerShell.Management | Services |
| `Get-NetTCPConnection` | NetTCPIP | TCP connections |
| `Get-NetUDPEndpoint` | NetTCPIP | UDP endpoints |
| `Get-NetRoute` | NetTCPIP | Routing table |
| `Get-NetNeighbor` | NetTCPIP | ARP cache |
| `Get-NetIPConfiguration` | NetTCPIP | IP configuration |
| `Get-NetFirewallRule` | NetSecurity | Firewall rules |
| `Get-DnsClientCache` | DnsClient | DNS cache |
| `Get-SmbShare` | SmbShare | SMB shares |
| `Get-SmbSession` | SmbShare | SMB sessions |
| `Get-ScheduledTask` | ScheduledTasks | Scheduled tasks |
| `Get-ScheduledTaskInfo` | ScheduledTasks | Task run info |
| `Get-BitsTransfer` | BitsTransfer | BITS jobs |
| `Get-WinEvent` | Microsoft.PowerShell.Diagnostics | Event logs |
| `Get-HotFix` | Microsoft.PowerShell.Management | Windows updates |
| `Get-TimeZone` | Microsoft.PowerShell.Management | Time zone |
| `Get-AuthenticodeSignature` | Microsoft.PowerShell.Security | Code signing |
| `Get-FileHash` | Microsoft.PowerShell.Utility | File hashing |
| `Get-MpComputerStatus` | Defender | Defender status |
| `Get-MpPreference` | Defender | Defender settings |
| `Get-MpThreatDetection` | Defender | Threat history |
| `Get-ItemProperty` | Microsoft.PowerShell.Management | Registry values |
| `Get-ChildItem` | Microsoft.PowerShell.Management | Directory listing |
| `Get-Content` | Microsoft.PowerShell.Management | File content |
| `Get-Item` | Microsoft.PowerShell.Management | File info |
| `Copy-Item` | Microsoft.PowerShell.Management | File copy |
| `ConvertTo-Csv` | Microsoft.PowerShell.Utility | CSV conversion |

---

## Appendix B: Error Handling Strategy

All collection operations use consistent error handling:

```powershell
try {
    # Collection operation
    $result = & $Action
    $script:Stats.Success++
} catch {
    Write-Log "$Name - $($_.Exception.Message)" "ERROR"
    $script:Stats.Failed++
}
```

**Philosophy**: Collection should never fail completely. Individual artifact failures are logged but don't stop the overall collection.

---

## Document Information

- **Version**: 1.0.0
- **Last Updated**: 25/01/2026
- **Author**: Prasanth
- **License**: BSD-3-Clause

This documentation is provided for educational and transparency purposes. Understanding exactly what the tool does helps security professionals make informed decisions about its use in their environments.
