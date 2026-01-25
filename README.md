<p align="center">
  <img src="assets/novatrace-logo.svg" alt="NovaTrace" width="140">
</p>

<h1 align="center">NovaTrace IR Kit</h1>

<p align="center">
  <strong>Forensic Evidence Collector for Windows Incident Response</strong><br>
  One script. 50+ artifact types. Zero dependencies. Direct-to-ZIP.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Windows-10%2F11%2FServer-0078D6?style=flat-square&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell">
  <img src="https://img.shields.io/badge/License-BSD--3--Clause-green?style=flat-square" alt="License">
</p>

<p align="center">
  <a href="#about">About</a> &nbsp;&bull;&nbsp;
  <a href="#quick-start">Quick Start</a> &nbsp;&bull;&nbsp;
  <a href="#artifacts-collected">Artifacts</a> &nbsp;&bull;&nbsp;
  <a href="#parsing-collected-evidence">Parsing</a> &nbsp;&bull;&nbsp;
  <a href="#documentation">Docs</a> &nbsp;&bull;&nbsp;
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## About

### What is NovaTrace?

**NovaTrace IR Kit** is a lightweight, single-file PowerShell forensic evidence collector purpose-built for Windows incident response. It automates the collection of 50+ forensic artifact types, packaging them into a single ZIP archive for offline analysis with industry-standard tools like those from Eric Zimmerman.

Unlike traditional forensic tools that require installation or complex deployment, NovaTrace is designed for rapid deployment scenarios where time is critical and system access may be limited - such as Microsoft Defender EDR Live Response sessions.

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **Comprehensive Collection** | Gathers 50+ artifact types across 12 forensic categories |
| **Zero Dependencies** | Single PowerShell script - no installation, no external modules |
| **Direct-to-ZIP** | Writes directly to compressed archive, minimizing disk footprint |
| **Live Response Optimized** | Designed for Microsoft Defender EDR Live Response constraints |
| **Forensically Sound** | Read-only operations with SHA256 hash verification |
| **Locked File Support** | Multiple methods to copy in-use files (Amcache, SRUM, browser DBs) |

<details>
<summary><b>Why NovaTrace?</b></summary>

During an incident, responders face critical challenges:

| Challenge | Problem |
|-----------|---------|
| **Time pressure** | Evidence must be collected before it's lost or overwritten |
| **Tool deployment** | Installing forensic tools on compromised systems is risky |
| **Live Response limits** | Remote collection tools have restrictions on what can be deployed |
| **Consistency** | Manual collection leads to gaps and inconsistencies |
| **Storage constraints** | Limited disk space on target systems |

**NovaTrace solves these by:**
- Collecting all critical artifacts in a single execution (under 5 minutes direct, under 10 minutes via Live Response)
- Requiring no installation - just one PowerShell script
- Being optimized for Microsoft Defender EDR Live Response
- Providing consistent, comprehensive collection every time
- Writing directly to ZIP to minimize disk usage
- Generating SHA256 hash manifests for evidence integrity

</details>

<details>
<summary><b>What It Collects</b></summary>

NovaTrace gathers forensic artifacts across 12 categories:

| Category | Artifacts |
|----------|-----------|
| **System** | OS info, hardware, installed software, drivers, USB history |
| **Users** | Local accounts, groups, profiles, active sessions |
| **Processes** | Running processes with command lines, loaded DLLs, services |
| **Network** | TCP/UDP connections, DNS cache, ARP, routes, SMB shares |
| **Persistence** | Run keys, scheduled tasks, WMI subscriptions, startup items |
| **Execution** | Prefetch, Amcache, ShimCache, BAM, UserAssist, SRUM |
| **Registry** | Raw hives (SOFTWARE, SYSTEM, NTUSER.DAT) |
| **File System** | Jump lists, LNK files, Recycle Bin, Windows Timeline |
| **Browser** | History from Chrome, Edge, Firefox (no credentials collected) |
| **Event Logs** | Security, System, PowerShell, Defender, Sysmon, and more |
| **Parsed Events** | Pre-parsed logons, process creation, RDP, service installs |
| **Security** | Defender status, exclusions, detections, firewall rules |

</details>

<details>
<summary><b>What It Does NOT Collect</b></summary>

NovaTrace is designed with security in mind and explicitly **does NOT collect**:

| Excluded | Reason |
|----------|--------|
| SAM registry hive | Contains password hashes |
| SECURITY registry hive | Contains LSA secrets and cached credentials |
| Browser saved passwords | Credential theft prevention |
| Windows Credential Manager | Stored credentials |
| DPAPI master keys | Encryption key material |
| Private keys/certificates | Authentication secrets |
| Memory dumps | May contain credentials |

</details>

---

## Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later (built into Windows)
- Administrator privileges recommended for full collection

### Running Directly on a Computer

```powershell
# Option 1: Simple execution (run as Administrator for full collection)
.\NovaTrace.ps1

# Option 2: Custom output location
.\NovaTrace.ps1 -OutputPath "D:\Evidence"

# Option 3: If execution policy blocks the script
powershell -ExecutionPolicy Bypass -File .\NovaTrace.ps1
```

**Output:**
```
NovaTrace_HOSTNAME_YYYYMMDD_HHMMSS.zip    # Single compressed archive
```

> **Note:** v1.0.0 writes directly to ZIP - no temporary folder is created.

---

### Running via Microsoft Defender EDR Live Response

```powershell
# Step 1: Upload the script to the target machine
putfile NovaTrace.ps1

# Step 2: Execute the collection
run NovaTrace.ps1

# Step 3: Wait for completion (typically 7-10 minutes)
# The script will display the exact getfile command when done

# Step 4: Download the evidence archive
getfile "C:\NovaTrace_HOSTNAME_YYYYMMDD_HHMMSS.zip"

# Step 5 (Optional): Clean up after download
remediate file "C:\NovaTrace_HOSTNAME_YYYYMMDD_HHMMSS.zip"
```

**Live Response Notes:**
- Script auto-detects Live Response environment
- Output is always written to `C:\` drive root
- Single ZIP file created - easy to download
- The exact `getfile` command is displayed when collection completes

---

### Remote Execution Options

```powershell
# Via PowerShell Remoting
Invoke-Command -ComputerName TARGET -FilePath .\NovaTrace.ps1

# Via PsExec (runs as SYSTEM)
psexec \\TARGET -s powershell -ExecutionPolicy Bypass -File C:\NovaTrace.ps1

# Via WMI
wmic /node:TARGET process call create "powershell -ExecutionPolicy Bypass -File C:\NovaTrace.ps1"
```

---

## Artifacts Collected

<details>
<summary><b>System Information</b> (9 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| System Info | OS, hostname, domain, build, install date, last boot, VM detection | `System/SystemInfo.csv` |
| Memory Info | Physical memory, page file configuration, usage | `System/MemoryInfo.csv` |
| Installed Software | Programs from registry uninstall keys | `System/InstalledSoftware.csv` |
| Hotfixes | Windows updates with install dates | `System/Hotfixes.csv` |
| Drivers | Kernel and system drivers with paths | `System/Drivers.csv` |
| Environment Variables | System and user environment | `System/EnvironmentVariables.csv` |
| USB Device History | Previously connected USB storage devices | `System/USBDevices.csv` |
| Disk Information | Drives, capacity, free space | `System/Disks.csv` |
| Temp Directory Contents | Files in Windows and user temp folders | `FileSystem/TempDirectoryContents.csv` |

</details>

<details>
<summary><b>User Accounts</b> (5 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Local Users | All local accounts with status, last logon | `Users/LocalUsers.csv` |
| Local Groups | Security groups on the system | `Users/LocalGroups.csv` |
| Group Memberships | Members of each local group | `Users/LocalGroupMembers.csv` |
| User Profiles | Profile paths and last use times | `Users/UserProfiles.csv` |
| Active Sessions | Currently logged on users (via quser) | `Users/ActiveUsers.csv` |

</details>

<details>
<summary><b>Processes and Services</b> (3 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Running Processes | Full process list with PID, PPID, command line, owner, path, signature status | `Processes/Processes.csv` |
| Process Modules | DLLs loaded by each process | `Processes/ProcessModules.csv` |
| Services | Windows services with state, start mode, path, account | `Processes/Services.csv` |

</details>

<details>
<summary><b>Network</b> (12 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| TCP Connections | All TCP connections with process info | `Network/TCPConnections.csv` |
| UDP Endpoints | UDP listening endpoints with process info | `Network/UDPEndpoints.csv` |
| Listening Ports | Services accepting connections | `Network/ListeningPorts.csv` |
| Netstat Raw | Raw netstat -ano output | `Network/netstat_raw.txt` |
| DNS Cache | Resolved domain names | `Network/DNSCache.csv` |
| ARP Cache | IP to MAC address mappings | `Network/ARPCache.csv` |
| Routes | Routing table | `Network/Routes.csv` |
| IP Configuration | Interface IPs, gateways, DNS servers | `Network/IPConfiguration.csv` |
| Hosts File | Local DNS overrides | `Network/hosts.txt` |
| Firewall Log | Windows Firewall log (if enabled) | `Network/pfirewall.log` |
| SMB Shares | Local file shares | `Network/SMBShares.csv` |
| SMB Sessions | Active SMB connections | `Network/SMBSessions.csv` |

</details>

<details>
<summary><b>Persistence Mechanisms</b> (9 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Registry Run Keys | Auto-start programs | `Persistence/RegistryRunKeys.csv` |
| Scheduled Tasks | Task Scheduler entries | `Persistence/ScheduledTasks.csv` |
| Task XML Files | Raw scheduled task definitions (Admin) | `Persistence/TaskFiles/` |
| WMI Subscriptions | WMI event filters, consumers, bindings | `Persistence/WMI_*.csv` |
| Startup Folder | Programs in startup locations | `Persistence/StartupFolder.csv` |
| BITS Jobs | Background transfer jobs | `Persistence/BITSJobs.csv` |
| Winlogon | Shell, userinit, taskman values | `Persistence/Winlogon.csv` |
| Image File Execution Options | Debugger hijacks | `Persistence/IFEO.csv` |
| AppInit DLLs | DLL injection points | `Persistence/AppInitDLLs.csv` |

</details>

<details>
<summary><b>Execution Artifacts</b> (8 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Prefetch | Application execution history | `Execution/Prefetch.csv` + raw .pf files |
| Amcache.hve | Application installation and execution | `Execution/Amcache.hve` |
| ShimCache | Program execution evidence | `Execution/ShimCache.reg` |
| BAM/DAM | Background Activity Moderator data | `Execution/BAM.csv` |
| UserAssist | GUI program execution counts | `Execution/UserAssist.csv` |
| SRUM | System Resource Usage Monitor (Admin) | `Execution/SRUDB.dat` |
| PowerShell History | Console command history per user | `Execution/PSHistory_*.txt` |
| Recent Commands | Run dialog MRU | `Execution/RecentCommands.csv` |

</details>

<details>
<summary><b>Registry Hives</b> (5 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| SOFTWARE | System-wide software settings (Admin) | `Registry/SOFTWARE` |
| SYSTEM | Hardware and service configuration (Admin) | `Registry/SYSTEM` |
| NTUSER.DAT | Per-user settings | `Registry/NTUSER_*.DAT` |
| UsrClass.dat | User shell settings | `Registry/UsrClass_*.dat` |
| Registry Exports | Run keys, services, USB history | `Registry/*.reg` |

</details>

<details>
<summary><b>File System Artifacts</b> (4 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Jump Lists | Recent/frequent files per application | `FileSystem/JumpLists/` |
| LNK Files | Shortcut metadata and targets | `FileSystem/LNK/` + `LNK_Metadata.csv` |
| Recycle Bin | Deleted file metadata | `FileSystem/RecycleBin.csv` |
| Windows Timeline | Activity history database | `FileSystem/ActivitiesCache_*.db` |

</details>

<details>
<summary><b>Browser History</b> (3 artifacts)</summary>

| Browser | Data Collected | Output |
|---------|----------------|--------|
| Chrome | History database (no passwords) | `Browser/*/Chrome/*/History` |
| Edge | History database (no passwords) | `Browser/*/Edge/*/History` |
| Firefox | places.sqlite (no passwords) | `Browser/*/Firefox/*/places.sqlite` |

</details>

<details>
<summary><b>Event Logs</b> (11+ artifacts)</summary>

| Log | Description | Output |
|-----|-------------|--------|
| Security | Authentication, process creation (Admin) | `EventLogs/Security.evtx` |
| System | Services, drivers, errors (Admin) | `EventLogs/System.evtx` |
| Application | Application events (Admin) | `EventLogs/Application.evtx` |
| PowerShell Operational | Script execution (Admin) | `EventLogs/PowerShell-Operational.evtx` |
| Task Scheduler | Scheduled task execution | `EventLogs/TaskScheduler.evtx` |
| Windows Defender | Malware detections | `EventLogs/Defender.evtx` |
| WinRM | Remote management | `EventLogs/WinRM.evtx` |
| Terminal Services | RDP sessions | `EventLogs/TerminalServices*.evtx` |
| Sysmon | Advanced process monitoring (if installed) | `EventLogs/Sysmon.evtx` |
| WMI Activity | WMI operations | `EventLogs/WMI-Activity.evtx` |
| BITS Client | Background transfers | `EventLogs/Bits-Client.evtx` |
| Defender Support Logs | Diagnostic logs (Admin) | `EventLogs/DefenderLogs/` |

</details>

<details>
<summary><b>Parsed Security Events</b> (6 artifacts)</summary>

| Artifact | Event IDs | Output |
|----------|-----------|--------|
| Logon Events | 4624, 4625, 4648 | `Security/SecurityEvents_Logons.csv` |
| Process Creation | 4688 | `Security/SecurityEvents_ProcessCreation.csv` |
| Kerberos/NTLM | 4768, 4769, 4776 | `Security/SecurityEvents_Kerberos_NTLM.csv` |
| RDP Sessions | 21, 22, 23, 24, 25 | `Security/RDP_Events.csv` |
| Service Installation | 4697, 7045 | `Security/ServiceInstallationEvents.csv` |
| Scheduled Task Events | 4698, 4702 | `Security/ScheduledTaskEvents.csv` |

</details>

<details>
<summary><b>Security Status</b> (4 artifacts)</summary>

| Artifact | Description | Output |
|----------|-------------|--------|
| Defender Status | Protection state, signatures (Admin) | `Security/DefenderStatus.csv` |
| Defender Exclusions | Configured exclusions (Admin) | `Security/DefenderExclusions.csv` |
| Defender Detections | Recent threat detections (Admin) | `Security/DefenderDetections.csv` |
| Firewall Rules | Enabled firewall rules | `Security/FirewallRules.csv` |

</details>

---

## Output Structure

```
NovaTrace_HOSTNAME_YYYYMMDD_HHMMSS.zip
├── System/           # OS, hardware, software, drivers
├── Users/            # Accounts, groups, profiles
├── Processes/        # Running processes, services
├── Network/          # Connections, DNS, configuration
├── Persistence/      # Run keys, tasks, WMI, startup
├── Execution/        # Prefetch, Amcache, ShimCache, BAM
├── Registry/         # Raw hives (SOFTWARE, SYSTEM, NTUSER)
├── FileSystem/       # Jump lists, LNK, Recycle Bin, Timeline
├── Browser/          # History databases per user/browser
├── EventLogs/        # Raw EVTX files + Defender logs
├── Security/         # Parsed events + Defender status
├── FileHashes.csv    # SHA256 manifest of all collected files
├── Manifest.csv      # Collection metadata and statistics
├── README.txt        # Collection summary
├── novatrace.log     # Execution log
└── errors.log        # Error log (if any errors occurred)
```

---

## Parsing Collected Evidence

### Recommended Tools by Artifact Type

| Artifact | Tool | Command |
|----------|------|---------|
| **Prefetch (.pf)** | [PECmd](https://github.com/EricZimmerman/PECmd) | `PECmd.exe -d "Execution\Prefetch" --csv output` |
| **Amcache.hve** | [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser) | `AmcacheParser.exe -f "Execution\Amcache.hve" --csv output` |
| **ShimCache** | [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) | `AppCompatCacheParser.exe -f "Execution\ShimCache.reg" --csv output` |
| **SRUDB.dat** | [SrumECmd](https://github.com/EricZimmerman/Srum) | `SrumECmd.exe -f "Execution\SRUDB.dat" --csv output` |
| **Registry Hives** | [Registry Explorer](https://github.com/EricZimmerman/RegistryExplorer) | GUI - Open hive files directly |
| **Event Logs (.evtx)** | [EvtxECmd](https://github.com/EricZimmerman/evtx) | `EvtxECmd.exe -d "EventLogs" --csv output` |
| **Jump Lists** | [JLECmd](https://github.com/EricZimmerman/JLECmd) | `JLECmd.exe -d "FileSystem\JumpLists" --csv output` |
| **LNK Files** | [LECmd](https://github.com/EricZimmerman/LECmd) | `LECmd.exe -d "FileSystem\LNK" --csv output` |
| **Browser History** | [Hindsight](https://github.com/nicoleibrahim/hindsight) | `hindsight.py -i "Browser\username\Chrome\Default"` |
| **Timeline DB** | [WxTCmd](https://github.com/EricZimmerman/WxTCmd) | `WxTCmd.exe -f "ActivitiesCache.db" --csv output` |
| **View CSV Results** | [Timeline Explorer](https://github.com/EricZimmerman/TimelineExplorer) | GUI - Open parsed CSV files |

### Quick Analysis Workflow

```powershell
# 1. Extract the ZIP
Expand-Archive -Path "NovaTrace_HOSTNAME_*.zip" -DestinationPath ".\Evidence"

# 2. Parse key artifacts
PECmd.exe -d ".\Evidence\Execution\Prefetch" --csv ".\Parsed"
AmcacheParser.exe -f ".\Evidence\Execution\Amcache.hve" --csv ".\Parsed"
EvtxECmd.exe -d ".\Evidence\EventLogs" --csv ".\Parsed"

# 3. Open results in Timeline Explorer
TimelineExplorer.exe ".\Parsed"
```

### Download All Eric Zimmerman Tools

**https://ericzimmerman.github.io/**

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile "Get-ZimmermanTools.ps1"
.\Get-ZimmermanTools.ps1 -Dest "C:\Tools\EZTools"
```

---

## Documentation

<details>
<summary><b>Admin vs Non-Admin Collection</b></summary>

| Requires Admin | Works Without Admin |
|----------------|---------------------|
| Registry hives (SOFTWARE, SYSTEM) | User registry (NTUSER.DAT) |
| Prefetch files | Process list |
| Security event log | Network connections |
| SRUM database | DNS cache |
| Defender status/exclusions | Browser history |
| Scheduled task XML files | Basic scheduled tasks |
| Defender support logs | Most persistence checks |

**Recommendation:** Always run as Administrator for complete collection.

</details>

<details>
<summary><b>Performance Benchmarks</b></summary>

| Execution Method | Time |
|------------------|------|
| Direct Execution (Windows Client) | 5-7 min |
| Defender EDR Live Response | 7-10 min |

Evidence collection on systems with larger event logs may take a few extra minutes.

</details>

<details>
<summary><b>Troubleshooting</b></summary>

**Execution Policy Error:**
```powershell
powershell -ExecutionPolicy Bypass -File .\NovaTrace.ps1
```

**Live Response Script Not Running:**
```
putfile NovaTrace.ps1
run NovaTrace.ps1
```

**ZIP File Creation Fails:**
- Ensure sufficient disk space (at least 500 MB free)
- Check write permissions to output directory
- Try specifying a different output path: `.\NovaTrace.ps1 -OutputPath "D:\Evidence"`

**Partial Collection:**
- Some artifacts require Administrator privileges
- Check `errors.log` inside the ZIP for specific failures
- Review `Manifest.csv` for collection statistics

</details>

<details>
<summary><b>FAQ</b></summary>

**Will this trigger antivirus?**
> Generally no. NovaTrace uses only native PowerShell cmdlets. However, some EDR solutions may flag bulk file copying or registry access. Test in your environment first.

**Is this forensically sound?**
> Yes. NovaTrace performs read-only operations and generates SHA256 hashes for all collected files in `FileHashes.csv`.

**Does it collect credentials or passwords?**
> No. SAM hive, SECURITY hive, browser passwords, and credential manager data are explicitly NOT collected.

**Can I customize what's collected?**
> The current version collects a fixed set of artifacts. Future versions may support collection profiles.

**What if the script is interrupted?**
> A partial ZIP file may remain. Re-run the script for a complete collection.

</details>

---

## Forensically Sound Guarantees

| Guarantee | Description |
|-----------|-------------|
| **No modifications** | System files and registry are not modified |
| **No deletions** | Nothing is deleted from the target system |
| **No network traffic** | All operations are local |
| **Read-only operations** | Data is only read, never written to source locations |
| **Hash verification** | SHA256 manifest for all collected files |
| **Output isolation** | All evidence contained in single ZIP archive |

---

## Credits & Acknowledgments

NovaTrace builds on the collective knowledge of the DFIR community:

- **[Eric Zimmerman](https://ericzimmerman.github.io/)** - His forensic tools set the standard for Windows artifact parsing
- **DFIR Community** - Shared research on Windows forensic artifacts and methodologies
- **Blue Team practitioners** - Real-world incident response insights and feedback

---

## License

BSD-3-Clause - See [LICENSE](LICENSE) for details.

```
Copyright (c) 2025 Prasanth
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
...
```

---

## Disclaimer

> **IMPORTANT: Please read before using this tool.**

### Important Warnings

| Warning | Description |
|-----------|-------------|
| **Test First** | Always test in a development or lab environment before running on production systems |
| **Get Authorization** | Obtain proper written authorization before collecting evidence from any system |
| **Chain of Custody** | Follow your organization's evidence handling procedures |
| **Legal Compliance** | Ensure compliance with applicable laws, regulations, and policies |
| **Data Sensitivity** | Collected data may contain sensitive information - handle appropriately |

### Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors and contributors are **NOT responsible** for any misuse, damage, or legal consequences resulting from the use of this tool. **You assume full responsibility** for ensuring that your use complies with all applicable laws and regulations.

By using this tool, you acknowledge that you have read, understood, and agree to these terms.

### Authorized Use Only

This tool is designed **exclusively for legitimate purposes** including:

- **Incident Response** - Authorized security investigations by IR teams
- **Digital Forensics** - Evidence collection with proper legal authority
- **Security Research** - Educational purposes in controlled lab environments
- **System Administration** - Authorized troubleshooting on systems you own or manage

### Prohibited Uses

- **Unauthorized access** to computer systems
- **Privacy violations** or surveillance without consent
- **Malicious activities** of any kind
- **Violation of laws** or organizational policies

---

<p align="center">
  <sub>NovaTrace IR Kit v1.0.0 | Built with ❤️ by Prasanth</sub>
</p>

<p align="center">
  <sub>Use responsibly and only on systems you are authorized to investigate.</sub>
</p>
