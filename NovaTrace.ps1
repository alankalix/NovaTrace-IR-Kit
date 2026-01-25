<#
.SYNOPSIS
    NovaTrace IR Kit v1.0.0
    Enterprise Forensic Evidence Collector for Windows
    
.DESCRIPTION
    Comprehensive forensic artifact collection optimized for incident response.
    Collects 50+ artifact types for offline analysis.
    Designed for rapid deployment in enterprise environments.
    Optimized for Microsoft Defender EDR Live Response.
    Writes directly to ZIP file to minimize disk footprint.
    
.NOTES
    Version: 1.0.0
    Author: Prasanth
    License: BSD-3-Clause
    Tested: Windows 10/11, Server 2016+
    
.EXAMPLE
    .\NovaTrace.ps1
    
.EXAMPLE
    .\NovaTrace.ps1 -OutputPath "D:\Evidence"
    
.LINK
    https://github.com/alankalix/NovaTrace-IR-Kit
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$env:POWERSHELL_UPDATECHECK = 'Off'

#region Initialization
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$StartTime = Get-Date
$Hostname = $env:COMPUTERNAME
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$IsLiveResponse = $PSScriptRoot -like "*Windows Defender Advanced Threat Protection*"

$ZipName = "NovaTrace_${Hostname}_${Timestamp}.zip"
if ($OutputPath) {
    $script:ZipPath = Join-Path $OutputPath $ZipName
} elseif ($IsLiveResponse) {
    $script:ZipPath = "C:\$ZipName"
} else {
    $script:ZipPath = Join-Path $PSScriptRoot $ZipName
}

$script:TempPath = Join-Path $env:TEMP "NovaTrace_$Timestamp"
$null = New-Item -ItemType Directory -Path $script:TempPath -Force -ErrorAction SilentlyContinue

$script:Stats = @{ Total = 0; Success = 0; Failed = 0; Skipped = 0 }
$script:FileHashes = [System.Collections.ArrayList]::new()
$script:LogEntries = [System.Collections.ArrayList]::new()
$script:ErrorEntries = [System.Collections.ArrayList]::new()

$Folders = @{
    Network     = "Network"
    Processes   = "Processes"
    Persistence = "Persistence"
    Execution   = "Execution"
    Registry    = "Registry"
    FileSystem  = "FileSystem"
    Browser     = "Browser"
    EventLogs   = "EventLogs"
    Users       = "Users"
    System      = "System"
    Security    = "Security"
}

try {
    $script:ZipArchive = [System.IO.Compression.ZipFile]::Open($script:ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
} catch {
    Write-Host "  [!] Failed to create ZIP file: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Helper Functions
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    $color = switch ($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} "OK" {"Green"} default {"Cyan"} }
    Write-Host $line -ForegroundColor $color
    $null = $script:LogEntries.Add($line)
    if ($Level -eq "ERROR") { $null = $script:ErrorEntries.Add($line) }
}

function Invoke-Collect {
    param([string]$Name, [scriptblock]$Action, [switch]$Admin, [switch]$Silent)
    $script:Stats.Total++
    $script:CurrentStep++
    if (-not $Silent) { Show-Progress -Task $Name }
    if ($Admin -and -not $IsAdmin) {
        Write-Log "$Name - Skipped (requires admin)" "WARN"
        $script:Stats.Skipped++
        if (-not $Silent) { Show-Result -Name $Name -Found $false -Detail "(requires admin)" }
        return
    }
    try {
        $result = & $Action
        Write-Log "$Name" "OK"
        $script:Stats.Success++
        $found = ($result -ne $false -and $result -ne 0 -and $null -ne $result)
        if (-not $Silent) { Show-Result -Name $Name -Found $found }
    } catch {
        Write-Log "$Name - $($_.Exception.Message)" "ERROR"
        $script:Stats.Failed++
        if (-not $Silent) { Show-Result -Name $Name -Found $false -Detail "(error)" }
    }
}

function Add-ToZip {
    param([string]$EntryPath, [string]$Content, [byte[]]$Bytes)
    try {
        $entry = $script:ZipArchive.CreateEntry($EntryPath, [System.IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        if ($Content) {
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.Encoding]::UTF8)
            $writer.Write($Content)
            $writer.Close()
        } elseif ($Bytes) {
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Close()
        }
        return $true
    } catch { return $false }
}

function Add-FileToZip {
    param([string]$SourcePath, [string]$EntryPath)
    if (-not (Test-Path $SourcePath)) { return $false }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($SourcePath)
        $entry = $script:ZipArchive.CreateEntry($EntryPath, [System.IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $hash = (Get-FileHash -Path $SourcePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $file = Get-Item -Path $SourcePath -ErrorAction Stop
        $null = $script:FileHashes.Add([PSCustomObject]@{
            FileName = $file.Name; RelativePath = $EntryPath; SizeBytes = $file.Length
            SHA256 = $hash; CollectedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
        return $true
    } catch { return $false }
}

function Save-ToCSV {
    param([object]$Data, [string]$EntryPath)
    if ($null -eq $Data) { return $false }
    $dataArray = @($Data)
    if ($dataArray.Count -eq 0) { return $false }
    try {
        $csvContent = ($Data | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
        Add-ToZip -EntryPath $EntryPath -Content $csvContent
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($csvContent)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($bytes)
        $hash = [BitConverter]::ToString($hashBytes) -replace '-', ''
        $null = $script:FileHashes.Add([PSCustomObject]@{
            FileName = Split-Path $EntryPath -Leaf; RelativePath = $EntryPath; SizeBytes = $bytes.Length
            SHA256 = $hash; CollectedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
        return $true
    } catch { return $false }
}

function Copy-LockedFile {
    param([string]$Source, [string]$EntryPath)
    if (-not (Test-Path $Source)) { return $false }
    $tempDest = Join-Path $script:TempPath (Split-Path $Source -Leaf)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Source)
        $entry = $script:ZipArchive.CreateEntry($EntryPath, [System.IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($bytes)
        $hash = [BitConverter]::ToString($hashBytes) -replace '-', ''
        $null = $script:FileHashes.Add([PSCustomObject]@{
            FileName = Split-Path $Source -Leaf; RelativePath = $EntryPath; SizeBytes = $bytes.Length
            SHA256 = $hash; CollectedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
        return $true
    } catch {}
    $copied = $false
    try { Copy-Item -Path $Source -Destination $tempDest -Force -ErrorAction Stop; $copied = $true } catch {}
    if (-not $copied) {
        try { $null = & esentutl /y $Source /d $tempDest /o 2>&1; if (Test-Path $tempDest) { $copied = $true } } catch {}
    }
    if ($copied -and (Test-Path $tempDest)) {
        $result = Add-FileToZip -SourcePath $tempDest -EntryPath $EntryPath
        Remove-Item -Path $tempDest -Force -ErrorAction SilentlyContinue
        return $result
    }
    return $false
}

function Add-TextToZip {
    param([string]$EntryPath, [string]$Content)
    Add-ToZip -EntryPath $EntryPath -Content $Content
}
#endregion

#region Display Functions
$script:C = @{ Title = 'Cyan'; OK = 'Green'; Warn = 'Yellow'; Err = 'Red'; Info = 'White'; Dim = 'DarkGray'; Bar = 'DarkCyan' }
$script:TotalSteps = 52
$script:CurrentStep = 0

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor $script:C.Bar
    Write-Host ""
    Write-Host "              N O V A T R A C E" -ForegroundColor $script:C.Title
    Write-Host "        Forensic Evidence Collector v1.1.0" -ForegroundColor $script:C.Dim
    Write-Host ""
    Write-Host "  =============================================" -ForegroundColor $script:C.Bar
    Write-Host ""
    Write-Host "   Host:   " -NoNewline -ForegroundColor $script:C.Dim
    Write-Host $Hostname -ForegroundColor $script:C.Info
    Write-Host "   Admin:  " -NoNewline -ForegroundColor $script:C.Dim
    $adminTxt = if ($IsAdmin) { "Yes" } else { "No (Limited)" }
    $adminCol = if ($IsAdmin) { $script:C.OK } else { $script:C.Warn }
    Write-Host $adminTxt -ForegroundColor $adminCol
    Write-Host "   Time:   " -NoNewline -ForegroundColor $script:C.Dim
    Write-Host (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -ForegroundColor $script:C.Info
    Write-Host "   Mode:   " -NoNewline -ForegroundColor $script:C.Dim
    Write-Host "Direct to ZIP" -ForegroundColor $script:C.OK
    Write-Host ""
}

function Show-Progress {
    param([string]$Task)
    $pct = [math]::Min(100, [math]::Floor(($script:CurrentStep / $script:TotalSteps) * 100))
    $filled = [math]::Floor(40 * $pct / 100)
    $empty = 40 - $filled
    $bar = "[" + ("=" * $filled) + ("-" * $empty) + "]"
    $elapsed = ((Get-Date) - $StartTime).ToString("mm\:ss")
    $progressText = "  {0} {1}% - {2} - {3}" -f $bar, $pct.ToString().PadLeft(3), $elapsed, $Task.PadRight(30)
    Write-Host ("`r" + $progressText) -NoNewline -ForegroundColor $script:C.Bar
}

function Show-Result {
    param([string]$Name, [bool]$Found, [string]$Detail = "")
    $icon = if ($Found) { "[OK]" } else { "[--]" }
    $color = if ($Found) { $script:C.OK } else { $script:C.Dim }
    Write-Host ("`r  " + $icon + " ") -NoNewline -ForegroundColor $color
    Write-Host $Name.PadRight(40) -NoNewline -ForegroundColor $script:C.Info
    if ($Detail) { Write-Host (" " + $Detail) -ForegroundColor $script:C.Dim } else { Write-Host "" }
}

Show-Banner
Write-Host "  Creating ZIP: $($script:ZipPath)" -ForegroundColor $script:C.Dim
Write-Host ""
Write-Host "  ================================================" -ForegroundColor $script:C.Bar
Write-Host "   COLLECTION IN PROGRESS" -ForegroundColor $script:C.Title
Write-Host "  ================================================" -ForegroundColor $script:C.Bar
Write-Host ""
#endregion

#region System Information
Write-Log "=== SYSTEM INFORMATION ===" "INFO"

Invoke-Collect "System Information" {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
    $tz = Get-TimeZone
    $info = [PSCustomObject]@{
        CollectionTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CollectionTimeUTC = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Hostname = $Hostname; Domain = $env:USERDOMAIN; DomainJoined = $cs.PartOfDomain
        OS = $os.Caption; Version = $os.Version; Build = $os.BuildNumber; Architecture = $os.OSArchitecture
        InstallDate = $os.InstallDate; LastBootTime = $os.LastBootUpTime
        TimeZoneId = $tz.Id; TimeZoneUtcOffset = $tz.BaseUtcOffset.ToString()
        Manufacturer = $cs.Manufacturer; Model = $cs.Model; SerialNumber = $bios.SerialNumber
        IsVirtualMachine = ($cs.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|QEMU|Xen')
        IsAdmin = $IsAdmin; CurrentUser = "$env:USERDOMAIN\$env:USERNAME"
    }
    Save-ToCSV -Data $info -EntryPath "$($Folders.System)/SystemInfo.csv"
}

Invoke-Collect "Memory Information" {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $pageFile = Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue
    $memInfo = [PSCustomObject]@{
        TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        FreePhysicalMemoryMB = [math]::Round($os.FreePhysicalMemory / 1KB, 2)
        MemoryUsagePercent = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 2)
        PageFileLocation = if ($pageFile) { ($pageFile | Select-Object -First 1).Name } else { "N/A" }
        PageFileSizeMB = if ($pageFile) { ($pageFile | Measure-Object -Property AllocatedBaseSize -Sum).Sum } else { 0 }
    }
    Save-ToCSV -Data $memInfo -EntryPath "$($Folders.System)/MemoryInfo.csv"
}

Invoke-Collect "Installed Software" {
    $software = [System.Collections.ArrayList]::new()
    $regPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    foreach ($path in $regPaths) {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if ($item.DisplayName) {
                $null = $software.Add([PSCustomObject]@{
                    DisplayName = $item.DisplayName; DisplayVersion = $item.DisplayVersion
                    Publisher = $item.Publisher; InstallDate = $item.InstallDate; InstallLocation = $item.InstallLocation
                })
            }
        }
    }
    if ($software.Count -gt 0) { Save-ToCSV -Data ($software | Sort-Object DisplayName -Unique) -EntryPath "$($Folders.System)/InstalledSoftware.csv" }
}

Invoke-Collect "Hotfixes" {
    $hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Select-Object HotFixID, Description, InstalledOn, InstalledBy
    if ($hotfixes) { Save-ToCSV -Data $hotfixes -EntryPath "$($Folders.System)/Hotfixes.csv" }
}

Invoke-Collect "Drivers" {
    $drivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, PathName
    Save-ToCSV -Data $drivers -EntryPath "$($Folders.System)/Drivers.csv"
}

Invoke-Collect "Environment Variables" {
    $envVars = [System.Collections.ArrayList]::new()
    Get-ChildItem Env: | ForEach-Object { $null = $envVars.Add([PSCustomObject]@{ Name = $_.Name; Value = $_.Value }) }
    if ($envVars.Count -gt 0) { Save-ToCSV -Data $envVars -EntryPath "$($Folders.System)/EnvironmentVariables.csv" }
}

Invoke-Collect "USB Device History" {
    $usb = [System.Collections.ArrayList]::new()
    $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    if (Test-Path $usbPath) {
        $devices = Get-ChildItem -Path $usbPath -ErrorAction SilentlyContinue
        foreach ($device in $devices) {
            $subDevices = Get-ChildItem -Path $device.PSPath -ErrorAction SilentlyContinue
            foreach ($subDevice in $subDevices) {
                $props = Get-ItemProperty -Path $subDevice.PSPath -ErrorAction SilentlyContinue
                $null = $usb.Add([PSCustomObject]@{ DeviceClass = Split-Path $device.PSPath -Leaf; SerialNumber = Split-Path $subDevice.PSPath -Leaf; FriendlyName = $props.FriendlyName })
            }
        }
    }
    if ($usb.Count -gt 0) { Save-ToCSV -Data $usb -EntryPath "$($Folders.System)/USBDevices.csv" }
}

Invoke-Collect "Disk Information" {
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction SilentlyContinue |
        Select-Object DeviceID, DriveType, FileSystem, @{N='SizeGB';E={[math]::Round($_.Size/1GB,2)}}, @{N='FreeSpaceGB';E={[math]::Round($_.FreeSpace/1GB,2)}}, VolumeName
    if ($disks) { Save-ToCSV -Data $disks -EntryPath "$($Folders.System)/Disks.csv" }
}

Invoke-Collect "Temp Directory Contents" {
    $tempFiles = [System.Collections.ArrayList]::new()
    $tempPaths = @("$env:SystemRoot\Temp", $env:TEMP) | Select-Object -Unique
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            $files = Get-ChildItem -Path $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Select-Object -First 500
            foreach ($file in $files) {
                $null = $tempFiles.Add([PSCustomObject]@{
                    TempDir = $tempPath; Name = $file.Name; FullPath = $file.FullName; IsDirectory = $file.PSIsContainer
                    SizeBytes = if (-not $file.PSIsContainer) { $file.Length } else { $null }
                    Created = $file.CreationTime; Modified = $file.LastWriteTime
                })
            }
        }
    }
    if ($tempFiles.Count -gt 0) { Save-ToCSV -Data $tempFiles -EntryPath "$($Folders.FileSystem)/TempDirectoryContents.csv" }
}
#endregion

#region User Accounts
Write-Log "=== USER ACCOUNTS ===" "INFO"

Invoke-Collect "Local Users" {
    $users = Get-LocalUser -ErrorAction Stop | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description, SID
    Save-ToCSV -Data $users -EntryPath "$($Folders.Users)/LocalUsers.csv"
}

Invoke-Collect "Local Groups" {
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue | Select-Object Name, Description, SID
    if ($groups) { Save-ToCSV -Data $groups -EntryPath "$($Folders.Users)/LocalGroups.csv" }
}

Invoke-Collect "Local Group Memberships" {
    $members = [System.Collections.ArrayList]::new()
    $groups = Get-LocalGroup -ErrorAction SilentlyContinue
    foreach ($group in $groups) {
        $groupMembers = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
        foreach ($member in $groupMembers) {
            $null = $members.Add([PSCustomObject]@{ Group = $group.Name; Name = $member.Name; Type = $member.ObjectClass; SID = $member.SID })
        }
    }
    if ($members.Count -gt 0) { Save-ToCSV -Data $members -EntryPath "$($Folders.Users)/LocalGroupMembers.csv" }
}

Invoke-Collect "User Profiles" {
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue | Select-Object LocalPath, SID, LastUseTime, Special
    if ($profiles) { Save-ToCSV -Data $profiles -EntryPath "$($Folders.Users)/UserProfiles.csv" }
}

Invoke-Collect "Active Logon Sessions" {
    $active = [System.Collections.ArrayList]::new()
    try {
        $quserOutput = quser 2>&1
        if ($quserOutput -and $quserOutput[0] -notmatch 'No User exists') {
            $lines = $quserOutput | Select-Object -Skip 1
            foreach ($line in $lines) {
                if ($line) {
                    $parts = $line -replace '\s{2,}', '|' -split '\|'
                    if ($parts.Count -ge 4) { $null = $active.Add([PSCustomObject]@{ User = $parts[0].TrimStart('>'); Session = $parts[1]; State = $parts[3] }) }
                }
            }
        }
    } catch {}
    if ($active.Count -gt 0) { Save-ToCSV -Data $active -EntryPath "$($Folders.Users)/ActiveUsers.csv" }
}
#endregion

#region Processes and Services
Write-Log "=== PROCESSES AND SERVICES ===" "INFO"

Invoke-Collect "Running Processes" {
    $processes = [System.Collections.ArrayList]::new()
    $wmiProcs = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
    foreach ($proc in $wmiProcs) {
        $owner = $null
        try { $ownerInfo = Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue; if ($ownerInfo.User) { $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)" } } catch {}
        $parentProc = $wmiProcs | Where-Object { $_.ProcessId -eq $proc.ParentProcessId } | Select-Object -First 1
        $sig = $null
        if ($proc.ExecutablePath -and (Test-Path $proc.ExecutablePath)) { $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -ErrorAction SilentlyContinue }
        $null = $processes.Add([PSCustomObject]@{
            PID = $proc.ProcessId; PPID = $proc.ParentProcessId; ParentName = $parentProc.Name; Name = $proc.Name
            Path = $proc.ExecutablePath; CommandLine = $proc.CommandLine; Owner = if ($owner) { $owner } else { "N/A" }
            SessionId = $proc.SessionId; Created = $proc.CreationDate; ThreadCount = $proc.ThreadCount; HandleCount = $proc.HandleCount
            WorkingSetMB = [math]::Round($proc.WorkingSetSize / 1MB, 2)
            SignatureStatus = if ($sig) { $sig.Status.ToString() } else { "Unknown" }
            Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        })
    }
    if ($processes.Count -gt 0) { Save-ToCSV -Data $processes -EntryPath "$($Folders.Processes)/Processes.csv" }
}

Invoke-Collect "Process Loaded Modules" {
    $modules = [System.Collections.ArrayList]::new()
    $procs = Get-Process -ErrorAction SilentlyContinue
    foreach ($proc in $procs) {
        try {
            foreach ($module in $proc.Modules) {
                $null = $modules.Add([PSCustomObject]@{ ProcessName = $proc.Name; PID = $proc.Id; ModuleName = $module.ModuleName; FileName = $module.FileName; Company = $module.FileVersionInfo.CompanyName })
            }
        } catch {}
    }
    if ($modules.Count -gt 0) { Save-ToCSV -Data $modules -EntryPath "$($Folders.Processes)/ProcessModules.csv" }
}

Invoke-Collect "Services" {
    $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, State, StartMode, PathName, StartName, ProcessId
    Save-ToCSV -Data $services -EntryPath "$($Folders.Processes)/Services.csv"
}
#endregion

#region Network
Write-Log "=== NETWORK ===" "INFO"

Invoke-Collect "TCP Connections" {
    $tcpConns = [System.Collections.ArrayList]::new()
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $null = $tcpConns.Add([PSCustomObject]@{
            LocalAddress = $conn.LocalAddress; LocalPort = $conn.LocalPort; RemoteAddress = $conn.RemoteAddress; RemotePort = $conn.RemotePort
            State = $conn.State; PID = $conn.OwningProcess; ProcessName = $proc.Name; ProcessPath = $proc.Path
        })
    }
    if ($tcpConns.Count -gt 0) { Save-ToCSV -Data $tcpConns -EntryPath "$($Folders.Network)/TCPConnections.csv" }
}

Invoke-Collect "UDP Endpoints" {
    $udpEndpoints = [System.Collections.ArrayList]::new()
    $endpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($ep in $endpoints) {
        $proc = Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue
        $null = $udpEndpoints.Add([PSCustomObject]@{ LocalAddress = $ep.LocalAddress; LocalPort = $ep.LocalPort; PID = $ep.OwningProcess; ProcessName = $proc.Name })
    }
    if ($udpEndpoints.Count -gt 0) { Save-ToCSV -Data $udpEndpoints -EntryPath "$($Folders.Network)/UDPEndpoints.csv" }
}

Invoke-Collect "Listening Ports" {
    $listening = [System.Collections.ArrayList]::new()
    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $null = $listening.Add([PSCustomObject]@{ LocalAddress = $conn.LocalAddress; LocalPort = $conn.LocalPort; PID = $conn.OwningProcess; ProcessName = $proc.Name; ProcessPath = $proc.Path })
    }
    if ($listening.Count -gt 0) { Save-ToCSV -Data $listening -EntryPath "$($Folders.Network)/ListeningPorts.csv" }
}

Invoke-Collect "Netstat Raw Output" {
    $netstatOutput = netstat -ano 2>&1 | Out-String
    Add-TextToZip -EntryPath "$($Folders.Network)/netstat_raw.txt" -Content $netstatOutput
}

Invoke-Collect "DNS Cache" {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, Name, Type, Status, TimeToLive, Data
    if ($dnsCache) { Save-ToCSV -Data $dnsCache -EntryPath "$($Folders.Network)/DNSCache.csv" }
}

Invoke-Collect "ARP Cache" {
    $arpCache = Get-NetNeighbor -ErrorAction SilentlyContinue | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    if ($arpCache) { Save-ToCSV -Data $arpCache -EntryPath "$($Folders.Network)/ARPCache.csv" }
}

Invoke-Collect "Routes" {
    $routes = Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias
    if ($routes) { Save-ToCSV -Data $routes -EntryPath "$($Folders.Network)/Routes.csv" }
}

Invoke-Collect "Network Configuration" {
    $netConfig = [System.Collections.ArrayList]::new()
    $configs = Get-NetIPConfiguration -ErrorAction SilentlyContinue
    foreach ($config in $configs) {
        $null = $netConfig.Add([PSCustomObject]@{ Interface = $config.InterfaceAlias; IPv4 = $config.IPv4Address.IPAddress; Gateway = $config.IPv4DefaultGateway.NextHop; DNS = ($config.DNSServer.ServerAddresses -join ",") })
    }
    if ($netConfig.Count -gt 0) { Save-ToCSV -Data $netConfig -EntryPath "$($Folders.Network)/IPConfiguration.csv" }
}

Invoke-Collect "Hosts File" {
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hostsPath) { $hostsContent = Get-Content -Path $hostsPath -Raw -ErrorAction SilentlyContinue; Add-TextToZip -EntryPath "$($Folders.Network)/hosts.txt" -Content $hostsContent }
}

Invoke-Collect "Firewall Log" {
    $fwLogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $fwLogPath) { Copy-LockedFile -Source $fwLogPath -EntryPath "$($Folders.Network)/pfirewall.log" }
}

Invoke-Collect "SMB Shares" {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path, Description
    if ($shares) { Save-ToCSV -Data $shares -EntryPath "$($Folders.Network)/SMBShares.csv" }
}

Invoke-Collect "SMB Sessions" {
    $sessions = Get-SmbSession -ErrorAction SilentlyContinue | Select-Object SessionId, ClientComputerName, ClientUserName, NumOpens
    if ($sessions) { Save-ToCSV -Data $sessions -EntryPath "$($Folders.Network)/SMBSessions.csv" }
}

Invoke-Collect "Network Profiles" {
    $profiles = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*" -ErrorAction SilentlyContinue | Select-Object ProfileName, Description, Managed
    if ($profiles) { Save-ToCSV -Data $profiles -EntryPath "$($Folders.Network)/NetworkProfiles.csv" }
}
#endregion

#region Persistence
Write-Log "=== PERSISTENCE ===" "INFO"

Invoke-Collect "Registry Run Keys" {
    $runKeys = [System.Collections.ArrayList]::new()
    $keyPaths = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx","HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx")
    foreach ($keyPath in $keyPaths) {
        if (Test-Path $keyPath) {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
            if ($props) { $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $null = $runKeys.Add([PSCustomObject]@{ Location = $keyPath; Name = $_.Name; Value = $_.Value }) } }
        }
    }
    if ($runKeys.Count -gt 0) { Save-ToCSV -Data $runKeys -EntryPath "$($Folders.Persistence)/RegistryRunKeys.csv" }
}

Invoke-Collect "Scheduled Tasks" {
    $tasks = [System.Collections.ArrayList]::new()
    $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($task in $scheduledTasks) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        $actionStr = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        $null = $tasks.Add([PSCustomObject]@{ Name = $task.TaskName; Path = $task.TaskPath; State = $task.State; Author = $task.Author; Action = $actionStr; RunAs = $task.Principal.UserId; LastRun = $taskInfo.LastRunTime; NextRun = $taskInfo.NextRunTime })
    }
    if ($tasks.Count -gt 0) { Save-ToCSV -Data $tasks -EntryPath "$($Folders.Persistence)/ScheduledTasks.csv" }
}

Invoke-Collect "Scheduled Task XML Files" -Admin {
    $taskSrcPath = "$env:SystemRoot\System32\Tasks"
    if (Test-Path $taskSrcPath) {
        $taskFiles = Get-ChildItem -Path $taskSrcPath -Recurse -File -ErrorAction SilentlyContinue
        foreach ($file in $taskFiles) {
            try { $relativePath = $file.FullName.Substring($taskSrcPath.Length).TrimStart('\'); Add-FileToZip -SourcePath $file.FullName -EntryPath "$($Folders.Persistence)/TaskFiles/$relativePath" } catch {}
        }
    }
}

Invoke-Collect "WMI Event Subscriptions" {
    $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, Query
    $consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Select-Object Name, @{N='Type';E={$_.__CLASS}}
    $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer
    if ($filters) { Save-ToCSV -Data $filters -EntryPath "$($Folders.Persistence)/WMI_Filters.csv" }
    if ($consumers) { Save-ToCSV -Data $consumers -EntryPath "$($Folders.Persistence)/WMI_Consumers.csv" }
    if ($bindings) { Save-ToCSV -Data $bindings -EntryPath "$($Folders.Persistence)/WMI_Bindings.csv" }
}

Invoke-Collect "Startup Folder Contents" {
    $startupItems = [System.Collections.ArrayList]::new()
    $startupPaths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) { $null = $startupItems.Add([PSCustomObject]@{ Location = $path; Name = $item.Name; Path = $item.FullName; Created = $item.CreationTime; Modified = $item.LastWriteTime }) }
        }
    }
    if ($startupItems.Count -gt 0) { Save-ToCSV -Data $startupItems -EntryPath "$($Folders.Persistence)/StartupFolder.csv" }
}

Invoke-Collect "BITS Jobs" {
    $bitsJobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Select-Object DisplayName, JobId, JobState, TransferType, BytesTotal, BytesTransferred, CreationTime
    if ($bitsJobs) { Save-ToCSV -Data $bitsJobs -EntryPath "$($Folders.Persistence)/BITSJobs.csv" }
}

Invoke-Collect "Winlogon Registry" {
    $winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object Shell, Userinit, Taskman
    if ($winlogon) { Save-ToCSV -Data $winlogon -EntryPath "$($Folders.Persistence)/Winlogon.csv" }
}

Invoke-Collect "Image File Execution Options" {
    $ifeo = [System.Collections.ArrayList]::new()
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        $subkeys = Get-ChildItem -Path $ifeoPath -ErrorAction SilentlyContinue
        foreach ($key in $subkeys) {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.Debugger -or $props.GlobalFlag) { $null = $ifeo.Add([PSCustomObject]@{ Image = $key.PSChildName; Debugger = $props.Debugger; GlobalFlag = $props.GlobalFlag }) }
        }
    }
    if ($ifeo.Count -gt 0) { Save-ToCSV -Data $ifeo -EntryPath "$($Folders.Persistence)/IFEO.csv" }
}

Invoke-Collect "AppInit DLLs" {
    $appInit = [System.Collections.ArrayList]::new()
    $paths = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($props.AppInit_DLLs -or $props.LoadAppInit_DLLs) { $null = $appInit.Add([PSCustomObject]@{ Path = $path; AppInit_DLLs = $props.AppInit_DLLs; LoadAppInit_DLLs = $props.LoadAppInit_DLLs }) }
        }
    }
    if ($appInit.Count -gt 0) { Save-ToCSV -Data $appInit -EntryPath "$($Folders.Persistence)/AppInitDLLs.csv" }
}
#endregion

#region Execution Artifacts
Write-Log "=== EXECUTION ARTIFACTS ===" "INFO"

Invoke-Collect "Prefetch Files" {
    $prefetchPath = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchPath) {
        $pfFiles = Get-ChildItem -Path "$prefetchPath\*.pf" -ErrorAction SilentlyContinue
        if ($pfFiles) {
            $prefetchData = $pfFiles | Select-Object Name, @{N='Executable';E={$_.BaseName -replace '-[A-F0-9]{8}$',''}}, CreationTime, LastWriteTime, Length
            Save-ToCSV -Data $prefetchData -EntryPath "$($Folders.Execution)/Prefetch.csv"
            $pfFiles | Select-Object -First 300 | ForEach-Object { Add-FileToZip -SourcePath $_.FullName -EntryPath "$($Folders.Execution)/Prefetch/$($_.Name)" }
        }
    }
}

Invoke-Collect "Amcache.hve" {
    $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    if (Test-Path $amcachePath) {
        Copy-LockedFile -Source $amcachePath -EntryPath "$($Folders.Execution)/Amcache.hve"
        $logFiles = Get-ChildItem -Path "$env:SystemRoot\AppCompat\Programs\Amcache.hve.LOG*" -ErrorAction SilentlyContinue
        foreach ($log in $logFiles) { Copy-LockedFile -Source $log.FullName -EntryPath "$($Folders.Execution)/$($log.Name)" }
    }
}

Invoke-Collect "ShimCache" {
    $tempShimPath = Join-Path $script:TempPath "ShimCache.reg"
    $null = reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" $tempShimPath /y 2>&1
    if (Test-Path $tempShimPath) { Add-FileToZip -SourcePath $tempShimPath -EntryPath "$($Folders.Execution)/ShimCache.reg"; Remove-Item -Path $tempShimPath -Force -ErrorAction SilentlyContinue }
}

Invoke-Collect "BAM and DAM" {
    $bamData = [System.Collections.ArrayList]::new()
    $bamPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings","HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings")
    foreach ($bamPath in $bamPaths) {
        if (Test-Path $bamPath) {
            $subkeys = Get-ChildItem -Path $bamPath -ErrorAction SilentlyContinue
            foreach ($key in $subkeys) {
                $sid = $key.PSChildName
                $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
                if ($props) {
                    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|^Version|^Sequence' } | ForEach-Object {
                        try { $execTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($_.Value, 0)); $null = $bamData.Add([PSCustomObject]@{ SID = $sid; Path = $_.Name; LastExecution = $execTime }) } catch {}
                    }
                }
            }
        }
    }
    if ($bamData.Count -gt 0) { Save-ToCSV -Data $bamData -EntryPath "$($Folders.Execution)/BAM.csv" }
}

Invoke-Collect "UserAssist" {
    $userAssist = [System.Collections.ArrayList]::new()
    $hkuKeys = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue
    foreach ($hkuKey in $hkuKeys) {
        $sid = $hkuKey.PSChildName
        $uaPath = "$($hkuKey.PSPath)\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        if (Test-Path $uaPath) {
            $guidKeys = Get-ChildItem -Path $uaPath -ErrorAction SilentlyContinue
            foreach ($guidKey in $guidKeys) {
                $countPath = "$($guidKey.PSPath)\Count"
                if (Test-Path $countPath) {
                    $props = Get-ItemProperty -Path $countPath -ErrorAction SilentlyContinue
                    if ($props) {
                        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                            $decoded = -join ($_.Name.ToCharArray() | ForEach-Object { if ([char]::IsLetter($_)) { $base = if ([char]::IsUpper($_)) { 65 } else { 97 }; [char]((([int]$_ - $base + 13) % 26) + $base) } else { $_ } })
                            $null = $userAssist.Add([PSCustomObject]@{ SID = $sid; DecodedPath = $decoded })
                        }
                    }
                }
            }
        }
    }
    if ($userAssist.Count -gt 0) { Save-ToCSV -Data $userAssist -EntryPath "$($Folders.Execution)/UserAssist.csv" }
}

Invoke-Collect "SRUM Database" -Admin {
    $srumPath = "$env:SystemRoot\System32\sru\SRUDB.dat"
    if (Test-Path $srumPath) { Copy-LockedFile -Source $srumPath -EntryPath "$($Folders.Execution)/SRUDB.dat" }
}

Invoke-Collect "PowerShell History" {
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $histPath = Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $histPath) { Add-FileToZip -SourcePath $histPath -EntryPath "$($Folders.Execution)/PSHistory_$($userFolder.Name).txt" }
    }
}

Invoke-Collect "Recent Commands" {
    $recentCommands = [System.Collections.ArrayList]::new()
    $runMru = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue
    if ($runMru) { $runMru.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS|MRUList' } | ForEach-Object { $null = $recentCommands.Add([PSCustomObject]@{ Type = "RunMRU"; Entry = $_.Name; Command = $_.Value }) } }
    if ($recentCommands.Count -gt 0) { Save-ToCSV -Data $recentCommands -EntryPath "$($Folders.Execution)/RecentCommands.csv" }
}
#endregion

#region Registry
Write-Log "=== REGISTRY ===" "INFO"

Invoke-Collect "SOFTWARE Hive" -Admin { Copy-LockedFile -Source "$env:SystemRoot\System32\config\SOFTWARE" -EntryPath "$($Folders.Registry)/SOFTWARE" }
Invoke-Collect "SYSTEM Hive" -Admin { Copy-LockedFile -Source "$env:SystemRoot\System32\config\SYSTEM" -EntryPath "$($Folders.Registry)/SYSTEM" }

Invoke-Collect "User NTUSER.DAT Files" {
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $ntuserPath = Join-Path $userFolder.FullName "NTUSER.DAT"
        if (Test-Path $ntuserPath) { Copy-LockedFile -Source $ntuserPath -EntryPath "$($Folders.Registry)/NTUSER_$($userFolder.Name).DAT" }
        $usrclassPath = Join-Path $userFolder.FullName "AppData\Local\Microsoft\Windows\UsrClass.dat"
        if (Test-Path $usrclassPath) { Copy-LockedFile -Source $usrclassPath -EntryPath "$($Folders.Registry)/UsrClass_$($userFolder.Name).dat" }
    }
}

Invoke-Collect "Registry Key Exports" {
    $exports = @(@{ Key = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; File = "Run_HKLM.reg" },@{ Key = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; File = "Run_HKCU.reg" },@{ Key = "HKLM\SYSTEM\CurrentControlSet\Services"; File = "Services.reg" },@{ Key = "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"; File = "USBSTOR.reg" })
    foreach ($export in $exports) {
        $tempRegPath = Join-Path $script:TempPath $export.File
        $null = reg export $export.Key $tempRegPath /y 2>&1
        if (Test-Path $tempRegPath) { Add-FileToZip -SourcePath $tempRegPath -EntryPath "$($Folders.Registry)/$($export.File)"; Remove-Item -Path $tempRegPath -Force -ErrorAction SilentlyContinue }
    }
}
#endregion

#region FileSystem
Write-Log "=== FILESYSTEM ===" "INFO"

Invoke-Collect "Jump Lists" {
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $jumpListPaths = @((Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"),(Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"))
        foreach ($jlPath in $jumpListPaths) {
            if (Test-Path $jlPath) {
                $jlFiles = Get-ChildItem -Path $jlPath -File -ErrorAction SilentlyContinue
                foreach ($file in $jlFiles) { $jlType = if ($jlPath -match 'Automatic') { 'Auto' } else { 'Custom' }; Add-FileToZip -SourcePath $file.FullName -EntryPath "$($Folders.FileSystem)/JumpLists/$($userFolder.Name)_${jlType}_$($file.Name)" }
            }
        }
    }
}

Invoke-Collect "LNK Files" {
    $lnkData = [System.Collections.ArrayList]::new()
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $recentPath = Join-Path $userFolder.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $recentPath) {
            $lnkFiles = Get-ChildItem -Path $recentPath -Filter "*.lnk" -ErrorAction SilentlyContinue | Select-Object -First 100
            $shell = New-Object -ComObject WScript.Shell
            foreach ($lnk in $lnkFiles) {
                try {
                    $shortcut = $shell.CreateShortcut($lnk.FullName)
                    $null = $lnkData.Add([PSCustomObject]@{ User = $userFolder.Name; LnkName = $lnk.Name; TargetPath = $shortcut.TargetPath; Arguments = $shortcut.Arguments; WorkingDir = $shortcut.WorkingDirectory; Created = $lnk.CreationTime; Modified = $lnk.LastWriteTime })
                    Add-FileToZip -SourcePath $lnk.FullName -EntryPath "$($Folders.FileSystem)/LNK/$($userFolder.Name)_$($lnk.Name)"
                } catch {}
            }
        }
    }
    if ($lnkData.Count -gt 0) { Save-ToCSV -Data $lnkData -EntryPath "$($Folders.FileSystem)/LNK_Metadata.csv" }
}

Invoke-Collect "Recycle Bin" {
    $recycleBin = [System.Collections.ArrayList]::new()
    $rbPath = 'C:\$Recycle.Bin'
    if (Test-Path $rbPath) {
        $sidFolders = Get-ChildItem -Path $rbPath -Directory -Force -ErrorAction SilentlyContinue
        foreach ($sidFolder in $sidFolders) {
            $files = Get-ChildItem -Path $sidFolder.FullName -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) { $null = $recycleBin.Add([PSCustomObject]@{ SID = $sidFolder.Name; FileName = $file.Name; Size = $file.Length; DeletedTime = $file.CreationTime }) }
        }
    }
    if ($recycleBin.Count -gt 0) { Save-ToCSV -Data $recycleBin -EntryPath "$($Folders.FileSystem)/RecycleBin.csv" }
}

Invoke-Collect "Windows Timeline" {
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $timelinePath = Join-Path $userFolder.FullName "AppData\Local\ConnectedDevicesPlatform"
        if (Test-Path $timelinePath) {
            $dbFiles = Get-ChildItem -Path $timelinePath -Recurse -Filter "ActivitiesCache.db" -ErrorAction SilentlyContinue
            foreach ($db in $dbFiles) { Copy-LockedFile -Source $db.FullName -EntryPath "$($Folders.FileSystem)/ActivitiesCache_$($userFolder.Name).db" }
        }
    }
}
#endregion

#region Browser
Write-Log "=== BROWSER ===" "INFO"

Invoke-Collect "Browser History" {
    $userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($userFolder in $userFolders) {
        $chromePath = Join-Path $userFolder.FullName "AppData\Local\Google\Chrome\User Data"
        if (Test-Path $chromePath) {
            $profiles = Get-ChildItem -Path $chromePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Default$|^Profile' }
            foreach ($profile in $profiles) { $historyPath = Join-Path $profile.FullName "History"; if (Test-Path $historyPath) { Copy-LockedFile -Source $historyPath -EntryPath "$($Folders.Browser)/$($userFolder.Name)/Chrome/$($profile.Name)/History" } }
        }
        $edgePath = Join-Path $userFolder.FullName "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path $edgePath) {
            $profiles = Get-ChildItem -Path $edgePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Default$|^Profile' }
            foreach ($profile in $profiles) { $historyPath = Join-Path $profile.FullName "History"; if (Test-Path $historyPath) { Copy-LockedFile -Source $historyPath -EntryPath "$($Folders.Browser)/$($userFolder.Name)/Edge/$($profile.Name)/History" } }
        }
        $firefoxPath = Join-Path $userFolder.FullName "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxPath) {
            $profiles = Get-ChildItem -Path $firefoxPath -Directory -ErrorAction SilentlyContinue
            foreach ($profile in $profiles) { $placesPath = Join-Path $profile.FullName "places.sqlite"; if (Test-Path $placesPath) { Copy-LockedFile -Source $placesPath -EntryPath "$($Folders.Browser)/$($userFolder.Name)/Firefox/$($profile.Name)/places.sqlite" } }
        }
    }
}
#endregion

#region Event Logs
Write-Log "=== EVENT LOGS ===" "INFO"

Invoke-Collect "Security Event Log" -Admin {
    $tempEvtx = Join-Path $script:TempPath "Security.evtx"
    $null = wevtutil epl Security $tempEvtx 2>&1
    if (Test-Path $tempEvtx) { Add-FileToZip -SourcePath $tempEvtx -EntryPath "$($Folders.EventLogs)/Security.evtx"; Remove-Item -Path $tempEvtx -Force -ErrorAction SilentlyContinue }
}

Invoke-Collect "System Event Log" -Admin {
    $tempEvtx = Join-Path $script:TempPath "System.evtx"
    $null = wevtutil epl System $tempEvtx 2>&1
    if (Test-Path $tempEvtx) { Add-FileToZip -SourcePath $tempEvtx -EntryPath "$($Folders.EventLogs)/System.evtx"; Remove-Item -Path $tempEvtx -Force -ErrorAction SilentlyContinue }
}

Invoke-Collect "Application Event Log" -Admin {
    $tempEvtx = Join-Path $script:TempPath "Application.evtx"
    $null = wevtutil epl Application $tempEvtx 2>&1
    if (Test-Path $tempEvtx) { Add-FileToZip -SourcePath $tempEvtx -EntryPath "$($Folders.EventLogs)/Application.evtx"; Remove-Item -Path $tempEvtx -Force -ErrorAction SilentlyContinue }
}

Invoke-Collect "PowerShell Event Log" -Admin {
    $tempEvtx = Join-Path $script:TempPath "PowerShell-Operational.evtx"
    $null = wevtutil epl "Microsoft-Windows-PowerShell/Operational" $tempEvtx 2>&1
    if (Test-Path $tempEvtx) { Add-FileToZip -SourcePath $tempEvtx -EntryPath "$($Folders.EventLogs)/PowerShell-Operational.evtx"; Remove-Item -Path $tempEvtx -Force -ErrorAction SilentlyContinue }
}

Invoke-Collect "Additional Event Logs" -Admin {
    $logNames = @(@{ Name = "Microsoft-Windows-TaskScheduler/Operational"; File = "TaskScheduler.evtx" },@{ Name = "Microsoft-Windows-Windows Defender/Operational"; File = "Defender.evtx" },@{ Name = "Microsoft-Windows-WinRM/Operational"; File = "WinRM.evtx" },@{ Name = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"; File = "TerminalServices-Local.evtx" },@{ Name = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"; File = "TerminalServices-Remote.evtx" },@{ Name = "Microsoft-Windows-Sysmon/Operational"; File = "Sysmon.evtx" },@{ Name = "Microsoft-Windows-WMI-Activity/Operational"; File = "WMI-Activity.evtx" },@{ Name = "Microsoft-Windows-Bits-Client/Operational"; File = "Bits-Client.evtx" })
    foreach ($log in $logNames) {
        $tempEvtx = Join-Path $script:TempPath $log.File
        $null = wevtutil epl $log.Name $tempEvtx 2>&1
        if (Test-Path $tempEvtx) { Add-FileToZip -SourcePath $tempEvtx -EntryPath "$($Folders.EventLogs)/$($log.File)"; Remove-Item -Path $tempEvtx -Force -ErrorAction SilentlyContinue }
    }
}
#endregion

#region Parsed Security Events
Write-Log "=== PARSED SECURITY EVENTS ===" "INFO"

Invoke-Collect "Logon Events" -Admin {
    $logonEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648} -MaxEvents 5000 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        try {
            $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            if ($event.Id -eq 4624) { $null = $logonEvents.Add([PSCustomObject]@{ EventId = $event.Id; EventType = "SuccessfulLogon"; TimeCreated = $event.TimeCreated; TargetUser = $data['TargetUserName']; TargetDomain = $data['TargetDomainName']; LogonType = $data['LogonType']; SourceIP = $data['IpAddress']; SourceHost = $data['WorkstationName']; LogonProcess = $data['LogonProcessName'] }) }
            elseif ($event.Id -eq 4625) { $null = $logonEvents.Add([PSCustomObject]@{ EventId = $event.Id; EventType = "FailedLogon"; TimeCreated = $event.TimeCreated; TargetUser = $data['TargetUserName']; TargetDomain = $data['TargetDomainName']; LogonType = $data['LogonType']; SourceIP = $data['IpAddress']; SourceHost = $data['WorkstationName']; FailureReason = $data['Status'] }) }
            elseif ($event.Id -eq 4648) { $null = $logonEvents.Add([PSCustomObject]@{ EventId = $event.Id; EventType = "ExplicitCredentials"; TimeCreated = $event.TimeCreated; SubjectUser = $data['SubjectUserName']; SubjectDomain = $data['SubjectDomainName']; TargetUser = $data['TargetUserName']; TargetDomain = $data['TargetDomainName']; TargetServer = $data['TargetServerName'] }) }
        } catch {}
    }
    if ($logonEvents.Count -gt 0) { Save-ToCSV -Data $logonEvents -EntryPath "$($Folders.Security)/SecurityEvents_Logons.csv" }
}

Invoke-Collect "Process Creation Events" -Admin {
    $procEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5000 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        try {
            $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            $null = $procEvents.Add([PSCustomObject]@{ TimeCreated = $event.TimeCreated; SubjectUser = $data['SubjectUserName']; SubjectDomainName = $data['SubjectDomainName']; NewProcessName = $data['NewProcessName']; CommandLine = $data['CommandLine']; ParentProcessName = $data['ParentProcessName']; TokenElevationType = $data['TokenElevationType'] })
        } catch {}
    }
    if ($procEvents.Count -gt 0) { Save-ToCSV -Data $procEvents -EntryPath "$($Folders.Security)/SecurityEvents_ProcessCreation.csv" }
}

Invoke-Collect "Kerberos and NTLM Events" -Admin {
    $authEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768,4769,4776} -MaxEvents 2000 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        try {
            $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
            if ($event.Id -eq 4768) { $null = $authEvents.Add([PSCustomObject]@{ EventId = $event.Id; Type = "KerberosTGT"; TimeCreated = $event.TimeCreated; TargetUser = $data['TargetUserName']; Domain = $data['TargetDomainName']; ClientIP = $data['IpAddress']; Status = $data['Status'] }) }
            elseif ($event.Id -eq 4769) { $null = $authEvents.Add([PSCustomObject]@{ EventId = $event.Id; Type = "KerberosST"; TimeCreated = $event.TimeCreated; TargetUser = $data['TargetUserName']; ServiceName = $data['ServiceName']; ClientIP = $data['IpAddress']; Status = $data['Status'] }) }
            elseif ($event.Id -eq 4776) { $null = $authEvents.Add([PSCustomObject]@{ EventId = $event.Id; Type = "NTLM"; TimeCreated = $event.TimeCreated; TargetUser = $data['TargetUserName']; Workstation = $data['Workstation']; Status = $data['Status'] }) }
        } catch {}
    }
    if ($authEvents.Count -gt 0) { Save-ToCSV -Data $authEvents -EntryPath "$($Folders.Security)/SecurityEvents_Kerberos_NTLM.csv" }
}

Invoke-Collect "RDP Events" -Admin {
    $rdpEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25} -MaxEvents 1000 -ErrorAction SilentlyContinue
    foreach ($event in $events) {
        try {
            $xml = [xml]$event.ToXml(); $userData = $xml.Event.UserData
            $null = $rdpEvents.Add([PSCustomObject]@{ EventId = $event.Id; Type = switch ($event.Id) { 21 {"SessionLogon"} 22 {"ShellStart"} 23 {"SessionLogoff"} 24 {"SessionDisconnect"} 25 {"SessionReconnect"} }; TimeCreated = $event.TimeCreated; User = $userData.EventXML.User; SessionId = $userData.EventXML.SessionID; SourceIP = $userData.EventXML.Address })
        } catch {}
    }
    if ($rdpEvents.Count -gt 0) { Save-ToCSV -Data $rdpEvents -EntryPath "$($Folders.Security)/RDP_Events.csv" }
}

Invoke-Collect "Service Installation Events" -Admin {
    $svcEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} -MaxEvents 500 -ErrorAction SilentlyContinue
    foreach ($event in $events) { try { $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; $null = $svcEvents.Add([PSCustomObject]@{ EventId = $event.Id; Source = "Security"; TimeCreated = $event.TimeCreated; ServiceName = $data['ServiceName']; ServiceFile = $data['ServiceFileName']; ServiceType = $data['ServiceType']; ServiceAccount = $data['ServiceAccount'] }) } catch {} }
    $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 500 -ErrorAction SilentlyContinue
    foreach ($event in $events) { try { $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; $null = $svcEvents.Add([PSCustomObject]@{ EventId = $event.Id; Source = "System"; TimeCreated = $event.TimeCreated; ServiceName = $data['ServiceName']; ServiceFile = $data['ImagePath']; ServiceType = $data['ServiceType']; ServiceAccount = $data['AccountName'] }) } catch {} }
    if ($svcEvents.Count -gt 0) { Save-ToCSV -Data $svcEvents -EntryPath "$($Folders.Security)/ServiceInstallationEvents.csv" }
}

Invoke-Collect "Scheduled Task Events" -Admin {
    $taskEvents = [System.Collections.ArrayList]::new()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4702} -MaxEvents 500 -ErrorAction SilentlyContinue
    foreach ($event in $events) { try { $xml = [xml]$event.ToXml(); $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; $null = $taskEvents.Add([PSCustomObject]@{ EventId = $event.Id; Type = if ($event.Id -eq 4698) { "Created" } else { "Updated" }; TimeCreated = $event.TimeCreated; TaskName = $data['TaskName']; User = $data['SubjectUserName'] }) } catch {} }
    if ($taskEvents.Count -gt 0) { Save-ToCSV -Data $taskEvents -EntryPath "$($Folders.Security)/ScheduledTaskEvents.csv" }
}
#endregion

#region Security Status
Write-Log "=== SECURITY STATUS ===" "INFO"

Invoke-Collect "Defender Status" -Admin {
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $status = [PSCustomObject]@{ RealTimeEnabled = $mpStatus.RealTimeProtectionEnabled; BehaviorMonitorEnabled = $mpStatus.BehaviorMonitorEnabled; IoavEnabled = $mpStatus.IoavProtectionEnabled; SignatureVersion = $mpStatus.AntivirusSignatureVersion; SignatureLastUpdated = $mpStatus.AntivirusSignatureLastUpdated; QuickScanAge = $mpStatus.QuickScanAge; FullScanAge = $mpStatus.FullScanAge }
        Save-ToCSV -Data $status -EntryPath "$($Folders.Security)/DefenderStatus.csv"
        $mpPref = Get-MpPreference -ErrorAction Stop
        $exclusions = [PSCustomObject]@{ PathExclusions = ($mpPref.ExclusionPath -join ";"); ProcessExclusions = ($mpPref.ExclusionProcess -join ";"); ExtensionExclusions = ($mpPref.ExclusionExtension -join ";") }
        Save-ToCSV -Data $exclusions -EntryPath "$($Folders.Security)/DefenderExclusions.csv"
    } catch {}
}

Invoke-Collect "Defender Detection History" -Admin {
    $detections = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object ThreatID, ProcessName, DomainUser, DetectionSourceTypeID, InitialDetectionTime, LastThreatStatusChangeTime
    if ($detections) { Save-ToCSV -Data $detections -EntryPath "$($Folders.Security)/DefenderDetections.csv" }
}

Invoke-Collect "Defender Support Logs" -Admin {
    $defenderPath = "$env:ProgramData\Microsoft\Windows Defender\Support"
    if (Test-Path $defenderPath) {
        $defenderFiles = Get-ChildItem -Path $defenderPath -File -ErrorAction SilentlyContinue
        foreach ($file in $defenderFiles) { Add-FileToZip -SourcePath $file.FullName -EntryPath "$($Folders.EventLogs)/DefenderLogs/$($file.Name)" }
    }
}

Invoke-Collect "Firewall Rules" {
    $fwRules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Direction, Action, Profile
    if ($fwRules) { Save-ToCSV -Data $fwRules -EntryPath "$($Folders.Security)/FirewallRules.csv" }
}
#endregion

#region Finalization
Write-Host ""
Write-Host ""
Write-Host "  ================================================" -ForegroundColor $script:C.Bar
Write-Host "   FINALIZING" -ForegroundColor $script:C.Title
Write-Host "  ================================================" -ForegroundColor $script:C.Bar

$endTime = Get-Date
$duration = ($endTime - $StartTime).ToString("hh\:mm\:ss")
$successRate = if ($script:Stats.Total -gt 0) { [math]::Round(($script:Stats.Success / $script:Stats.Total) * 100, 1) } else { 0 }

Write-Host "  Saving file hashes..." -ForegroundColor $script:C.Dim
if ($script:FileHashes.Count -gt 0) {
    $hashCsv = ($script:FileHashes | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    Add-ToZip -EntryPath "FileHashes.csv" -Content $hashCsv
}

$manifest = [PSCustomObject]@{ ToolName = "NovaTrace IR Kit"; ToolVersion = "1.1.0"; CollectionStart = $StartTime; CollectionEnd = $endTime; Duration = $duration; Hostname = $Hostname; IsAdmin = $IsAdmin; Attempted = $script:Stats.Total; Collected = $script:Stats.Success; Failed = $script:Stats.Failed; Skipped = $script:Stats.Skipped; SuccessRate = "$successRate%" }
$manifestCsv = ($manifest | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
Add-ToZip -EntryPath "Manifest.csv" -Content $manifestCsv

$readmeContent = @"
================================================================================
                        NOVATRACE IR KIT - COLLECTION REPORT
================================================================================

  Collection Time: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) - $($endTime.ToString('HH:mm:ss'))
  Duration:        $duration
  Host:            $Hostname
  Admin:           $IsAdmin
  Statistics:      $($script:Stats.Success)/$($script:Stats.Total) collected ($successRate%)

================================================================================
                              FOLDER STRUCTURE
================================================================================

  System/        - OS info, software, drivers, hardware
  Users/         - Local users, groups, profiles
  Processes/     - Running processes, services, modules
  Network/       - Connections, DNS, ARP, configuration
  Persistence/   - Run keys, tasks, WMI, startup items
  Execution/     - Prefetch, Amcache, ShimCache, BAM, UserAssist
  Registry/      - Raw hives SOFTWARE, SYSTEM, NTUSER
  FileSystem/    - Jump lists, LNK files, Recycle Bin, Timeline
  Browser/       - History databases
  EventLogs/     - Raw EVTX files and Defender logs
  Security/      - Logon events, RDP, Defender status

================================================================================
                           ANALYSIS RECOMMENDATIONS
================================================================================

  1 - Parse Amcache.hve with AmcacheParser
  2 - Parse Prefetch with PECmd
  3 - Analyze event logs with EvtxECmd or Timeline Explorer
  4 - Review registry hives with Registry Explorer
  5 - Cross-reference timestamps across artifacts

================================================================================
                           NovaTrace IR Kit v1.1.0
================================================================================
"@
Add-ToZip -EntryPath "README.txt" -Content $readmeContent

if ($script:LogEntries.Count -gt 0) { $logContent = $script:LogEntries -join "`r`n"; Add-ToZip -EntryPath "novatrace.log" -Content $logContent }
if ($script:ErrorEntries.Count -gt 0) { $errorContent = $script:ErrorEntries -join "`r`n"; Add-ToZip -EntryPath "errors.log" -Content $errorContent }

Write-Host "  Closing archive..." -ForegroundColor $script:C.Dim
$script:ZipArchive.Dispose()

Remove-Item -Path $script:TempPath -Recurse -Force -ErrorAction SilentlyContinue

$zipSize = [math]::Round((Get-Item -Path $script:ZipPath).Length / 1MB, 2)

Write-Host ""
Write-Host "  +=============================================+" -ForegroundColor $script:C.OK
Write-Host "  |          COLLECTION COMPLETE               |" -ForegroundColor $script:C.OK
Write-Host "  +=============================================+" -ForegroundColor $script:C.OK
Write-Host "  |  Time:     " -NoNewline -ForegroundColor $script:C.OK
Write-Host "$($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) - $($endTime.ToString('HH:mm:ss'))".PadRight(32) -NoNewline -ForegroundColor $script:C.Info
Write-Host "|" -ForegroundColor $script:C.OK
Write-Host "  |  Duration: " -NoNewline -ForegroundColor $script:C.OK
Write-Host "$duration".PadRight(32) -NoNewline -ForegroundColor $script:C.Info
Write-Host "|" -ForegroundColor $script:C.OK
Write-Host "  |  Host:     " -NoNewline -ForegroundColor $script:C.OK
Write-Host "$Hostname | Admin: $IsAdmin".PadRight(32) -NoNewline -ForegroundColor $script:C.Info
Write-Host "|" -ForegroundColor $script:C.OK
Write-Host "  |  Stats:    " -NoNewline -ForegroundColor $script:C.OK
Write-Host "$($script:Stats.Success)/$($script:Stats.Total) ($successRate%)".PadRight(32) -NoNewline -ForegroundColor $script:C.Info
Write-Host "|" -ForegroundColor $script:C.OK
Write-Host "  |  Archive:  " -NoNewline -ForegroundColor $script:C.OK
Write-Host "$zipSize MB".PadRight(32) -NoNewline -ForegroundColor $script:C.Info
Write-Host "|" -ForegroundColor $script:C.OK
Write-Host "  +=============================================+" -ForegroundColor $script:C.OK

if ($IsLiveResponse) {
    Write-Host ""
    Write-Host "  Download: " -NoNewline -ForegroundColor $script:C.Info
    Write-Host "getfile `"$($script:ZipPath)`"" -ForegroundColor $script:C.Warn
}

Write-Host ""
Write-Host "  Output: $($script:ZipPath)" -ForegroundColor $script:C.Info
Write-Host ""
#endregion
