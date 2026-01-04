# =============================
# MAINTENANCE SCRIPT ALL-IN-ONE
# =============================
# Support: Windows 7, 8, 8.1, 10, 11
# Execution: Async/Background (Non-blocking)

# ===================================================
# LOAD CONFIGURATION FROM .ENV FILE
# ===================================================

function Load-EnvFile {
    param([string]$EnvPath = ".\.env")
    
    $config = @{}
    
    if (Test-Path $EnvPath) {
        Write-Host "[CONFIG] Loading configuration from .env file..." -ForegroundColor Cyan
        
        Get-Content $EnvPath | ForEach-Object {
            $line = $_.Trim()
            
            # Skip empty lines and comments
            if ($line -and -not $line.StartsWith('#')) {
                if ($line -match '^([^=]+)=(.*)$') {
                    $key = $matches[1].Trim()
                    $value = $matches[2].Trim()
                    
                    # Remove quotes if present
                    $value = $value -replace '^["'']|["'']$'
                    
                    $config[$key] = $value
                }
            }
        }
        
        Write-Host "[OK] Configuration loaded: $($config.Count) settings" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] .env file not found at: $EnvPath" -ForegroundColor Yellow
        Write-Host "[INFO] Using default configuration" -ForegroundColor Gray
    }
    
    return $config
}

# Load environment variables
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $scriptDir ".env"
$Config = Load-EnvFile -EnvPath $envFile

# Set default values if not in .env
if (-not $Config.API_URL) {
    $Config.API_URL = "http://localhost:3000/api/pc-reports/submit"
}
if (-not $Config.API_TIMEOUT) {
    $Config.API_TIMEOUT = 30
}
if (-not $Config.API_RETRY_COUNT) {
    $Config.API_RETRY_COUNT = 3
}

Write-Host "[CONFIG] Backend API: $($Config.API_URL)" -ForegroundColor Cyan

# --- Deteksi Windows Version untuk Compatibility ---
$osVersion = [System.Environment]::OSVersion.Version
$winVersion = switch ($osVersion.Major) {
    6 {
        switch ($osVersion.Minor) {
            1 { "Windows 7" }
            2 { "Windows 8" }
            3 { "Windows 8.1" }
            default { "Windows Vista/Server 2008" }
        }
    }
    10 {
        if ($osVersion.Build -ge 22000) { "Windows 11" }
        else { "Windows 10" }
    }
    default { "Unknown Windows" }
}
Write-Host "Detected OS: $winVersion (Build: $($osVersion.Build))" -ForegroundColor Cyan

# --- Initialize Background Jobs Array ---
$BackgroundJobs = @()

# --- Ambil IP Address (prioritas IP LAN privat) ---
try {
    # Kumpulkan semua IPv4 yang bukan APIPA dan bukan loopback
    $allIPv4 = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.IPAddress -notmatch '^169\.254' -and
            $_.IPAddress -ne '127.0.0.1'
        }

    # Filter hanya private LAN (10.x, 172.16-31.x, 192.168.x)
    $privateIPv4 = $allIPv4 | Where-Object {
        $_.IPAddress -match '^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)'
    }

    # Buang interface virtual/VPN sebisa mungkin
    $filtered = $privateIPv4 | Where-Object {
        $_.InterfaceAlias -notmatch 'Loopback|Virtual|VMware|Hyper-V|vEthernet|VPN|TAP|Bluetooth'
    }

    # Prioritaskan Ethernet lalu Wi-Fi
    $preferredOrder = @('Ethernet','Wi-Fi','WiFi','LAN')
    $sorted = $filtered | Sort-Object -Property @{
        Expression = {
            $idx = $preferredOrder.IndexOf($_.InterfaceAlias)
            if ($idx -ge 0) { $idx } else { 999 }
        }
    }, InterfaceMetric

    $IPAddress = ($sorted | Select-Object -First 1).IPAddress

    # Fallback jika tidak ketemu yang private/filtered
    if (-not $IPAddress) {
        $IPAddress = ($allIPv4 | Select-Object -First 1).IPAddress
    }
} catch {
    $IPAddress = $null
}

if (-not $IPAddress) { $IPAddress = "No IP" }

$Report = @{
    Hostname = $env:COMPUTERNAME
    IPAddress = $IPAddress
    ReportDate = (Get-Date).ToString("yyyy-MM-dd")
    ReportTime = (Get-Date).ToString("HH:mm:ss")
    FullDateTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

# ===================================================
# 1. DETEKSI & SCAN ANTIVIRUS (ASYNC - Background Job)
# ===================================================
# Prioritas scan: Defender > Avira > Smadav (hanya jalankan 1 AV saja)

$AllAV = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue

# Pilih hanya 1 antivirus berdasarkan prioritas
$SelectedAV = $null
$priorityList = @("Windows Defender", "Microsoft Defender", "Avira", "Smadav")

if ($AllAV) {
    # Tampilkan semua AV yang terdeteksi
    $avNames = ($AllAV | ForEach-Object { $_.displayName }) -join ", "
    Write-Host "[INFO] Antivirus detected: $avNames" -ForegroundColor Cyan
    
    # Pilih AV berdasarkan prioritas
    foreach ($priority in $priorityList) {
        $SelectedAV = $AllAV | Where-Object { $_.displayName -match $priority } | Select-Object -First 1
        if ($SelectedAV) {
            Write-Host "[SCAN] Selected for quick scan: $($SelectedAV.displayName)" -ForegroundColor Green
            break
        }
    }
    
    # Jika tidak ada di prioritas, ambil yang pertama
    if (-not $SelectedAV) {
        $SelectedAV = $AllAV | Select-Object -First 1
        Write-Host "[INFO] Using first available AV: $($SelectedAV.displayName)" -ForegroundColor Yellow
    }
}

# Jalankan quick scan pada 1 antivirus terpilih
if ($SelectedAV) {
    $Report.Antivirus = $SelectedAV.displayName
    $Report.AllAntivirus = $avNames
    
    $avScanJob = Start-Job -ScriptBlock {
        param($displayName, $osVersion)
        
        $result = @{}
        $result.AVInstalled = $true
        $result.AVName = $displayName
        $result.AVScanResult = "Quick scan started in background for: $displayName"

        switch -Regex ($displayName) {
            "Windows Defender|Microsoft Defender" {
                try {
                    # Gunakan MpCmdRun.exe untuk Quick Scan
                    $mpCmd = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
                    if (-not (Test-Path $mpCmd)) {
                        $mpCmd = "${env:ProgramFiles(x86)}\Windows Defender\MpCmdRun.exe"
                    }
                    if (Test-Path $mpCmd) {
                        Start-Process -FilePath $mpCmd -ArgumentList "-Scan", "-ScanType", "1" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                        $result.AVScanResult = "[OK] Defender quick scan completed"
                    } else {
                        $result.AVScanResult = "[WARNING] Defender engine not found"
                    }
                } catch {
                    $result.AVScanResult = "[ERROR] Defender quick scan failed: $($_.Exception.Message)"
                }
            }

            "Avira" {
                try {
                    # Avira Quick Scan
                    $cmd = "C:\\Program Files (x86)\\Avira\\Antivirus\\avguard.exe"
                    $cmdCLI = "C:\\Program Files (x86)\\Avira\\Antivirus\\avscan.exe"
                    
                    if (Test-Path $cmdCLI) {
                        Start-Process -FilePath $cmdCLI -ArgumentList "/GUIMODE=2", "/QUICKSCAN" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                        $result.AVScanResult = "[OK] Avira quick scan completed"
                    } else {
                        $result.AVScanResult = "[WARNING] Avira scanner not found"
                    }
                } catch {
                    $result.AVScanResult = "[ERROR] Avira quick scan failed: $($_.Exception.Message)"
                }
            }

            "Smadav" {
                try {
                    $cmd = "C:\\Program Files\\Smadav\\Smadav.exe"
                    if (-not (Test-Path $cmd)) {
                        $cmd = "C:\\Program Files (x86)\\Smadav\\Smadav.exe"
                    }
                    if (Test-Path $cmd) {
                        Start-Process -FilePath $cmd -ArgumentList "/scan", "/auto-delete" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                        $result.AVScanResult = "[OK] Smadav quick scan completed"
                    } else {
                        $result.AVScanResult = "[WARNING] Smadav executable not found"
                    }
                } catch {
                    $result.AVScanResult = "[ERROR] Smadav quick scan failed: $($_.Exception.Message)"
                }
            }

            default {
                $result.AVScanResult = "[INFO] Quick scan not configured for: $displayName (scan skipped)"
            }
        }
        
        return $result
    } -ArgumentList $SelectedAV.displayName, $osVersion
    
    $BackgroundJobs += @{
        Name = "AVScan"
        Job = $avScanJob
        Type = "AV"
    }
} else {
    $Report.Antivirus = "Not detected"
    $Report.AVScanResult = "SKIPPED - No antivirus found"
    Write-Host "[WARNING] No antivirus detected" -ForegroundColor Yellow
}

# ===================================================
# 2. HEALTH CHECK (Disk, Battery, CPU Temp, RAM)
# ===================================================

# --- Disk Space ---
$Disk = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" |
    Select-Object DeviceID,
                  @{N="FreeGB";E={[math]::Round($_.FreeSpace/1GB,2)}},
                  @{N="TotalGB";E={[math]::Round($_.Size/1GB,2)}}

$Report.Disk = $Disk

# --- Disk Health & Model info ---
$Report.DiskHealth = Get-WmiObject Win32_DiskDrive |
    Select-Object Model, InterfaceType, MediaType, SerialNumber, Size, Status

# --- Disk Health via Hard Disk Sentinel (optional, jika terpasang) ---
try {
    $hdsCandidates = @(
        "C:\\Program Files\\Hard Disk Sentinel\\HDSentinel.exe",
        "C:\\Program Files (x86)\\Hard Disk Sentinel\\HDSentinel.exe"
    )

    $hdsExe = $hdsCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($hdsExe) {
        # Jalankan di background job agar tidak block script utama
        $hdsJob = Start-Job -ScriptBlock {
            param($exePath)

            $result = @{}
            $result.Tool = "Hard Disk Sentinel"
            $result.Installed = $true

            try {
                # Lokasi file report sementara
                $reportPath = Join-Path $env:TEMP ("hdsentinel_report_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt")

                # Contoh penggunaan CLI HDSentinel: /REPORT /R=filename
                # Jika versi Anda berbeda, sesuaikan argumen di bawah sesuai dokumentasi HDSentinel.
                $args = @("/REPORT", "/R=$reportPath")

                Start-Process -FilePath $exePath -ArgumentList $args -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue

                if (Test-Path $reportPath) {
                    $content = Get-Content $reportPath -ErrorAction SilentlyContinue
                    $healthLines = $content | Where-Object { $_ -match "Health" -or $_ -match "Condition" }

                    $result.ReportPath = $reportPath
                    $result.HealthSummary = $healthLines
                } else {
                    $result.Error = "Report file not created. Please verify HDSentinel CLI arguments."
                }
            } catch {
                $result.Error = $_.Exception.Message
            }

            return $result
        } -ArgumentList $hdsExe

        $BackgroundJobs += @{
            Name = "HDSentinel"
            Job = $hdsJob
            Type = "DiskHealth_HDS"
        }
    } else {
        $Report.DiskHealth_HDSentinel = "Hard Disk Sentinel not found in default install paths"
    }
} catch {
    $Report.DiskHealth_HDSentinel = "Hard Disk Sentinel check failed: $($_.Exception.Message)"
}

# --- Battery Health (untuk Laptop) ---
try {
    $Battery = Get-WmiObject Win32_Battery -ErrorAction Stop
    
    # Generate Battery Report untuk detail lengkap
    $reportPath = "$env:TEMP\battery-report.xml"
    powercfg /batteryreport /xml /output $reportPath 2>$null
    
    $batteryHealth = @{
        ChargeRemaining = $Battery.EstimatedChargeRemaining
        BatteryStatus = switch ($Battery.BatteryStatus) {
            1 { "Discharging" }
            2 { "AC Power (Charging)" }
            3 { "Fully Charged" }
            4 { "Low" }
            5 { "Critical" }
            6 { "Charging" }
            7 { "Charging High" }
            8 { "Charging Low" }
            9 { "Charging Critical" }
            10 { "Undefined" }
            11 { "Partially Charged" }
            default { "Unknown ($($Battery.BatteryStatus))" }
        }
        Name = $Battery.Name
        Chemistry = $Battery.Chemistry
        EstimatedRunTime = if($Battery.EstimatedRunTime -ne 71582788){"$($Battery.EstimatedRunTime) minutes"}else{"Calculating..."}
    }
    
    # Parse Battery Report XML untuk detail kesehatan
    if (Test-Path $reportPath) {
        try {
            [xml]$batteryXml = Get-Content $reportPath
            $designCapacity = $batteryXml.BatteryReport.Batteries.Battery.DesignCapacity
            $fullChargeCapacity = $batteryXml.BatteryReport.Batteries.Battery.FullChargeCapacity
            $cycleCount = $batteryXml.BatteryReport.Batteries.Battery.CycleCount
            
            if ($designCapacity -and $fullChargeCapacity) {
                $healthPercent = [math]::Round(($fullChargeCapacity / $designCapacity) * 100, 2)
                
                $batteryHealth.DesignCapacity_mWh = $designCapacity
                $batteryHealth.FullChargeCapacity_mWh = $fullChargeCapacity
                $batteryHealth.HealthPercent = $healthPercent
                $batteryHealth.CycleCount = if($cycleCount){$cycleCount}else{"Not Available"}
                $batteryHealth.Condition = if($healthPercent -ge 80){"Good"}elseif($healthPercent -ge 50){"Fair"}else{"Poor - Needs Replacement"}
                $batteryHealth.Degradation = [math]::Round(100 - $healthPercent, 2)
            }
            
            # Cleanup temp file
            Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
        } catch {
            # Jika gagal parse XML, skip detail health
        }
    }
    
    $Report.Battery = $batteryHealth
    
} catch {
    $Report.Battery = "Desktop / Battery Not Available"
}

# --- CPU Temperature ---
try {
    $temp = Get-WmiObject MSAcpi_ThermalZoneTemperature -Namespace "root/wmi" -ErrorAction Stop 2>$null
    if ($temp -and $temp.CurrentTemperature) {
        $Report.CPUTempC = [math]::Round(($temp.CurrentTemperature/10 - 273.15), 1)
    } else {
        $Report.CPUTempC = "Not Available"
    }
} catch {
    $Report.CPUTempC = "Not Available (requires admin or not supported)"
}

# --- RAM Usage ---
$os = Get-WmiObject Win32_OperatingSystem
$Report.RAM_Usage = @{
    TotalGB = [math]::Round($os.TotalVisibleMemorySize/1MB,2)
    FreeGB  = [math]::Round($os.FreePhysicalMemory/1MB,2)
}

# ===================================================
# 3. SPESIFIKASI HARDWARE LENGKAP
# ===================================================

# CPU Info
$cpu = Get-WmiObject Win32_Processor | 
    Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed
$Report.CPU = $cpu

# Motherboard Info
$mb = Get-WmiObject Win32_BaseBoard |
    Select-Object Manufacturer,Product,SerialNumber
$Report.Motherboard = $mb

# OS Info
$osinfo = Get-WmiObject Win32_OperatingSystem |
          Select-Object Caption,Version,OSArchitecture,SerialNumber
$Report.OS = $osinfo

# RAM Detail per Slot
$ram = Get-WmiObject Win32_PhysicalMemory |
    Select-Object BankLabel,Capacity,Manufacturer,PartNumber,Speed
$Report.RAM_Spec = $ram

# GPU Info
$gpu = Get-WmiObject Win32_VideoController |
    Select-Object Name,AdapterRAM,DriverVersion
$Report.GPU = $gpu

# BIOS Info & First Boot Date
try {
    $bios = Get-WmiObject Win32_BIOS
    $Report.BIOS = @{
        Manufacturer = $bios.Manufacturer
        Version = $bios.Version
        ReleaseDate = if($bios.ReleaseDate){[System.Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate).ToString("yyyy-MM-dd")}else{"N/A"}
        SerialNumber = $bios.SerialNumber
    }
    
    # Tanggal install OS (sebagai indikator pertama kali hidup)
    $osInstallDate = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty InstallDate
    if ($osInstallDate) {
        $Report.FirstBootDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($osInstallDate).ToString("yyyy-MM-dd HH:mm:ss")
    } else {
        $Report.FirstBootDate = "N/A"
    }
    
    # Waktu terakhir komputer dihidupkan (boot time)
    $os = Get-WmiObject Win32_OperatingSystem
    $lastBootUpTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    $uptime = (Get-Date) - $lastBootUpTime
    
    $Report.SystemBoot = @{
        LastBootTime = $lastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        UptimeDays = [math]::Round($uptime.TotalDays, 2)
        UptimeHours = [math]::Round($uptime.TotalHours, 2)
        UptimeMinutes = [math]::Round($uptime.TotalMinutes, 0)
        UptimeFormatted = "$($uptime.Days) hari, $($uptime.Hours) jam, $($uptime.Minutes) menit"
    }
} catch {
    $Report.BIOS = "Not Available"
    $Report.FirstBootDate = "Not Available"
    $Report.SystemBoot = "Not Available"
}

# ===================================================
# 4. BERSIHKAN CACHE BROWSER (ASYNC - Background Job)
# ===================================================

$browserCleanJob = Start-Job -ScriptBlock {
    $report = @{}
    
    # Chrome - Hapus Cache
    $ChromeCachePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache\*",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache\*",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Service Worker\CacheStorage\*",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Media Cache\*"
    )

    $chromeCleared = 0
    foreach ($path in $ChromeCachePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                $chromeCleared++
            } catch {}
        }
    }

    # Edge Chromium
    $EdgeCachePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\GPUCache\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Service Worker\CacheStorage\*"
    )

    $edgeCleared = 0
    foreach ($path in $EdgeCachePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                $edgeCleared++
            } catch {}
        }
    }

    # Firefox
    $FirefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $firefoxCleared = 0
    if (Test-Path $FirefoxPath) {
        Get-ChildItem $FirefoxPath -Directory | ForEach-Object {
            $cache = "$($_.FullName)\cache2\*"
            if (Test-Path $cache) {
                try {
                    Remove-Item $cache -Recurse -Force -ErrorAction SilentlyContinue
                    $firefoxCleared++
                } catch {}
            }
        }
    }

    # TEMP Folder
    try {
        Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | 
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}

    $report.Chrome = "$chromeCleared cache locations cleared"
    $report.Edge = "$edgeCleared cache locations cleared"
    $report.Firefox = "$firefoxCleared cache locations cleared"
    
    return $report
}

$BackgroundJobs += @{
    Name = "BrowserClean"
    Job = $browserCleanJob
    Type = "BrowserCache"
}

# ===================================================
# 5. CLEANING RECYCLE BIN & DISK CLEANUP (ASYNC)
# ===================================================

$diskCleanJob = Start-Job -ScriptBlock {
    $report = @{}
    
    try {
        # --- Quick Recycle Bin check ---
        $shell = New-Object -ComObject Shell.Application
        $recycleBin = $shell.Namespace(10)
        
        $totalItems = 0
        $totalSizeBytes = 0
        
        foreach ($item in $recycleBin.Items()) {
            try {
                $totalItems++
                if ($item.Size) {
                    $totalSizeBytes += [int64]$item.Size
                }
            } catch {}
        }
        
        $totalSizeMB = [math]::Round($totalSizeBytes / 1MB, 2)
        $totalSizeGB = [math]::Round($totalSizeBytes / 1GB, 2)
        
        $report.RecycleBin = @{
            Status = "Checked"
            TotalFiles = $totalItems
            TotalSizeMB = $totalSizeMB
            TotalSizeGB = $totalSizeGB
            HasTrash = $totalItems -gt 0
        }
        
        # --- Alert jika ada sampah di Recycle Bin ---
        if ($totalItems -gt 0) {
            $report.RecycleBin.Alert = "[WARNING] Found $totalItems file(s) in Recycle Bin ($totalSizeMB MB)"
            $report.RecycleBin.Recommendation = "Consider emptying Recycle Bin to free up $($totalSizeGB) GB of disk space"
            
            # Tampilkan notifikasi di console
            Add-Type -AssemblyName System.Windows.Forms
            $notification = New-Object System.Windows.Forms.NotifyIcon
            $notification.Icon = [System.Drawing.SystemIcons]::Information
            $notification.BalloonTipIcon = 'Warning'
            $notification.BalloonTipTitle = "Recycle Bin Alert"
            $notification.BalloonTipText = "Found $totalItems unused file(s) ($totalSizeGB GB). Consider deleting to free up disk space."
            $notification.Visible = $true
            $notification.ShowBalloonTip(5000)
            
            # Cleanup notification after display
            Start-Sleep -Seconds 6
            $notification.Dispose()
        } else {
            $report.RecycleBin.Alert = "[OK] Recycle Bin is empty"
        }
    } catch {
        $report.RecycleBin = "Check skipped: $($_.Exception.Message)"
    }
    
    # --- Start disk cleanup in background (non-blocking) ---
    try {
        Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:100","/D:C" -WindowStyle Hidden -ErrorAction SilentlyContinue
        $report.DiskCleanup = "Cleanup started (background process)"
    } catch {
        $report.DiskCleanup = "Cleanup failed: $($_.Exception.Message)"
    }
    
    return $report
}

$BackgroundJobs += @{
    Name = "DiskClean"
    Job = $diskCleanJob
    Type = "DiskCleanup"
}

# ===================================================
# 6. ANALISA APLIKASI & PERFORMA (ASYNC)
# ===================================================

$appAnalysisJob = Start-Job -ScriptBlock {
    $AppAnalysis = @{
        TopCPU = @()
        TopRAM = @()
        RunningApps = @()
        RarelyUsed = @()
        UnknownApps = @()
        Summary = @{}
    }

    # --- Aplikasi yang sedang berjalan ---
    $runningProcesses = Get-Process | Where-Object {$_.MainWindowTitle -ne ""} | 
        Select-Object Name, 
                      @{N="CPU_Percent";E={[math]::Round($_.CPU,2)}},
                      @{N="RAM_MB";E={[math]::Round($_.WorkingSet64/1MB,2)}},
                      @{N="StartTime";E={if($_.StartTime){$_.StartTime}else{"N/A"}}},
                      @{N="Runtime_Minutes";E={if($_.StartTime){[math]::Round(((Get-Date) - $_.StartTime).TotalMinutes,2)}else{0}}},
                      Path,
                      Company,
                      ProductVersion

    $AppAnalysis.TopCPU = $runningProcesses | 
        Sort-Object CPU_Percent -Descending | 
        Select-Object -First 10 Name, CPU_Percent, RAM_MB, Runtime_Minutes, Company

    $AppAnalysis.TopRAM = $runningProcesses | 
        Sort-Object RAM_MB -Descending | 
        Select-Object -First 10 Name, RAM_MB, CPU_Percent, Runtime_Minutes, Company

    $AppAnalysis.RunningApps = $runningProcesses | 
        Select-Object Name, Runtime_Minutes, CPU_Percent, RAM_MB, Company, Path

    # --- Aplikasi terinstall ---
    $installedApps = @()
    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $regPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | 
            Where-Object {$_.DisplayName} |
            ForEach-Object {
                $installedApps += [PSCustomObject]@{
                    Name = $_.DisplayName
                    Version = $_.DisplayVersion
                    Publisher = $_.Publisher
                    InstallDate = $_.InstallDate
                    InstallLocation = $_.InstallLocation
                    UninstallString = $_.UninstallString
                }
            }
    }

    $installedApps = $installedApps | Sort-Object Name -Unique

    # --- Aplikasi jarang digunakan ---
    $rareApps = @()
    $runningNames = $runningProcesses.Name

    foreach ($app in $installedApps) {
        if ($app.InstallDate) {
            try {
                $installDate = [datetime]::ParseExact($app.InstallDate, 'yyyyMMdd', $null)
                $daysSinceInstall = ((Get-Date) - $installDate).Days
                
                $isRunning = $false
                foreach ($proc in $runningNames) {
                    if ($app.Name -match $proc -or $proc -match $app.Name.Split()[0]) {
                        $isRunning = $true
                        break
                    }
                }
                
                if ($daysSinceInstall -gt 90 -and -not $isRunning) {
                    $rareApps += [PSCustomObject]@{
                        Name = $app.Name
                        Publisher = $app.Publisher
                        InstallDate = $installDate.ToString("yyyy-MM-dd")
                        DaysSinceInstall = $daysSinceInstall
                        UninstallString = $app.UninstallString
                        Recommendation = "Rarely used - consider uninstall"
                    }
                }
            } catch {}
        }
    }

    $AppAnalysis.RarelyUsed = $rareApps | Sort-Object DaysSinceInstall -Descending | Select-Object -First 20

    # --- Aplikasi mencurigakan ---
    $unknownApps = @()
    $trustedPublishers = @(
        "Microsoft Corporation",
        "Google LLC",
        "Mozilla Corporation",
        "Adobe Inc.",
        "Intel Corporation",
        "NVIDIA Corporation",
        "Apple Inc.",
        "Oracle Corporation",
        "VMware, Inc.",
        "Dell Inc.",
        "HP Inc.",
        "Lenovo"
    )

    foreach ($proc in $runningProcesses) {
        if ([string]::IsNullOrWhiteSpace($proc.Company) -or 
            ($trustedPublishers -notcontains $proc.Company -and 
             $proc.Company -notmatch "Microsoft|Windows|Intel|AMD|NVIDIA")) {
            
            $isSuspicious = $false
            if ($proc.Path) {
                $isSuspicious = $proc.Path -notmatch "Program Files|Windows|System32|SysWOW64"
            }
            
            $unknownApps += [PSCustomObject]@{
                Name = $proc.Name
                Company = if($proc.Company){$proc.Company}else{"Unknown"}
                Path = $proc.Path
                RAM_MB = $proc.RAM_MB
                CPU_Percent = $proc.CPU_Percent
                IsSuspicious = $isSuspicious
                Alert = if($isSuspicious){"[WARNING] CHECK - Suspicious path"}else{"[INFO] Unknown publisher"}
            }
        }
    }

    $AppAnalysis.UnknownApps = $unknownApps | Sort-Object IsSuspicious -Descending

    $AppAnalysis.Summary = @{
        TotalRunningApps = $runningProcesses.Count
        TotalInstalledApps = $installedApps.Count
        TotalRarelyUsedApps = $rareApps.Count
        TotalUnknownApps = $unknownApps.Count
        TotalSuspiciousApps = ($unknownApps | Where-Object {$_.IsSuspicious}).Count
        TotalCPU_AllApps = [math]::Round(($runningProcesses | Measure-Object CPU_Percent -Sum).Sum, 2)
        TotalRAM_AllApps_MB = [math]::Round(($runningProcesses | Measure-Object RAM_MB -Sum).Sum, 2)
        AvgRAM_PerApp_MB = [math]::Round(($runningProcesses | Measure-Object RAM_MB -Average).Average, 2)
    }

    return $AppAnalysis
}

$BackgroundJobs += @{
    Name = "AppAnalysis"
    Job = $appAnalysisJob
    Type = "Applications"
}

# ===================================================
# 7. TUNGGU SEMUA BACKGROUND JOBS SELESAI
# ===================================================

Write-Host "`n[WAITING] Semua processes berjalan di background..." -ForegroundColor Cyan
Write-Host "[INFO] Antivirus scan: max 5 menit" -ForegroundColor Gray
Write-Host "[INFO] Browser cleanup: ~30 detik" -ForegroundColor Gray
Write-Host "[INFO] Disk cleanup: ~1 menit" -ForegroundColor Gray
Write-Host "[INFO] App analysis: ~30 detik" -ForegroundColor Gray

# Tunggu semua jobs dengan timeout
$maxWaitTime = 600 # 10 menit total timeout
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($job in $BackgroundJobs) {
    try {
        # Skip if job is null or failed to start
        if (-not $job.Job) {
            Write-Host "`n[$($job.Type)] SKIPPED - $($job.Name) failed to start" -ForegroundColor Yellow
            continue
        }
        
        $remaining = $maxWaitTime - [int]$stopwatch.Elapsed.TotalSeconds
        if ($remaining -gt 0) {
            Write-Host "`n[$($job.Type)] Waiting for $($job.Name)..." -ForegroundColor Yellow
            $result = $job.Job | Wait-Job -Timeout $remaining | Receive-Job -Wait -AutoRemoveJob
            
            if ($job.Type -eq "AV") {
                if ($result -is [hashtable]) {
                    $Report.AVScanResult = $result.AVScanResult
                }
            } elseif ($job.Type -eq "BrowserCache") {
                if ($result -is [hashtable]) {
                    $Report.BrowserCacheCleared = $result
                }
            } elseif ($job.Type -eq "DiskCleanup") {
                if ($result -is [hashtable]) {
                    $Report.RecycleBin = $result.RecycleBin
                    $Report.DiskCleanup = $result.DiskCleanup
                }
            } elseif ($job.Type -eq "DiskHealth_HDS") {
                if ($result -is [hashtable]) {
                    $Report.DiskHealth_HDSentinel = $result
                }
            } elseif ($job.Type -eq "Applications") {
                if ($result) {
                    $Report.ApplicationAnalysis = $result
                }
            }
        } else {
            Write-Host "`n[$($job.Type)] TIMEOUT - $($job.Name) took too long" -ForegroundColor Red
            Stop-Job $job.Job
            Remove-Job $job.Job
        }
    } catch {
        Write-Host "`n[$($job.Type)] ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

$stopwatch.Stop()
Write-Host "`n[OK] All background jobs completed in $([int]$stopwatch.Elapsed.TotalSeconds) seconds" -ForegroundColor Green

# ===================================================
# 8. KIRIM REPORT KE DATABASE BACKEND
# ===================================================

# Kirim Report langsung ke Database Backend API (tanpa simpan file lokal)
Write-Host "`n[SUBMIT] Sending report to backend..." -ForegroundColor Cyan

$retryCount = 0
$maxRetries = [int]$Config.API_RETRY_COUNT
$submitSuccess = $false

while ($retryCount -lt $maxRetries -and -not $submitSuccess) {
    $retryCount++
    
    try {
        if ($retryCount -gt 1) {
            Write-Host "[RETRY] Attempt $retryCount of $maxRetries..." -ForegroundColor Yellow
        }
        
        # Convert report ke JSON
        $jsonBody = $Report | ConvertTo-Json -Depth 10 -Compress
        
        # Kirim POST request ke API
        $response = Invoke-RestMethod -Uri $Config.API_URL -Method Post -Body $jsonBody -ContentType "application/json" -TimeoutSec ([int]$Config.API_TIMEOUT)
        
        if ($response.success) {
            Write-Host "[OK] Report berhasil dikirim ke Database Backend" -ForegroundColor Green
            Write-Host "  Backend: $($Config.API_URL)" -ForegroundColor Gray
            Write-Host "  Server ID: $($response.data.serverId)" -ForegroundColor Cyan
            Write-Host "  Report ID: $($response.data.reportId)" -ForegroundColor Cyan
            $submitSuccess = $true
        } else {
            Write-Host "[ERROR] Backend response error: $($response.error)" -ForegroundColor Yellow
            
            if ($retryCount -lt $maxRetries) {
                $waitTime = $retryCount * 5
                Write-Host "[WAIT] Waiting $waitTime seconds before retry..." -ForegroundColor Gray
                Start-Sleep -Seconds $waitTime
            }
        }
        
    } catch {
        Write-Host "[ERROR] Submit failed: $($_.Exception.Message)" -ForegroundColor Red
        
        if ($retryCount -lt $maxRetries) {
            $waitTime = $retryCount * 5
            Write-Host "[WAIT] Waiting $waitTime seconds before retry..." -ForegroundColor Gray
            Start-Sleep -Seconds $waitTime
        } else {
            Write-Host "[FAILED] Cannot submit report after $maxRetries attempts" -ForegroundColor Red
            Write-Host "[INFO] Report data is available in memory for manual submission" -ForegroundColor Yellow
        }
    }
}

if (-not $submitSuccess) {
    Write-Host "`n[FALLBACK] Saving report to local file as backup..." -ForegroundColor Yellow
    try {
        $backupPath = Join-Path $env:TEMP "maintenance_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupPath -Encoding UTF8
        Write-Host "[OK] Backup saved to: $backupPath" -ForegroundColor Green
        Write-Host "[INFO] You can manually submit this file later" -ForegroundColor Gray
    } catch {
        Write-Host "[ERROR] Cannot save backup: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =============================
# END OF SCRIPT
# =============================
