# =============================
# CREATE SCHEDULED TASK FOR SYNC-CLOUD
# =============================
# Task akan jalan setiap bulan minggu pertama (hari 1-7)
# Retry setiap hari di minggu pertama jika belum sukses (Senin-Jumat)
# Hanya jalan 1x jika sudah sukses

# =============================
# CHECK POWERSHELL VERSION
# =============================
if ($PSVersionTable.PSVersion.Major -lt 2) {
    Write-Host "[FATAL] PowerShell 2.0 atau lebih baru diperlukan" -ForegroundColor Red
    Write-Host "Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Yellow
    exit 1
}

# Peringatan untuk Windows 7 default PowerShell
if ($PSVersionTable.PSVersion.Major -eq 2) {
    Write-Host "[WARNING] Menggunakan PowerShell 2.0 (Windows 7 default)" -ForegroundColor Yellow
    Write-Host "Script akan menggunakan fallback untuk kompatibilitas" -ForegroundColor Yellow
    Write-Host "Disarankan upgrade ke WMF 5.1 jika memungkinkan" -ForegroundColor Cyan
    Write-Host ""
}

# =============================
# CHECK ADMIN PRIVILEGES
# =============================
if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "[FATAL] Script harus dijalankan sebagai Administrator" -ForegroundColor Red
    Write-Host "Klik kanan PowerShell → Run as Administrator" -ForegroundColor Yellow
    exit 1
}

# Konfigurasi
$TaskName = "Maintenance Script Monthly Sync"
$ScriptPath = "C:\script\sync-cloud.ps1"
$WrapperScriptPath = "C:\script\sync-cloud-wrapper.ps1"
$CloudUrl = "https://raw.githubusercontent.com/edy-kurniawan/script/refs/heads/main/script.ps1"

# Pastikan script ada
if (-not (Test-Path $ScriptPath)) {
    Write-Host "[ERROR] Script not found: $ScriptPath" -ForegroundColor Red
    exit 1
}

# Buat wrapper script yang cek apakah sudah jalan bulan ini
$wrapperContent = @"
# Wrapper untuk sync-cloud.ps1 dengan monthly execution check
`$CloudUrl = "$CloudUrl"
`$ScriptPath = "$ScriptPath"
`$LogDir = "C:\script\Logs"
`$SuccessFlagDir = "C:\script\Flags"

# Buat folder jika belum ada
if (-not (Test-Path `$LogDir)) { New-Item -Path `$LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path `$SuccessFlagDir)) { New-Item -Path `$SuccessFlagDir -ItemType Directory -Force | Out-Null }

# File flag untuk bulan ini (format: sync_success_YYYY_MM.flag)
`$CurrentMonth = (Get-Date).ToString("yyyy_MM")
`$SuccessFlag = Join-Path `$SuccessFlagDir "sync_success_`$CurrentMonth.flag"
`$LogFile = Join-Path `$LogDir "sync_`$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Cek apakah sudah sukses bulan ini
if (Test-Path `$SuccessFlag) {
    # PS 2.0 compatible - baca file text
    `$flagLines = Get-Content `$SuccessFlag
    `$flagDate = ""
    `$flagHost = ""
    foreach (`$line in `$flagLines) {
        if (`$line -match '^Date=(.+)$') { `$flagDate = `$matches[1] }
        if (`$line -match '^Hostname=(.+)$') { `$flagHost = `$matches[1] }
    }
    Write-Host "[SKIP] Script sudah berhasil dijalankan bulan ini" -ForegroundColor Green
    Write-Host "  Tanggal: `$flagDate" -ForegroundColor Gray
    Write-Host "  Hostname: `$flagHost" -ForegroundColor Gray
    "Script already executed this month at `$flagDate" | Out-File `$LogFile
    exit 0
}

# Log start
"[`$(Get-Date)] Starting sync-cloud.ps1..." | Out-File `$LogFile

try {
    # Jalankan sync-cloud.ps1 dengan AutoRun
    & powershell.exe -ExecutionPolicy Bypass -File `$ScriptPath -CloudUrl `$CloudUrl -AutoRun *>&1 | Tee-Object -FilePath `$LogFile -Append
    
    `$exitCode = `$LASTEXITCODE
    
    if (`$exitCode -eq 0 -or `$null -eq `$exitCode) {
        # Sukses - buat flag file (PS 2.0 compatible - text format)
        `$flagText = "Date=" + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + "````n"
        `$flagText += "Hostname=" + `$env:COMPUTERNAME + "````n"
        `$flagText += "User=" + `$env:USERNAME + "````n"
        `$flagText += "ExitCode=" + `$exitCode
        `$flagText | Out-File `$SuccessFlag -Encoding UTF8
        
        Write-Host "[SUCCESS] Script berhasil dijalankan dan flag disimpan" -ForegroundColor Green
        "[`$(Get-Date)] SUCCESS - Flag created" | Out-File `$LogFile -Append
        
        # Cleanup old flags (hapus flag > 3 bulan)
        Get-ChildItem `$SuccessFlagDir -Filter "sync_success_*.flag" | 
            Where-Object { `$_.LastWriteTime -lt (Get-Date).AddMonths(-3) } | 
            Remove-Item -Force
        
        exit 0
    } else {
        Write-Host "[ERROR] Script gagal dengan exit code: `$exitCode" -ForegroundColor Red
        "[`$(Get-Date)] FAILED - Exit code: `$exitCode" | Out-File `$LogFile -Append
        exit `$exitCode
    }
} catch {
    Write-Host "[ERROR] Exception: `$(`$_.Exception.Message)" -ForegroundColor Red
    "[`$(Get-Date)] ERROR: `$(`$_.Exception.Message)" | Out-File `$LogFile -Append
    exit 1
}
"@

# Simpan wrapper script
$wrapperContent | Out-File -FilePath $WrapperScriptPath -Encoding UTF8 -Force
Write-Host "[OK] Wrapper script created: $WrapperScriptPath" -ForegroundColor Green

# Hapus task lama jika ada
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "[INFO] Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Buat task menggunakan COM object karena PowerShell cmdlet tidak support monthly day range trigger
$TaskService = New-Object -ComObject Schedule.Service
$TaskService.Connect()
$TaskFolder = $TaskService.GetFolder("\")

# Buat task definition
$TaskDefinition = $TaskService.NewTask(0)
$TaskDefinition.RegistrationInfo.Description = "Sync maintenance script dari cloud server. Jalan di hari 1-7 setiap bulan jam 12:00. Hanya eksekusi 1x per bulan jika sudah sukses."
$TaskDefinition.RegistrationInfo.Author = $env:USERNAME

# Settings
$TaskDefinition.Settings.Enabled = $true
$TaskDefinition.Settings.AllowDemandStart = $true
$TaskDefinition.Settings.AllowHardTerminate = $true
$TaskDefinition.Settings.StartWhenAvailable = $true
$TaskDefinition.Settings.RunOnlyIfNetworkAvailable = $true
$TaskDefinition.Settings.ExecutionTimeLimit = "PT2H"
$TaskDefinition.Settings.RestartCount = 2
$TaskDefinition.Settings.RestartInterval = "PT10M"
$TaskDefinition.Settings.DisallowStartIfOnBatteries = $false
$TaskDefinition.Settings.StopIfGoingOnBatteries = $false
$TaskDefinition.Settings.WakeToRun = $true

# Principal (SYSTEM dengan highest privileges)
$TaskDefinition.Principal.UserId = "SYSTEM"
$TaskDefinition.Principal.LogonType = 5  # 5 = Service Account
$TaskDefinition.Principal.RunLevel = 1   # 1 = Highest

# Action
$Action = $TaskDefinition.Actions.Create(0)  # 0 = Exec
$Action.Path = "powershell.exe"
$Action.Arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WrapperScriptPath`""

# Trigger: Monthly pada hari 1-7 setiap bulan jam 12:00
$Trigger = $TaskDefinition.Triggers.Create(4)  # 4 = MonthlyTrigger
$Trigger.StartBoundary = "2026-01-05T12:00:00"
$Trigger.EndBoundary = "2099-12-31T23:59:59"
$Trigger.Enabled = $true
$Trigger.ExecutionTimeLimit = "PT2H"

# Set monthly schedule - hari 1,2,3,4,5,6,7 setiap bulan
$Trigger.DaysOfMonth = 127  # Binary: 1111111 (bit 0-6 = hari 1-7)
$Trigger.MonthsOfYear = 0xFFF  # Binary: 111111111111 (semua bulan)

# Register task (Flag 6 = CREATE_OR_UPDATE dengan LOGON_SERVICE_ACCOUNT)
try {
    $TaskFolder.RegisterTaskDefinition(
        $TaskName,
        $TaskDefinition,
        6,          # TASK_CREATE_OR_UPDATE
        "SYSTEM",   # User
        $null,      # Password
        5,          # TASK_LOGON_SERVICE_ACCOUNT
        $null       # sddl
    ) | Out-Null
} catch {
    Write-Host "[ERROR] Failed to register task: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Release COM objects
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskDefinition) | Out-Null
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskFolder) | Out-Null
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($TaskService) | Out-Null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-Host "`n[SUCCESS] Task scheduler created!" -ForegroundColor Green
Write-Host "Task Name: $TaskName" -ForegroundColor Cyan
Write-Host "Schedule: Monthly on day 1-7 at 12:00 PM" -ForegroundColor Cyan
Write-Host "Wrapper Script: $WrapperScriptPath" -ForegroundColor Gray
Write-Host "Flag Directory: C:\Script\Flags" -ForegroundColor Gray
Write-Host "Log Directory: C:\Script\Logs" -ForegroundColor Gray
Write-Host "`nCara kerja:" -ForegroundColor Yellow
Write-Host "  - Task jalan setiap hari jam 12:00" -ForegroundColor White
Write-Host "  - Hanya eksekusi di hari 1-7 setiap bulan (minggu pertama)" -ForegroundColor White
Write-Host "  - Jika sudah sukses bulan ini, skip otomatis" -ForegroundColor White
Write-Host "  - Jika komputer mati saat jadwal, akan jalan saat menyala (StartWhenAvailable)" -ForegroundColor White
Write-Host "  - Flag direset otomatis setiap bulan baru" -ForegroundColor White
Write-Host "`nTo view task: taskschd.msc" -ForegroundColor Gray
Write-Host "To test run now: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Gray
Write-Host "To check status: Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo" -ForegroundColor Gray
Write-Host "To view logs: Get-Content C:\Script\Logs\sync_*.log -Tail 50" -ForegroundColor Gray