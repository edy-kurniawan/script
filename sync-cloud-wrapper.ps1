# =============================
# SYNC-CLOUD WRAPPER WITH MONTHLY CHECK
# =============================
# Support: Windows 7 (incl. Ultimate with PowerShell 2.0), 8, 8.1, 10, 11
# PowerShell: 2.0, 3.0, 4.0, 5.0, 5.1, 7.x (Full compatibility)
# Wrapper untuk sync-cloud.ps1 dengan monthly execution check
$CloudUrl = "https://raw.githubusercontent.com/edy-kurniawan/script/refs/heads/main/script.ps1"
$ScriptPath = "C:\script\sync-cloud.ps1"
$LogDir = "C:\script\Logs"
$SuccessFlagDir = "C:\script\Flags"

# Buat folder jika belum ada
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $SuccessFlagDir)) { New-Item -Path $SuccessFlagDir -ItemType Directory -Force | Out-Null }

# File flag untuk bulan ini (format: sync_success_YYYY_MM.flag)
$CurrentMonth = (Get-Date).ToString("yyyy_MM")
$SuccessFlag = Join-Path $SuccessFlagDir "sync_success_$CurrentMonth.flag"
$LogFile = Join-Path $LogDir "sync_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Cek apakah sudah sukses bulan ini
if (Test-Path $SuccessFlag) {
    # PS 2.0 compatible - baca file text
    $flagLines = Get-Content $SuccessFlag
    $flagDate = ""
    $flagHost = ""
    foreach ($line in $flagLines) {
        if ($line -match '^Date=(.+)$') { $flagDate = $matches[1] }
        if ($line -match '^Hostname=(.+)$') { $flagHost = $matches[1] }
    }
    Write-Host "[SKIP] Script sudah berhasil dijalankan bulan ini" -ForegroundColor Green
    Write-Host "  Tanggal: $flagDate" -ForegroundColor Gray
    Write-Host "  Hostname: $flagHost" -ForegroundColor Gray
    "Script already executed this month at $flagDate" | Out-File $LogFile
    exit 0
}

# Log start
"[$(Get-Date)] Starting sync-cloud.ps1..." | Out-File $LogFile

try {
    # Jalankan sync-cloud.ps1 dengan AutoRun
    & powershell.exe -ExecutionPolicy Bypass -File $ScriptPath -CloudUrl $CloudUrl -AutoRun *>&1 | Tee-Object -FilePath $LogFile -Append
    
    $exitCode = $LASTEXITCODE
    
    if ($exitCode -eq 0 -or $null -eq $exitCode) {
        # Sukses - buat flag file (PS 2.0 compatible - text format)
        $flagDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $flagText = "Date=$flagDate`nHostname=$env:COMPUTERNAME`nUser=$env:USERNAME`nExitCode=$exitCode"
        $flagText | Out-File $SuccessFlag -Encoding UTF8
        
        Write-Host "[SUCCESS] Script berhasil dijalankan dan flag disimpan" -ForegroundColor Green
        "[$(Get-Date)] SUCCESS - Flag created" | Out-File $LogFile -Append
        
        # Cleanup old flags (hapus flag > 3 bulan)
        Get-ChildItem $SuccessFlagDir -Filter "sync_success_*.flag" | 
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddMonths(-3) } | 
            Remove-Item -Force
        
        exit 0
    } else {
        Write-Host "[ERROR] Script gagal dengan exit code: $exitCode" -ForegroundColor Red
        "[$(Get-Date)] FAILED - Exit code: $exitCode" | Out-File $LogFile -Append
        exit $exitCode
    }
} catch {
    Write-Host "[ERROR] Exception: $($_.Exception.Message)" -ForegroundColor Red
    "[$(Get-Date)] ERROR: $($_.Exception.Message)" | Out-File $LogFile -Append
    exit 1
}
