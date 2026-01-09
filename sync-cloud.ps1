# =============================
# SYNC MAINTENANCE SCRIPT FROM CLOUD
# =============================
# Download latest maintenance script dari cloud server
# Support: Windows 7, 8, 8.1, 10, 11

param(
    [string]$CloudUrl = "https://raw.githubusercontent.com/edy-kurniawan/script/refs/heads/main/script.ps1",
    [string]$LocalPath = "C:\script\",
    [string]$ScriptName = "script.ps1",
    [switch]$AutoRun = $true,
    [switch]$ForceDownload = $false,
    [int]$RetryCount = 3
)

# Warna output
$ColorInfo = "Cyan"
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorError = "Red"

Write-Host "`n========================================" -ForegroundColor $ColorInfo
Write-Host "  MAINTENANCE SCRIPT CLOUD SYNC" -ForegroundColor $ColorInfo
Write-Host "========================================" -ForegroundColor $ColorInfo
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Gray

# Deteksi PowerShell version untuk fitur JSON
$UseJson = $PSVersionTable.PSVersion.Major -ge 3
if (-not $UseJson) {
    Write-Host "[INFO] Using PowerShell 2.0 compatibility mode (text format)" -ForegroundColor Yellow
}

# ===================================================
# 1. CEK & BUAT FOLDER LOKAL
# ===================================================

Write-Host "`n[INFO] Checking local folder..." -ForegroundColor $ColorInfo

if (-not (Test-Path $LocalPath)) {
    try {
        New-Item -Path $LocalPath -ItemType Directory -Force | Out-Null
        Write-Host "[OK] Created folder: $LocalPath" -ForegroundColor $ColorSuccess
    } catch {
        Write-Host "[ERROR] Failed to create folder: $($_.Exception.Message)" -ForegroundColor $ColorError
        exit 1
    }
} else {
    Write-Host "[OK] Folder exists: $LocalPath" -ForegroundColor $ColorSuccess
}

$LocalScriptPath = Join-Path $LocalPath $ScriptName
$BackupPath = Join-Path $LocalPath "$($ScriptName).backup"
$VersionFile = Join-Path $LocalPath "version.txt"

# ===================================================
# 2. CEK VERSI LOKAL (jika ada)
# ===================================================

$LocalVersion = $null
$LocalHash = $null

if (Test-Path $LocalScriptPath) {
    Write-Host "`n[INFO] Local script found: $LocalScriptPath" -ForegroundColor $ColorInfo
    
    # Baca versi dari file version.txt
    if (Test-Path $VersionFile) {
        try {
            if ($UseJson) {
                # PowerShell 3.0+ - gunakan JSON
                $versionContent = Get-Content $VersionFile | Out-String
                $versionData = $versionContent | ConvertFrom-Json
                $LocalVersion = $versionData.Version
                $LocalHash = $versionData.Hash
                $LocalDate = $versionData.Date
            } else {
                # PowerShell 2.0 - gunakan format text
                $versionLines = Get-Content $VersionFile
                foreach ($line in $versionLines) {
                    if ($line -match '^Version=(.+)$') { $LocalVersion = $matches[1] }
                    if ($line -match '^Hash=(.+)$') { $LocalHash = $matches[1] }
                    if ($line -match '^Date=(.+)$') { $LocalDate = $matches[1] }
                }
            }
            
            Write-Host "[INFO] Current version: $LocalVersion" -ForegroundColor $ColorInfo
            Write-Host "[INFO] Last updated: $LocalDate" -ForegroundColor $ColorInfo
        } catch {
            Write-Host "[WARNING] Cannot read version file" -ForegroundColor $ColorWarning
        }
    }
    
    # Backup script lama
    if (-not $ForceDownload) {
        try {
            Copy-Item $LocalScriptPath $BackupPath -Force
            Write-Host "[OK] Backup created: $BackupPath" -ForegroundColor $ColorSuccess
        } catch {
            Write-Host "[WARNING] Cannot create backup: $($_.Exception.Message)" -ForegroundColor $ColorWarning
        }
    }
} else {
    Write-Host "`n[INFO] No local script found, will download new copy" -ForegroundColor $ColorInfo
}

# ===================================================
# 3. DOWNLOAD SCRIPT DARI CLOUD
# ===================================================

Write-Host "`n[DOWNLOAD] Downloading from cloud..." -ForegroundColor $ColorInfo
Write-Host "[URL] $CloudUrl" -ForegroundColor Gray

$DownloadSuccess = $false
$Attempt = 0

while ($Attempt -lt $RetryCount -and -not $DownloadSuccess) {
    $Attempt++
    
    try {
        Write-Host "`n[ATTEMPT $Attempt/$RetryCount] Downloading..." -ForegroundColor $ColorInfo
        
        # Download script
        $webClient = New-Object System.Net.WebClient
        $webClient.Encoding = [System.Text.Encoding]::UTF8
        
        # Set timeout (30 detik)
        $webClient.Headers.Add("User-Agent", "PowerShell Maintenance Script Sync/1.0")
        
        $scriptContent = $webClient.DownloadString($CloudUrl)
        
        # PS 2.0 compatible - gunakan IsNullOrEmpty
        if ([string]::IsNullOrEmpty($scriptContent) -or $scriptContent.Trim() -eq "") {
            throw "Downloaded content is empty"
        }
        
        Write-Host "[DEBUG] Downloaded $($scriptContent.Length) bytes" -ForegroundColor Gray
        
        # Validasi script (cek apakah file valid PowerShell)
        # Cek apakah bukan HTML error page
        if ($scriptContent -match '<!DOCTYPE|<html|<head|<body') {
            Write-Host "[ERROR] Downloaded content appears to be HTML, not PowerShell" -ForegroundColor Red
            Write-Host "[DEBUG] First 200 chars: $($scriptContent.Substring(0, [Math]::Min(200, $scriptContent.Length)))" -ForegroundColor Gray
            throw "Downloaded file is HTML (possibly 404 page), not a PowerShell script"
        }
        
        # Validasi lebih fleksibel - cek apakah mengandung syntax PowerShell
        $hasPowerShellSyntax = $scriptContent -match '\$\w+|Get-|Set-|Write-Host|function\s+\w+|param\s*\(|#\s*=+'
        
        if (-not $hasPowerShellSyntax) {
            Write-Host "[ERROR] Downloaded content does not contain PowerShell syntax" -ForegroundColor Red
            Write-Host "[DEBUG] First 500 chars: $($scriptContent.Substring(0, [Math]::Min(500, $scriptContent.Length)))" -ForegroundColor Gray
            throw "Downloaded file is not a valid PowerShell script"
        }
        
        Write-Host "[OK] PowerShell script validated" -ForegroundColor Green
        
        # Hitung hash untuk versi tracking (PS 2.0 compatible)
        if ($UseJson) {
            # PowerShell 3.0+ - gunakan SHA256
            $hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $hashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($scriptContent))
            $NewHash = [System.BitConverter]::ToString($hashBytes).Replace("-","")
        } else {
            # PowerShell 2.0 - gunakan MD5 (lebih sederhana)
            $hashAlgorithm = [System.Security.Cryptography.MD5]::Create()
            $hashBytes = $hashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($scriptContent))
            $NewHash = [System.BitConverter]::ToString($hashBytes).Replace("-","")
        }
        
        # Cek apakah ada perubahan
        if ($LocalHash -eq $NewHash -and -not $ForceDownload) {
            Write-Host "[INFO] Script is already up-to-date (no changes detected)" -ForegroundColor $ColorSuccess
            $DownloadSuccess = $true
            break
        }
        
        # Simpan script ke file lokal
        $scriptContent | Out-File -FilePath $LocalScriptPath -Encoding UTF8 -Force
        
        # Simpan versi info
        $currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $versionString = "Auto-Sync-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        
        if ($UseJson) {
            # PowerShell 3.0+ - gunakan JSON
            $versionInfo = @{
                Version = $versionString
                Hash = $NewHash
                Date = $currentDate
                Source = $CloudUrl
                DownloadedBy = $env:COMPUTERNAME
                PSVersion = $PSVersionTable.PSVersion.ToString()
            }
            $versionInfo | ConvertTo-Json | Out-File -FilePath $VersionFile -Encoding UTF8 -Force
        } else {
            # PowerShell 2.0 - gunakan format text
            $versionText = @"
Version=$versionString
Hash=$NewHash
Date=$currentDate
Source=$CloudUrl
DownloadedBy=$env:COMPUTERNAME
PSVersion=$($PSVersionTable.PSVersion)
"@
            $versionText | Out-File -FilePath $VersionFile -Encoding UTF8 -Force
        }
        
        Write-Host "[OK] Script downloaded successfully!" -ForegroundColor $ColorSuccess
        Write-Host "[OK] Saved to: $LocalScriptPath" -ForegroundColor $ColorSuccess
        Write-Host "[INFO] New version: $versionString" -ForegroundColor $ColorInfo
        Write-Host "[INFO] Hash: $($NewHash.Substring(0,16))..." -ForegroundColor Gray
        
        $DownloadSuccess = $true
        
    } catch {
        Write-Host "[ERROR] Download failed: $($_.Exception.Message)" -ForegroundColor $ColorError
        
        if ($Attempt -lt $RetryCount) {
            $waitTime = $Attempt * 5
            Write-Host "[RETRY] Waiting $waitTime seconds before retry..." -ForegroundColor $ColorWarning
            Start-Sleep -Seconds $waitTime
        }
    }
}

if (-not $DownloadSuccess) {
    Write-Host "`n[FAILED] Cannot download script after $RetryCount attempts" -ForegroundColor $ColorError
    
    # Restore backup jika ada
    if (Test-Path $BackupPath) {
        Write-Host "[RESTORE] Restoring from backup..." -ForegroundColor $ColorWarning
        Copy-Item $BackupPath $LocalScriptPath -Force
        Write-Host "[OK] Backup restored" -ForegroundColor $ColorSuccess
    }
    
    exit 1
}

# ===================================================
# 4. JALANKAN SCRIPT (OPTIONAL)
# ===================================================

if ($AutoRun) {
    Write-Host "`n[EXECUTE] Running maintenance script..." -ForegroundColor $ColorInfo
    
    try {
        & powershell.exe -ExecutionPolicy Bypass -File $LocalScriptPath
        Write-Host "[OK] Script executed successfully" -ForegroundColor $ColorSuccess
    } catch {
        Write-Host "[ERROR] Script execution failed: $($_.Exception.Message)" -ForegroundColor $ColorError
        exit 1
    }
} else {
    Write-Host "`n[INFO] Auto-run is disabled" -ForegroundColor $ColorInfo
    Write-Host "[INFO] To run script manually, use:" -ForegroundColor Gray
    Write-Host "  powershell.exe -ExecutionPolicy Bypass -File `"$LocalScriptPath`"" -ForegroundColor Gray
}

# ===================================================
# 5. CLEANUP
# ===================================================

# Hapus backup lama (lebih dari 7 hari)
try {
    $oldBackups = Get-ChildItem $LocalPath -Filter "*.backup" | 
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) }
    
    if ($oldBackups) {
        $oldBackups | Remove-Item -Force
        Write-Host "`n[CLEANUP] Removed $($oldBackups.Count) old backup(s)" -ForegroundColor $ColorInfo
    }
} catch {
    # Silent fail on cleanup
}

Write-Host "`n========================================" -ForegroundColor $ColorInfo
Write-Host "  SYNC COMPLETED" -ForegroundColor $ColorSuccess
Write-Host "========================================" -ForegroundColor $ColorInfo
Write-Host "Script location: $LocalScriptPath" -ForegroundColor $ColorInfo
Write-Host "Last sync: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor $ColorInfo
Write-Host ""
