# Cara Install & Setup

## Prerequisites
- **Windows 7, 8, 8.1, 10, atau 11**
- **PowerShell 2.0 atau lebih baru**
  - Windows 7 Ultimate: PowerShell 2.0 (built-in) ✅ **SUPPORTED**
  - Windows 10/11: PowerShell 5.1+ (built-in) ✅
  - **Optional**: Untuk performa lebih baik di Windows 7/8, install [Windows Management Framework 5.1](https://www.microsoft.com/download/details.aspx?id=54616)
- Akses Administrator

## Langkah Instalasi

### 1. Download/Clone Script
```powershell
# Clone repository atau copy semua file ke C:\script
```

### 2. Jalankan Create Task Scheduler

**PENTING: Harus run sebagai Administrator!**

```powershell
# Buka PowerShell sebagai Administrator
# (Klik kanan Start Menu → Windows PowerShell (Admin))

# Jalankan script untuk membuat scheduled task
powershell.exe -ExecutionPolicy Bypass -File "C:\script\create-sync-task.ps1"
```

### 3. Verifikasi Task Berhasil Dibuat

**Opsi 1: Via Command**
```powershell
Get-ScheduledTask -TaskName "Maintenance Script Monthly Sync" | Get-ScheduledTaskInfo
```

**Opsi 2: Via Task Scheduler GUI**
```powershell
# Buka Task Scheduler
taskschd.msc
```

Cari task dengan nama: **"Maintenance Script Monthly Sync"**

Pastikan trigger menampilkan:
```
At 12:00 PM on day 1, 2, 3, 4, 5, 6, and 7 of every month
```

### 4. Test Run (Opsional)

```powershell
# Test jalankan task secara manual
Start-ScheduledTask -TaskName "Maintenance Script Monthly Sync"

# Cek log hasil eksekusi
Get-Content C:\script\Logs\sync_*.log -Tail 50
```

## Cara Kerja

1. **Scheduled Task** jalan setiap hari 1-7 setiap bulan jam 12:00 PM
2. **Wrapper Script** (`sync-cloud-wrapper.ps1`) cek apakah sudah sukses bulan ini
3. Jika belum sukses → jalankan `sync-cloud.ps1`
4. Jika sudah sukses → skip dan tunggu bulan depan
5. **Flag file** disimpan di `C:\script\Flags\sync_success_YYYY_MM.flag`

## Folder Structure Setelah Install

```
C:\script\
├── sync-cloud.ps1              # Script utama (di-sync dari cloud)
├── sync-cloud-wrapper.ps1      # Wrapper dengan monthly check logic
├── Logs\                        # Log file eksekusi
│   └── sync_20260105_120000.log
└── Flags\                       # Flag file sukses per bulan
    └── sync_success_2026_01.flag
```

## Troubleshooting

### PowerShell 2.0 Support (Windows 7 Ultimate)
**Script sudah kompatibel dengan PowerShell 2.0!**
- Script akan otomatis menggunakan mode kompatibilitas
- Tidak perlu upgrade PowerShell (optional, tapi direkomendasikan untuk performa)

**Cek versi PowerShell:**
```powershell
$PSVersionTable.PSVersion
```

**Jika ingin upgrade (optional):**
1. Download [Windows Management Framework 5.1](https://www.microsoft.com/download/details.aspx?id=54616)
2. Install sesuai versi Windows (x64/x86)
3. Restart komputer

### Error: "PowerShell 3.0 atau lebih baru diperlukan"
**Catatan:** Error ini tidak lagi muncul. Script sudah support PowerShell 2.0.

### Error: "Script harus dijalankan sebagai Administrator"
**Solusi:** Buka PowerShell dengan klik kanan → **Run as Administrator**

### Task muncul "Daily at 12:00 PM every day"
**Solusi:** Script lama. Hapus task dan jalankan ulang:
```powershell
Unregister-ScheduledTask -TaskName "Maintenance Script Monthly Sync" -Confirm:$false
.\create-sync-task.ps1
```

### Cek apakah task sudah jalan bulan ini
```powershell
Get-Content C:\script\Flags\sync_success_*.flag
```

### Lihat log eksekusi
```powershell
# Log terbaru
Get-Content C:\script\Logs\sync_*.log | Select-Object -Last 100

# Semua log
Get-ChildItem C:\script\Logs\sync_*.log | Sort-Object LastWriteTime
```

### Force run ulang bulan ini (hapus flag)
```powershell
Remove-Item C:\script\Flags\sync_success_*.flag -Force
Start-ScheduledTask -TaskName "Maintenance Script Monthly Sync"
```

## Uninstall

```powershell
# Hapus scheduled task
Unregister-ScheduledTask -TaskName "Maintenance Script Monthly Sync" -Confirm:$false

# Hapus file (opsional)
Remove-Item C:\script -Recurse -Force
``` 

