<#
.SYNOPSIS
    APIHunter Security Platform — Automated Full Database Backup Script (PowerShell)
    Performs compressed pg_dump, generates SHA-256 integrity checksum,
    and enforces backup retention policy.
#>

param(
    [string]$BackupDir = "C:\Backups\APIHunter",
    [string]$PostgresHost = "localhost",
    [int]$PostgresPort = 5432,
    [string]$PostgresDb = "apihunter_platform",
    [string]$PostgresUser = "postgres"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
}

$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$BackupFile = Join-Path $BackupDir "${PostgresDb}_full_${Timestamp}.dump"
$ChecksumFile = "${BackupFile}.sha256"

Write-Host "[$((Get-Date).ToUniversalTime().ToString("u"))] Starting full database backup for '$PostgresDb'..."

$pgDumpArgs = @(
    "-h", $PostgresHost,
    "-p", $PostgresPort,
    "-U", $PostgresUser,
    "-d", $PostgresDb,
    "-F", "c",
    "-b",
    "-f", $BackupFile
)

Start-Process -FilePath "pg_dump.exe" -ArgumentList $pgDumpArgs -Wait -NoNewWindow

if (Test-Path $BackupFile) {
    $hash = (Get-FileHash -Path $BackupFile -Algorithm SHA256).Hash
    Set-Content -Path $ChecksumFile -Value "$hash  $(Split-Path $BackupFile -Leaf)"

    Write-Host "[$((Get-Date).ToUniversalTime().ToString("u"))] Backup successful: $BackupFile"
    Write-Host "SHA256: $hash"
} else {
    throw "pg_dump failed to produce output file."
}

# Retention cleanup (> 7 days)
Get-ChildItem -Path $BackupDir -Filter "${PostgresDb}_full_*.dump*" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force
Write-Host "Retention cleanup completed."
