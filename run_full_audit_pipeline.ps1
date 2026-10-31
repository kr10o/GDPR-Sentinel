<#
.SYNOPSIS
    GDPR Sentinel - Cjeloviti Windows 10 Pipeline (Crawler -> Risk Analyzer -> PDF Generator)
.DESCRIPTION
    Podiže .venv, pokreće dubinski crawler nad učitanim domenama u data/scans/,
    analizira pre-consent kolačiće i podstranice te generira PDF izvještaje u output/pdf/ i generated_docs/.
#>

param (
    [string[]]$Domains = @(),
    [switch]$RemoveVenvOnExit = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$VenvDir = Join-Path $ProjectRoot ".venv"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$PipExe = Join-Path $VenvDir "Scripts\pip.exe"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " GDPR SENTINEL - FULL AUDIT & PDF PIPELINE (WINDOWS 10 .venv)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

try {
    if (-not (Test-Path $PythonExe)) {
        Write-Host "[1/5] Kreiram lokalno virtualno okruženje (.venv)..." -ForegroundColor Yellow
        python -m venv $VenvDir
    } else {
        Write-Host "[1/5] Aktiviram postojeće .venv okruženje..." -ForegroundColor Green
    }

    Write-Host "[2/5] Provjeravam i instaliram ovisnosti (requirements.txt)..." -ForegroundColor Yellow
    & $PythonExe -m pip install --upgrade pip --quiet
    & $PipExe install -r (Join-Path $ProjectRoot "requirements.txt") --quiet

    Write-Host "[3/5] Pokrećem dubinsko pretraživanje domena i podstranica (scanner.py)..." -ForegroundColor Cyan
    if ($Domains.Count -gt 0) {
        & $PythonExe (Join-Path $ProjectRoot "scanner.py") @Domains
    } else {
        & $PythonExe (Join-Path $ProjectRoot "scanner.py") --rescan-all
    }

    Write-Host "[4/5] Generiram PDF izvještaje s tablicama pre-consent kolačića i podstranica (generator.py)..." -ForegroundColor Cyan
    & $PythonExe (Join-Path $ProjectRoot "generator.py")

    Write-Host "`n[OK] Provjera izlaznih PDF dokumenata u output/pdf/:" -ForegroundColor Green
    Get-ChildItem -Path (Join-Path $ProjectRoot "output\pdf\*.pdf") | ForEach-Object {
        Write-Host ("  -> {0,-22} ({1:N1} KB) | Ažurirano: {2}" -f $_.Name, ($_.Length / 1KB), $_.LastWriteTime) -ForegroundColor White
    }
}
finally {
    Write-Host "`n[5/5] Zatvaranje sesije i čišćenje..." -ForegroundColor Cyan
    if (Get-Command deactivate -ErrorAction SilentlyContinue) {
        deactivate
    }
    if ($RemoveVenvOnExit -and (Test-Path $VenvDir)) {
        Remove-Item -Recurse -Force $VenvDir
        Write-Host "Privremeni .venv direktorij je uklonjen." -ForegroundColor Yellow
    }
    Write-Host "Cjevovod uspješno završen." -ForegroundColor Green
}
