<#
.SYNOPSIS
    GDPR Sentinel - Windows 10 .venv Lifecycle & Crawler Runner
.DESCRIPTION
    Automatski podiže lokalno virtualno okruženje (.venv), instalira ovisnosti,
    pokreće višeslojni GDPR crawler nad svim učitanim domenama u data/scans/,
    te čisto deaktivira (i opcijski briše) .venv nakon završetka.
#>

param (
    [string[]]$Domains = @(),
    [switch]$InstallPlaywrightBrowser = $false,
    [switch]$StartWebApp = $false,
    [switch]$RemoveVenvOnExit = $false
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$VenvDir = Join-Path $ProjectRoot ".venv"
$PythonExe = Join-Path $VenvDir "Scripts\python.exe"
$PipExe = Join-Path $VenvDir "Scripts\pip.exe"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " GDPR SENTINEL - INICIJALIZACIJA LOKALNOG OKRUŽENJA (.venv)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

try {
    if (-not (Test-Path $PythonExe)) {
        Write-Host "[1/4] Kreiram izolirano Python virtualno okruženje u .venv..." -ForegroundColor Yellow
        python -m venv $VenvDir
    } else {
        Write-Host "[1/4] Pronađeno postojeće .venv okruženje." -ForegroundColor Green
    }

    Write-Host "[2/4] Nadograđujem pip i instaliram ovisnosti iz requirements.txt..." -ForegroundColor Yellow
    & $PythonExe -m pip install --upgrade pip --quiet
    & $PipExe install -r (Join-Path $ProjectRoot "requirements.txt") --quiet

    if ($InstallPlaywrightBrowser) {
        Write-Host "[2.1/4] Instaliram Playwright Chromium headless engine..." -ForegroundColor Yellow
        & $PythonExe -m playwright install chromium
    }

    Write-Host "[3/4] Pokrećem napredni GDPR Crawler..." -ForegroundColor Cyan
    if ($Domains.Count -gt 0) {
        & $PythonExe (Join-Path $ProjectRoot "scanner.py") @Domains
    } else {
        & $PythonExe (Join-Path $ProjectRoot "batch_rescan.py")
    }

    if (Test-Path (Join-Path $ProjectRoot "tests\test_regressions.py")) {
        Write-Host "[3.1/4] Pokrećem regresijske testove (tests/test_regressions.py)..." -ForegroundColor Yellow
        & $PythonExe -m unittest discover -s tests -p "test_*.py"
    }

    if ($StartWebApp -and (Test-Path (Join-Path $ProjectRoot "app.py"))) {
        Write-Host "[3.2/4] Pokrećem GDPR Sentinel SaaS Web sučelje (app.py)..." -ForegroundColor Green
        & $PythonExe (Join-Path $ProjectRoot "app.py")
    }
}
finally {
    Write-Host "[4/4] Čišćenje i zatvaranje sesije..." -ForegroundColor Cyan
    if (Get-Command deactivate -ErrorAction SilentlyContinue) {
        deactivate
    }
    if ($RemoveVenvOnExit -and (Test-Path $VenvDir)) {
        Write-Host "Uklanjam privremeno .venv okruženje..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force $VenvDir
        Write-Host ".venv uspješno uklonjen." -ForegroundColor Green
    }
    Write-Host "Proces uspješno završen." -ForegroundColor Green
}
