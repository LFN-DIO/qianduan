param(
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$AppRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $AppRoot ".venv\Scripts\python.exe"
$AppBaseUrl = "http://127.0.0.1:8000"
$AppUrl = "$AppBaseUrl/?v=20261024-500mb"

try {
    $AlreadyRunning = $false
    try {
        $Health = Invoke-RestMethod -Uri "$AppBaseUrl/api/health" -TimeoutSec 3
        $AlreadyRunning = $Health.status -eq "ok"
    } catch {
        $AlreadyRunning = $false
    }

    if ($AlreadyRunning) {
        Write-Host "MMD Sentinel is already running." -ForegroundColor Green
        if (-not $NoBrowser) {
            Start-Process $AppUrl
        }
        exit 0
    }

    $ExistingListener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    if ($ExistingListener) {
        throw "Port 8000 is already used by another application. Close it and run again."
    }

    if (-not (Test-Path $Python)) {
        Write-Host "Creating virtual environment..." -ForegroundColor Cyan
        python -m venv (Join-Path $AppRoot ".venv")
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $Python)) {
            throw "Unable to create .venv. Make sure Python is installed and available in PATH."
        }
    }

    & $Python -c "import importlib.util, sys; modules=['fastapi','uvicorn','torch','androguard']; sys.exit(0 if all(importlib.util.find_spec(name) for name in modules) else 1)"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing dependencies. The first launch can take several minutes..." -ForegroundColor Cyan
        & $Python -m pip install -r (Join-Path $AppRoot "requirements.txt")
        if ($LASTEXITCODE -ne 0) {
            throw "Dependency installation failed. Check the network and the error above."
        }
    }

    $Schema = Join-Path $AppRoot "data\feature_schema.json"
    if (-not (Test-Path $Schema)) {
        Write-Host "Building feature schema from the training data..." -ForegroundColor Cyan
        & $Python (Join-Path $AppRoot "scripts\build_feature_schema.py")
        if ($LASTEXITCODE -ne 0) {
            throw "Feature schema generation failed."
        }
    }

    if (-not $NoBrowser) {
        Start-Process -FilePath "powershell.exe" -WindowStyle Hidden -ArgumentList @(
            "-NoProfile",
            "-Command",
            "Start-Sleep -Seconds 2; Start-Process '$AppUrl'"
        )
    }

    Write-Host "Starting MMD Sentinel at $AppUrl" -ForegroundColor Green
    Write-Host "Keep this window open while using the application. Press Ctrl+C to stop." -ForegroundColor DarkGray
    & $Python -m uvicorn app.main:app --app-dir $AppRoot --host 127.0.0.1 --port 8000
    if ($LASTEXITCODE -ne 0) {
        throw "The web server stopped with exit code $LASTEXITCODE."
    }
}
catch {
    Write-Host ""
    Write-Host "MMD Sentinel could not start:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to close this window"
    exit 1
}
