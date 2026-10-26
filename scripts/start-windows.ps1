<#
.SYNOPSIS
    AUTHENTIX / EduVerify-AI (SIH26261) — Reliable Windows Startup Script
.DESCRIPTION
    Resolves Windows Python launcher pitfalls (avoids Microsoft Store zero-byte python3.exe stub),
    validates Node.js >= 22.5 (for built-in node:sqlite), checks port availability (8001 & 3000),
    initializes migrations and demo seed data, starts the Python OCR & Forensics service on port 8001,
    verifies health endpoints, and runs the full-stack Express + React server on port 3000.
#>

param(
    [switch]$ResetDb = $false,
    [int]$AppPort = 3000,
    [int]$OcrPort = 8001
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " AUTHENTIX / EduVerify-AI (SIH26261) — Windows Startup & Health Check" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

function Resolve-WorkingPython {
    # Prefer Windows py.exe launcher (-3), then python.exe, avoiding the WindowsApps Microsoft Store stub.
    $candidates = @(
        @{ Exe = "py"; Args = @("-3") },
        @{ Exe = "python"; Args = @() },
        @{ Exe = "python3"; Args = @() }
    )

    foreach ($cand in $candidates) {
        $cmd = Get-Command $cand.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }

        # Skip zero-byte Microsoft Store alias under WindowsApps if real Python is not installed
        if ($cmd.Source -like "*\Microsoft\WindowsApps\*" -and $cand.Exe -eq "python3") {
            try {
                $verOut = & $cand.Exe @($cand.Args + @("--version")) 2>&1
                if ($LASTEXITCODE -ne 0 -or ($verOut -notmatch "Python 3\.")) {
                    continue
                }
            } catch {
                continue
            }
        }

        try {
            $verOut = & $cand.Exe @($cand.Args + @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")) 2>$null
            if ($LASTEXITCODE -eq 0 -and $verOut -match "^3\.(\d+)\.") {
                $minor = [int]$Matches[1]
                if ($minor -ge 10) {
                    return @{
                        Exe = $cand.Exe
                        PrefixArgs = $cand.Args
                        Version = $verOut.Trim()
                    }
                }
            }
        } catch {
            continue
        }
    }
    return $null
}

function Test-PortInUse([int]$Port) {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return ($null -ne $conn)
}

function Wait-HttpHealthy([string]$Url, [int]$TimeoutSeconds = 25) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-RestMethod -Uri $Url -Method Get -TimeoutSec 2
            if ($null -ne $resp) { return $resp }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $null
}

# 1. Verify Node.js >= 22.5
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Write-Host "[ERROR] Node.js is not installed or not on PATH. Install Node.js 22.5+ LTS from https://nodejs.org/" -ForegroundColor Red
    exit 1
}
$nodeVerRaw = (& node -v).Trim().TrimStart("v")
$nodeParts = $nodeVerRaw.Split(".")
$nodeMajor = [int]$nodeParts[0]
$nodeMinor = [int]$nodeParts[1]
if ($nodeMajor -lt 22 -or ($nodeMajor -eq 22 -and $nodeMinor -lt 5)) {
    Write-Host "[ERROR] Detected Node.js v$nodeVerRaw. AUTHENTIX requires Node.js >= 22.5.0 for built-in node:sqlite persistence." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Node.js v$nodeVerRaw detected." -ForegroundColor Green

# 2. Verify Python >= 3.10
$pyInfo = Resolve-WorkingPython
if (-not $pyInfo) {
    Write-Host "[WARN] Python 3.10+ was not found (or only Microsoft Store stub exists)." -ForegroundColor Yellow
    Write-Host "       The Node backend will run using its deterministic PDF/PNG fallback adapter," -ForegroundColor Yellow
    Write-Host "       and report OCR microservice status honestly. Install Python 3.10+ from python.org for full microservice mode." -ForegroundColor Yellow
} else {
    Write-Host "[OK] Python $($pyInfo.Version) detected via '$($pyInfo.Exe) $($pyInfo.PrefixArgs -join ' ')'." -ForegroundColor Green
}

# 3. Environment setup
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[OK] Created .env from .env.example." -ForegroundColor Green
}

$env:PORT = "$AppPort"
$env:OCR_SERVICE_PORT = "$OcrPort"
$env:OCR_SERVICE_URL = "http://127.0.0.1:$OcrPort"

# 4. Dependencies check
if (-not (Test-Path "node_modules")) {
    Write-Host "[INFO] Installing npm dependencies..." -ForegroundColor Cyan
    & npm.cmd install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] npm install failed." -ForegroundColor Red
        exit 1
    }
}

# 5. Port collision check
if (Test-PortInUse -Port $AppPort) {
    Write-Host "[ERROR] Port $AppPort is already in use by another process. Stop the conflicting service or pass -AppPort <port>." -ForegroundColor Red
    exit 1
}

# 6. Database initialization & seeding
if ($ResetDb) {
    Write-Host "[INFO] Resetting SQLite database and regenerating synthetic sample fixtures..." -ForegroundColor Cyan
    & npm.cmd run db:reset
} else {
    Write-Host "[INFO] Running database migrations and verifying demo seed records..." -ForegroundColor Cyan
    & npm.cmd run db:migrate
    if ($LASTEXITCODE -eq 0) {
        & npm.cmd run db:seed
    }
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Database initialization failed. Review output above." -ForegroundColor Red
    exit 1
}

# 7. Launch Python OCR & Forensics Microservice (Port 8001)
New-Item -ItemType Directory -Force -Path "logs" | Out-Null
$ocrProc = $null

if ($pyInfo) {
    if (Test-PortInUse -Port $OcrPort) {
        Write-Host "[WARN] Port $OcrPort already has a listener; checking if OCR service is already healthy..." -ForegroundColor Yellow
    } else {
        $ocrArgs = @() + $pyInfo.PrefixArgs + @("services/ocr_service/server.py")
        Write-Host "[INFO] Starting Python OCR & Forensics service on http://127.0.0.1:$OcrPort ..." -ForegroundColor Cyan
        $ocrProc = Start-Process -FilePath $pyInfo.Exe `
            -ArgumentList $ocrArgs `
            -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput "logs\ocr-service.log" `
            -RedirectStandardError "logs\ocr-service.err.log" `
            -NoNewWindow `
            -PassThru
    }

    $ocrHealth = Wait-HttpHealthy -Url "http://127.0.0.1:$OcrPort/health" -TimeoutSeconds 15
    if ($null -eq $ocrHealth) {
        Write-Host "[ERROR] Python OCR service failed health check at http://127.0.0.1:$OcrPort/health" -ForegroundColor Red
        if (Test-Path "logs\ocr-service.err.log") {
            Get-Content "logs\ocr-service.err.log" -Tail 20 | Write-Host -ForegroundColor Red
        }
        if ($ocrProc -and -not $ocrProc.HasExited) { Stop-Process -Id $ocrProc.Id -Force }
        exit 1
    }
    Write-Host "[OK] Python OCR service healthy (tesseract_cli=$($ocrHealth.capabilities.tesseract_cli), pdftotext_cli=$($ocrHealth.capabilities.pdftotext_cli))." -ForegroundColor Green
}

# 8. Launch Full-Stack Server (Port 3000) and cleanly terminate child processes on exit
try {
    Write-Host ""
    Write-Host "Starting AUTHENTIX Full-Stack Server on http://localhost:$AppPort ..." -ForegroundColor Cyan
    Write-Host "Note: Demo accounts are active only when ENABLE_DEMO_MODE=true in .env." -ForegroundColor Gray
    Write-Host "Press Ctrl+C to stop all services." -ForegroundColor Yellow
    Write-Host ""

    & npm.cmd run dev
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] AUTHENTIX server exited with code $LASTEXITCODE." -ForegroundColor Red
        exit $LASTEXITCODE
    }
} finally {
    if ($ocrProc -and -not $ocrProc.HasExited) {
        Write-Host "[INFO] Stopping Python OCR service (PID $($ocrProc.Id))..." -ForegroundColor Cyan
        Stop-Process -Id $ocrProc.Id -Force -ErrorAction SilentlyContinue
    }
}
