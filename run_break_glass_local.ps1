# Break-Glass local runner (Windows PowerShell)
# Usage (from repo root):
#   powershell -ExecutionPolicy Bypass -File .\run_break_glass_local.ps1
# Optional:
#   $env:BACKEND_REQUIREMENTS_FILE = "requirements.txt"
#   $env:SKIP_BACKEND_INSTALL = "1"
#   $env:SKIP_FRONTEND_INSTALL = "1"
#
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $RootDir "backend"
$FrontendDir = Join-Path $RootDir "apps\security-ui"

$BackendPort = if ($env:BACKEND_PORT) { [int]$env:BACKEND_PORT } else { 5001 }
$FrontendPortStart = if ($env:FRONTEND_PORT_START) { [int]$env:FRONTEND_PORT_START } else { 3000 }
$BackendRequirementsFile = if ($env:BACKEND_REQUIREMENTS_FILE) { $env:BACKEND_REQUIREMENTS_FILE } else { "requirements_minimal.txt" }
$SkipFrontendInstall = if ($env:SKIP_FRONTEND_INSTALL) { $env:SKIP_FRONTEND_INSTALL } else { "0" }
$SkipBackendInstall = if ($env:SKIP_BACKEND_INSTALL) { $env:SKIP_BACKEND_INSTALL } else { "0" }

function Have-Cmd($name) {
  return $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

function Test-PortListening($port) {
  try {
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    return $null -ne $conn
  } catch {
    # Fallback if Get-NetTCPConnection isn't available
    try {
      $null = (Test-NetConnection -ComputerName "localhost" -Port $port -WarningAction SilentlyContinue)
      return $false
    } catch {
      return $false
    }
  }
}

function Pick-FreePort($startPort) {
  $p = $startPort
  while (Test-PortListening $p) { $p++ }
  return $p
}

function Wait-BackendHealth($url, $seconds) {
  for ($i=0; $i -lt $seconds; $i++) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2 | Out-Null
      return
    } catch {
      Start-Sleep -Seconds 1
    }
  }
  throw "Backend did not become healthy at $url within ${seconds}s."
}

Write-Host "🚀 Starting Break-Glass (local)" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

if (-not (Have-Cmd python)) {
  throw "python not found. Install Python 3 and ensure it's on PATH."
}
if (-not (Have-Cmd node) -or -not (Have-Cmd npm)) {
  throw "node/npm not found. Install Node.js (LTS recommended)."
}
if (-not (Test-Path $BackendDir)) { throw "Backend folder not found: $BackendDir" }
if (-not (Test-Path $FrontendDir)) { throw "Frontend folder not found: $FrontendDir" }

# Backend
Write-Host "📡 Backend: ensuring venv + deps" -ForegroundColor Yellow
if (Test-PortListening $BackendPort) {
  Write-Host "✅ Backend already listening on port $BackendPort" -ForegroundColor Green
} else {
  Push-Location $BackendDir

  if (-not (Test-Path "venv")) {
    Write-Host "🔄 Creating backend venv" -ForegroundColor Yellow
    python -m venv venv
  }

  $Activate = Join-Path $BackendDir "venv\Scripts\Activate.ps1"
  if (-not (Test-Path $Activate)) {
    throw "Cannot find venv activation script at: $Activate"
  }
  . $Activate

  if ($SkipBackendInstall -ne "1") {
    $ReqPath = Join-Path $BackendDir $BackendRequirementsFile
    if (-not (Test-Path $ReqPath)) {
      throw "Requirements file not found: backend\$BackendRequirementsFile (set BACKEND_REQUIREMENTS_FILE if needed)"
    }
    Write-Host "📦 Installing backend deps from $BackendRequirementsFile" -ForegroundColor Yellow
    python -m pip install --upgrade pip | Out-Null
    pip install -r $ReqPath | Out-Null
  } else {
    Write-Host "⏭️  Skipping backend dependency install (SKIP_BACKEND_INSTALL=1)" -ForegroundColor DarkYellow
  }

  Write-Host "🏃 Starting backend on http://localhost:$BackendPort" -ForegroundColor Yellow
  $BackendProc = Start-Process -FilePath "python" -ArgumentList "run.py" -NoNewWindow -PassThru
  Pop-Location
}

Write-Host "⏱️  Waiting for backend health..." -ForegroundColor Yellow
Wait-BackendHealth -url "http://localhost:$BackendPort/health" -seconds 30
Write-Host "✅ Backend health OK" -ForegroundColor Green

# Frontend
Write-Host "🎨 Frontend: ensuring deps + starting dev server" -ForegroundColor Yellow
$FrontendPort = Pick-FreePort $FrontendPortStart
Push-Location $FrontendDir

if ($SkipFrontendInstall -ne "1") {
  if (-not (Test-Path "node_modules")) {
    if (Have-Cmd pnpm) {
      Write-Host "📦 Installing frontend deps (pnpm)" -ForegroundColor Yellow
      pnpm install
    } else {
      Write-Host "📦 Installing frontend deps (npm)" -ForegroundColor Yellow
      npm install
    }
  } else {
    Write-Host "✅ Frontend deps already present (node_modules)" -ForegroundColor Green
  }
} else {
  Write-Host "⏭️  Skipping frontend dependency install (SKIP_FRONTEND_INSTALL=1)" -ForegroundColor DarkYellow
}

Write-Host "🏃 Starting frontend on http://localhost:$FrontendPort" -ForegroundColor Yellow
if (Have-Cmd pnpm) {
  $FrontendProc = Start-Process -FilePath "pnpm" -ArgumentList @("dev","--","--port", "$FrontendPort") -NoNewWindow -PassThru
} else {
  $FrontendProc = Start-Process -FilePath "npm" -ArgumentList @("run","dev","--","-p", "$FrontendPort") -NoNewWindow -PassThru
}
Pop-Location

Write-Host "" 
Write-Host "🎉 Break-Glass local stack is up" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host "📍 Backend API:  http://localhost:$BackendPort" -ForegroundColor White
Write-Host "🌐 Frontend UI:  http://localhost:$FrontendPort" -ForegroundColor White
Write-Host "➡️  Go to:        /emergency-access" -ForegroundColor White
Write-Host "" 
Write-Host "Close this window or press Ctrl+C to stop." -ForegroundColor DarkGray

try {
  while ($true) { Start-Sleep -Seconds 2 }
} finally {
  Write-Host "\n🧹 Stopping services..." -ForegroundColor Yellow
  if ($FrontendProc -and -not $FrontendProc.HasExited) { Stop-Process -Id $FrontendProc.Id -Force -ErrorAction SilentlyContinue }
  if ($BackendProc -and -not $BackendProc.HasExited) { Stop-Process -Id $BackendProc.Id -Force -ErrorAction SilentlyContinue }
}
