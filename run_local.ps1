Write-Host "🚀 Starting Zero Trust Security Framework (Integrated PowerShell)" -ForegroundColor Cyan
Write-Host "=========================================================="

# Set environment variables
$env:FLASK_ENV = "development"
$env:CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"

# Kill existing processes
Write-Host "🧹 Cleaning up existing processes..."
$backendPort = 5001
$frontendPort = 3000

$backendProc = Get-NetTCPConnection -LocalPort $backendPort -ErrorAction SilentlyContinue
if ($backendProc) {
    Write-Host "🛑 Stopping backend process"
    Stop-Process -Id $backendProc.OwningProcess -Force -ErrorAction SilentlyContinue
}

$frontendProc = Get-NetTCPConnection -LocalPort $frontendPort -ErrorAction SilentlyContinue
if ($frontendProc) {
    Write-Host "🛑 Stopping frontend process"
    Stop-Process -Id $frontendProc.OwningProcess -Force -ErrorAction SilentlyContinue
}

# Start Backend
Write-Host "`n📡 Setting up Backend..."
Push-Location backend
if (-not (Test-Path "venv")) {
    Write-Host "📦 Creating virtual environment..."
    python -m venv venv
}
& ".\venv\Scripts\Activate.ps1"
Write-Host "📦 Installing dependencies..."
pip install -r requirements_minimal.txt
Write-Host "🏃 Starting Backend..."
Start-Process python -ArgumentList "run.py" -NoNewWindow
Pop-Location

# Start Frontend
Write-Host "`n🎨 Setting up Frontend..."
Push-Location apps\security-ui
if (-not (Test-Path "node_modules")) {
    Write-Host "📦 Installing dependencies..."
    npm install
}

Write-Host "`n🎉 Everything is starting up!"
Write-Host "🌐 Frontend: http://localhost:3000"
Write-Host "📍 Backend:  http://localhost:5001"
Write-Host "=========================================================="
Write-Host "`nLOGS WILL APPEAR BELOW:`n"

npm run dev -- -p 3000
Pop-Location
