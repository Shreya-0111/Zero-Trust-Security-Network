@echo off
echo 🚀 Starting Zero Trust Security Framework (Integrated Terminal)
echo ==========================================================

:: Set local environment variables
set FLASK_ENV=development
set CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

:: Kill existing processes on 5001 (Backend) and 3000 (Frontend)
echo 🧹 Cleaning up existing processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5001 ^| findstr LISTENING') do (
    echo 🛑 Stopping backend process %%a...
    taskkill /F /PID %%a >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3000 ^| findstr LISTENING') do (
    echo 🛑 Stopping frontend process %%a...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo 📡 Setting up Backend...
cd backend
if not exist venv (
    echo 📦 Creating Python virtual environment...
    python -m venv venv
)
echo ✅ Activating virtual environment...
call venv\Scripts\activate

echo 📦 Installing/Updating dependencies (this may take a moment)...
pip install -r requirements_minimal.txt

echo 🏃 Starting Backend in background...
start /b python run.py
cd ..

echo.
echo 🎨 Setting up Frontend...
cd apps\security-ui
if not exist node_modules (
    echo 📦 Installing Node dependencies...
    npm install
)

echo.
echo 🎉 Everything is starting up!
echo 🌐 Frontend: http://localhost:3000
echo 📍 Backend:  http://localhost:5001
echo ==========================================================
echo LOGS WILL APPEAR BELOW:
echo.

:: Run frontend in the foreground
npm run dev -- -p 3000
