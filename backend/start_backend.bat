@echo off
echo 📡 Starting Backend...
echo =====================

:: Check for environment file
if not exist .env (
    if exist .env.example (
        echo 📝 Creating .env from .env.example...
        copy .env.example .env
    ) else (
        echo ⚠️  No .env file found!
    )
)

:: Check for Firebase credentials
if not exist firebase-credentials.json (
    if exist firebase-credentials.json.example (
        echo 📝 Creating firebase-credentials.json from example...
        copy firebase-credentials.json.example firebase-credentials.json
    )
    echo ⚠️  Firebase credentials not found. Some features may be limited.
)

:: Virtual environment management
if not exist venv (
    echo 📦 Creating virtual environment...
    python -m venv venv
)

echo ✅ Activating virtual environment...
call venv\Scripts\activate

echo 📦 Installing dependencies...
pip install -r requirements_minimal.txt

:: Set environment variables
set FLASK_ENV=development
set CORS_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

echo.
echo 🏃‍♂️ Starting Flask server...
echo 📍 API will be available at: http://localhost:5001
echo.

python run.py
pause
