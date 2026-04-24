@echo off
echo 🎨 Starting Frontend...
echo ======================

:: Check for environment file
if not exist .env.local (
    if exist env.example (
        echo 📝 Creating .env.local from env.example...
        copy env.example .env.local
    ) else (
        echo ⚠️  No .env.local file found!
    )
)

:: Install dependencies if node_modules is missing
if not exist node_modules (
    echo 📦 Installing frontend dependencies (this may take a minute)...
    npm install
)

echo.
echo 🏃‍♂️ Starting Next.js development server...
echo 🌐 Frontend UI will be available at: http://localhost:3000
echo.

:: Note: Next.js handles port conflicts automatically
npm run dev -- -p 3000
pause
