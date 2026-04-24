#!/bin/bash

echo "🚀 Starting Zero Trust Framework Frontend"
echo "========================================"

# Navigate to frontend directory
cd apps/security-ui

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    npm install
fi

# Check environment configuration
if [ ! -f ".env.local" ] && [ ! -f ".env" ]; then
    echo "⚠️  Frontend env file not found!"
    echo "Please create apps/security-ui/.env.local with NEXT_PUBLIC_FIREBASE_* and NEXT_PUBLIC_BACKEND_URL"
else
    echo "✅ Environment configuration found"
fi

echo ""
echo "🔧 Configuration:"
echo "   Backend URL: ${NEXT_PUBLIC_BACKEND_URL:-http://localhost:5001}"
PORT=3000
while lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; do
    PORT=$((PORT+1))
done
echo "   Port: $PORT"
echo ""

# Start the Next.js development server
echo "🏃‍♂️ Starting Next.js development server..."
npm run dev -- -p $PORT