#!/bin/bash

echo "🚀 Starting Zero Trust Security Framework"
echo "========================================"

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Start Backend
echo "📡 Starting Backend Server..."
if check_port 5001; then
    echo "✅ Backend already running on port 5001"
else
    echo "🔄 Starting backend on port 5001..."
    cd backend
    chmod +x start_proper.sh
    ./start_proper.sh &
    BACKEND_PID=$!
    cd ..
    echo "✅ Backend started (PID: $BACKEND_PID)"
fi

# Wait a moment for backend to start
sleep 3

# Start Frontend
echo "🎨 Starting Frontend Server..."
FRONTEND_PORT=3000
while check_port $FRONTEND_PORT; do
    FRONTEND_PORT=$((FRONTEND_PORT+1))
done

echo "🔄 Starting frontend on port $FRONTEND_PORT..."
cd apps/security-ui
if [ ! -d "node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    npm install
fi
npm run dev -- -p $FRONTEND_PORT &
FRONTEND_PID=$!
cd ..
echo "✅ Frontend started (PID: $FRONTEND_PID)"

echo ""
echo "🎉 Zero Trust Security Framework Started!"
echo "========================================"
echo "📍 Backend API:  http://localhost:5001"
echo "🌐 Frontend UI:  http://localhost:$FRONTEND_PORT"
echo "🧪 Test Login:   file://$(pwd)/test_login.html"
echo ""
echo "🔗 Quick Test Endpoints:"
echo "- Health Check:  curl http://localhost:5001/health"
echo "- Auth Health:   curl http://localhost:5001/api/auth/health"
echo ""
echo "Press Ctrl+C to stop all services"

# Keep script running
wait