#!/bin/bash

# Stop all Flask/Python processes on port 5001
echo "Stopping backend server..."

# Kill all Python processes running run.py
pkill -9 -f "python.*run.py"

# Kill all processes on port 5001
lsof -ti:5001 | xargs kill -9 2>/dev/null

# Wait a moment
sleep 1

# Verify port is free
if lsof -ti:5001 > /dev/null 2>&1; then
    echo "Warning: Port 5001 still in use"
    lsof -ti:5001 | xargs kill -9 2>/dev/null
else
    echo "✓ Backend server stopped successfully"
fi
