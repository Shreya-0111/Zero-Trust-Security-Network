#!/bin/bash

echo "🚀 Starting Zero Trust Framework (Proper Setup)"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Creating one..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "✅ Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
echo "📦 Checking dependencies..."
if ! python -c "import flask" 2>/dev/null; then
    echo "📦 Installing dependencies..."
    pip install -r requirements_minimal.txt
else
    echo "✅ Dependencies already installed"
fi

# Check if Firebase credentials exist
if [ ! -f "firebase-credentials.json" ]; then
    echo "⚠️  Warning: firebase-credentials.json not found"
    echo "   Please ensure your Firebase credentials are properly configured"
fi

# Set environment variables
export FLASK_ENV=development
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

echo "🏃‍♂️ Starting Flask server..."
echo "📍 API will be available at: http://localhost:5001"
echo "🔗 Test endpoints:"
echo "- GET  http://localhost:5001/health"
echo "- POST http://localhost:5001/api/auth/verify"
echo ""

# Start the server
python run.py