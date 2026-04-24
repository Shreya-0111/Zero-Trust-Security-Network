#!/bin/bash

echo "🚀 Starting Zero Trust Framework Backend"
echo "======================================="

# Navigate to backend directory
cd backend

# Check if virtual environment exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "✅ Virtual environment activated"
else
    echo "⚠️  No virtual environment found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    echo "✅ Virtual environment created and activated"
fi

# Install/update dependencies
echo "📦 Installing minimal dependencies..."
pip install -r requirements_minimal.txt

# Check if Firebase credentials exist
if [ ! -f "firebase-credentials.json" ]; then
    echo "⚠️  Firebase credentials not found!"
    echo "Please download firebase-credentials.json from Firebase Console"
    echo "and place it in the backend directory"
fi

# Set environment variables
export FLASK_ENV=development
export CORS_ORIGINS="http://localhost:3000,http://127.0.0.1:3000"

echo ""
echo "🔧 Configuration:"
echo "   Environment: $FLASK_ENV"
echo "   CORS Origins: $CORS_ORIGINS"
echo "   Port: 5001"
echo ""

# Start the server
echo "🏃‍♂️ Starting Flask server..."
python run.py