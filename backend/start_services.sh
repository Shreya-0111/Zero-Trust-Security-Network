#!/bin/bash

# Start All Services Script for Zero Trust AI Innovations
# This script starts Redis, RabbitMQ, Ganache, IPFS, Celery workers, and Flask

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Starting Zero Trust AI Services"
echo "=========================================="
echo ""

# Function to check if a service is running
check_service() {
    if pgrep -x "$1" > /dev/null; then
        echo -e "${GREEN}✓ $1 is running${NC}"
        return 0
    else
        echo -e "${RED}✗ $1 is not running${NC}"
        return 1
    fi
}

# Function to start a service in background
start_background() {
    local name=$1
    local command=$2
    local log_file="logs/${name}.log"
    
    mkdir -p logs
    
    echo -e "${BLUE}Starting $name...${NC}"
    nohup $command > "$log_file" 2>&1 &
    echo $! > "logs/${name}.pid"
    sleep 2
    
    if [ -f "logs/${name}.pid" ] && kill -0 $(cat "logs/${name}.pid") 2>/dev/null; then
        echo -e "${GREEN}✓ $name started (PID: $(cat logs/${name}.pid))${NC}"
        echo "  Log: $log_file"
    else
        echo -e "${RED}✗ Failed to start $name${NC}"
    fi
}

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found. Please run setup_infrastructure.sh first.${NC}"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

echo "Step 1: Checking Redis..."
echo "=========================================="
if check_service redis-server; then
    echo "Redis is already running"
else
    echo "Starting Redis..."
    brew services start redis
    sleep 2
fi
echo ""

echo "Step 2: Checking RabbitMQ..."
echo "=========================================="
if pgrep -f rabbitmq > /dev/null; then
    echo -e "${GREEN}✓ RabbitMQ is running${NC}"
else
    echo "Starting RabbitMQ..."
    brew services start rabbitmq
    sleep 3
fi
echo ""

echo "Step 3: Starting Ganache (Blockchain)..."
echo "=========================================="
if pgrep -f ganache > /dev/null; then
    echo -e "${GREEN}✓ Ganache is already running${NC}"
else
    start_background "ganache" "ganache --port 8545 --networkId 1337 --deterministic"
fi
echo ""

echo "Step 4: Starting IPFS Daemon..."
echo "=========================================="
if pgrep -f "ipfs daemon" > /dev/null; then
    echo -e "${GREEN}✓ IPFS daemon is already running${NC}"
else
    start_background "ipfs" "ipfs daemon"
fi
echo ""

echo "Step 5: Starting Celery Worker..."
echo "=========================================="
if pgrep -f "celery.*worker" > /dev/null; then
    echo -e "${GREEN}✓ Celery worker is already running${NC}"
else
    start_background "celery-worker" "celery -A celery_config.celery_app worker --loglevel=info --concurrency=4"
fi
echo ""

echo "Step 6: Starting Celery Beat (Scheduler)..."
echo "=========================================="
if pgrep -f "celery.*beat" > /dev/null; then
    echo -e "${GREEN}✓ Celery beat is already running${NC}"
else
    start_background "celery-beat" "celery -A celery_config.celery_app beat --loglevel=info"
fi
echo ""

echo "=========================================="
echo "All Services Started!"
echo "=========================================="
echo ""
echo "Service Status:"
echo "---------------"
redis-cli ping >/dev/null 2>&1 && echo -e "Redis: ${GREEN}✓ Running${NC}" || echo -e "Redis: ${RED}✗ Not running${NC}"
rabbitmqctl status >/dev/null 2>&1 && echo -e "RabbitMQ: ${GREEN}✓ Running${NC}" || echo -e "RabbitMQ: ${RED}✗ Not running${NC}"
pgrep -f ganache > /dev/null && echo -e "Ganache: ${GREEN}✓ Running${NC}" || echo -e "Ganache: ${RED}✗ Not running${NC}"
pgrep -f "ipfs daemon" > /dev/null && echo -e "IPFS: ${GREEN}✓ Running${NC}" || echo -e "IPFS: ${RED}✗ Not running${NC}"
pgrep -f "celery.*worker" > /dev/null && echo -e "Celery Worker: ${GREEN}✓ Running${NC}" || echo -e "Celery Worker: ${RED}✗ Not running${NC}"
pgrep -f "celery.*beat" > /dev/null && echo -e "Celery Beat: ${GREEN}✓ Running${NC}" || echo -e "Celery Beat: ${RED}✗ Not running${NC}"
echo ""

echo "Logs are available in the logs/ directory"
echo ""
echo "To start the Flask application:"
echo "  python run.py"
echo ""
echo "To stop all services:"
echo "  ./stop_services.sh"
echo ""
echo -e "${GREEN}Ready to go! 🚀${NC}"
