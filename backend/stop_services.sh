#!/bin/bash

# Stop All Services Script for Zero Trust AI Innovations

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Stopping Zero Trust AI Services"
echo "=========================================="
echo ""

# Function to stop a service by PID file
stop_service() {
    local name=$1
    local pid_file="logs/${name}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping $name (PID: $pid)..."
            kill "$pid"
            rm "$pid_file"
            echo -e "${GREEN}✓ $name stopped${NC}"
        else
            echo -e "${YELLOW}$name was not running${NC}"
            rm "$pid_file"
        fi
    else
        echo -e "${YELLOW}No PID file found for $name${NC}"
    fi
}

# Stop Celery Beat
echo "Stopping Celery Beat..."
stop_service "celery-beat"
pkill -f "celery.*beat" 2>/dev/null && echo -e "${GREEN}✓ Celery beat stopped${NC}"

# Stop Celery Worker
echo "Stopping Celery Worker..."
stop_service "celery-worker"
pkill -f "celery.*worker" 2>/dev/null && echo -e "${GREEN}✓ Celery worker stopped${NC}"

# Stop IPFS
echo "Stopping IPFS..."
stop_service "ipfs"
pkill -f "ipfs daemon" 2>/dev/null && echo -e "${GREEN}✓ IPFS stopped${NC}"

# Stop Ganache
echo "Stopping Ganache..."
stop_service "ganache"
pkill -f ganache 2>/dev/null && echo -e "${GREEN}✓ Ganache stopped${NC}"

# Stop RabbitMQ
echo "Stopping RabbitMQ..."
brew services stop rabbitmq 2>/dev/null && echo -e "${GREEN}✓ RabbitMQ stopped${NC}"

# Stop Redis
echo "Stopping Redis..."
brew services stop redis 2>/dev/null && echo -e "${GREEN}✓ Redis stopped${NC}"

echo ""
echo "=========================================="
echo "All Services Stopped"
echo "=========================================="
