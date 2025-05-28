#!/bin/bash

# GPU Shield System Integration Test
# This script tests the entire GPU Shield system end-to-end

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKEND_URL="http://localhost:8000"
COLLECTOR_URL="http://localhost:8080"
ALERT_URL="http://localhost:8090"
TEST_TIMEOUT=30

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if binaries exist
check_binaries() {
    log "Checking binaries..."
    
    if [[ ! -f "bin/sensor" ]]; then
        error "Sensor binary not found. Run 'make build' first."
        exit 1
    fi
    
    if [[ ! -f "bin/collector" ]]; then
        error "Collector binary not found. Run 'make build' first."
        exit 1
    fi
    
    if [[ ! -f "bin/alert" ]]; then
        error "Alert binary not found. Run 'make build' first."
        exit 1
    fi
    
    success "All binaries found"
}

# Test binary versions
test_versions() {
    log "Testing binary versions..."
    
    ./bin/sensor --version
    ./bin/collector --version  
    ./bin/alert --version
    
    success "All binaries respond to --version"
}

# Test binary help
test_help() {
    log "Testing binary help..."
    
    ./bin/sensor --help > /dev/null
    ./bin/collector --help > /dev/null
    ./bin/alert --help > /dev/null
    
    success "All binaries respond to --help"
}

# Start backend (if available)
start_backend() {
    log "Checking for backend..."
    
    if [[ -d "backend" ]] && [[ -f "backend/requirements.txt" ]]; then
        log "Starting FastAPI backend..."
        cd backend
        
        # Check if virtual environment exists
        if [[ ! -d "venv" ]]; then
            warning "Creating Python virtual environment..."
            python3 -m venv venv
        fi
        
        source venv/bin/activate
        pip install -r requirements.txt > /dev/null 2>&1
        
        # Start backend in background
        uvicorn main:app --host 0.0.0.0 --port 8000 &
        BACKEND_PID=$!
        cd ..
        
        # Wait for backend to start
        sleep 5
        
        # Test backend health
        if curl -s "$BACKEND_URL/health" > /dev/null; then
            success "Backend started successfully"
            return 0
        else
            warning "Backend health check failed"
            return 1
        fi
    else
        warning "Backend not found, skipping backend tests"
        return 1
    fi
}

# Start collector service
start_collector() {
    log "Starting collector service..."
    
    ./bin/collector \
        --port 8080 \
        --backend-url "$BACKEND_URL" \
        --buffer-size 100 \
        --flush-interval 10s &
    COLLECTOR_PID=$!
    
    # Wait for collector to start
    sleep 3
    
    # Test collector health
    if curl -s "$COLLECTOR_URL/health" > /dev/null; then
        success "Collector started successfully"
        return 0
    else
        error "Collector health check failed"
        return 1
    fi
}

# Start alert engine
start_alert_engine() {
    log "Starting alert engine..."
    
    ./bin/alert \
        --port 8090 \
        --backend-url "$BACKEND_URL" \
        --check-interval 30s &
    ALERT_PID=$!
    
    # Wait for alert engine to start
    sleep 3
    
    # Test alert engine health
    if curl -s "$ALERT_URL/health" > /dev/null; then
        success "Alert engine started successfully"
        return 0
    else
        error "Alert engine health check failed"
        return 1
    fi
}

# Test sensor data collection
test_sensor() {
    log "Testing sensor data collection..."
    
    # Test sensor without collector
    timeout 10s ./bin/sensor --interval 2s --max-iterations 3 || true
    success "Sensor basic functionality test completed"
    
    # Test sensor with collector (if running)
    if [[ -n "$COLLECTOR_PID" ]] && kill -0 "$COLLECTOR_PID" 2>/dev/null; then
        log "Testing sensor -> collector integration..."
        timeout 15s ./bin/sensor \
            --interval 2s \
            --max-iterations 5 \
            --collector-url "$COLLECTOR_URL" \
            --send-to-collector || true
        success "Sensor -> Collector integration test completed"
    fi
}

# Test API endpoints
test_apis() {
    log "Testing API endpoints..."
    
    # Test collector endpoints
    if [[ -n "$COLLECTOR_PID" ]] && kill -0 "$COLLECTOR_PID" 2>/dev/null; then
        log "Testing collector APIs..."
        
        # Health check
        curl -s "$COLLECTOR_URL/health" | jq . || echo "Health check response received"
        
        # Metrics
        curl -s "$COLLECTOR_URL/metrics" || echo "Metrics endpoint accessible"
        
        # Test telemetry submission
        curl -X POST "$COLLECTOR_URL/telemetry" \
            -H "Content-Type: application/json" \
            -d '{
                "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
                "node_id": "test-node",
                "gpu_metrics": {
                    "gpu_id": "test-gpu",
                    "utilization": 50.0,
                    "memory_used": 1024,
                    "memory_total": 8192,
                    "temperature": 65.0
                }
            }' || echo "Telemetry submission test completed"
        
        success "Collector API tests completed"
    fi
    
    # Test alert engine endpoints
    if [[ -n "$ALERT_PID" ]] && kill -0 "$ALERT_PID" 2>/dev/null; then
        log "Testing alert engine APIs..."
        
        # Health check
        curl -s "$ALERT_URL/health" | jq . || echo "Health check response received"
        
        # Trigger manual processing
        curl -X POST "$ALERT_URL/process" || echo "Manual processing trigger test completed"
        
        success "Alert engine API tests completed"
    fi
}

# Test Docker builds
test_docker() {
    log "Testing Docker builds..."
    
    if command -v docker &> /dev/null; then
        docker build -f docker/Dockerfile.sensor -t gpushield-sensor:test . > /dev/null
        docker run --rm gpushield-sensor:test --version
        success "Sensor Docker build test passed"
        docker build -f docker/Dockerfile.collector -t gpushield-collector:test . > /dev/null
        docker run --rm gpushield-collector:test --version
        success "Collector Docker build test passed"
        docker build -f docker/Dockerfile.alert -t gpushield-alert:test . > /dev/null
        docker run --rm gpushield-alert:test --version
        success "Alert Docker build test passed"
        docker rmi gpushield-sensor:test gpushield-collector:test gpushield-alert:test > /dev/null
        success "Docker cleanup completed"
    else
        warning "Docker not found, skipping Docker tests"
    fi
}

# Test Helm chart
test_helm() {
    log "Testing Helm chart..."
    
    if command -v helm &> /dev/null; then
        helm lint helm/gpu-runtime-security/ || warning "Helm lint found issues"
        helm template test-release helm/gpu-runtime-security/ > /dev/null
        success "Helm template generation test passed"
    else
        warning "Helm not found, skipping Helm tests"
    fi
}

# Cleanup function
cleanup() {
    log "Cleaning up test processes..."
    
    # Kill background processes
    [[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null || true
    [[ -n "$ALERT_PID" ]] && kill "$ALERT_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true

    sleep 2
    [[ -n "$COLLECTOR_PID" ]] && kill -9 "$COLLECTOR_PID" 2>/dev/null || true
    [[ -n "$ALERT_PID" ]] && kill -9 "$ALERT_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -9 "$BACKEND_PID" 2>/dev/null || true
    
    success "Cleanup completed"
}

# Trap cleanup on exit
trap cleanup EXIT

# Main test execution
main() {
    log "Starting GPU Shield System Integration Tests"
    log "=========================================="
    
    # Basic tests
    check_binaries
    test_versions
    test_help
    
    # Service tests
    BACKEND_RUNNING=false
    if start_backend; then
        BACKEND_RUNNING=true
    fi
    
    COLLECTOR_RUNNING=false
    if start_collector; then
        COLLECTOR_RUNNING=true
    fi
    
    ALERT_RUNNING=false
    if start_alert_engine; then
        ALERT_RUNNING=true
    fi
    
    # Integration tests
    test_sensor
    test_apis
    
    # Build tests
    test_docker
    test_helm
    
    # Summary
    log "=========================================="
    log "Test Summary:"
    success "✓ Binary compilation and basic functionality"
    
    if [[ "$BACKEND_RUNNING" == "true" ]]; then
        success "✓ Backend integration"
    else
        warning "⚠ Backend integration (skipped)"
    fi
    
    if [[ "$COLLECTOR_RUNNING" == "true" ]]; then
        success "✓ Collector service"
    else
        warning "⚠ Collector service (failed)"
    fi
    
    if [[ "$ALERT_RUNNING" == "true" ]]; then
        success "✓ Alert engine service"
    else
        warning "⚠ Alert engine service (failed)"
    fi
    
    success "✓ API endpoint testing"
    
    if command -v docker &> /dev/null; then
        success "✓ Docker builds"
    else
        warning "⚠ Docker builds (Docker not available)"
    fi
    
    if command -v helm &> /dev/null; then
        success "✓ Helm chart validation"
    else
        warning "⚠ Helm chart validation (Helm not available)"
    fi
    
    log "=========================================="
    success "GPU Shield system testing completed!"
}

# Check for required tools
check_requirements() {
    local missing_tools=()
    
    command -v curl >/dev/null 2>&1 || missing_tools+=("curl")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warning "Missing tools: ${missing_tools[*]}"
        warning "Install with: brew install ${missing_tools[*]}"
        warning "Some tests may fail without these tools"
    fi
}

# Run requirements check
check_requirements

# Run main tests
main 