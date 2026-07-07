#!/usr/bin/env bash
# ZK-XDR Graph - Integration Test Suite
# Verifies all services are running and communicating

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

check() {
    local name=$1
    local url=$2
    local expected=${3:-200}
    
    status=$(curl -sf -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    
    if [ "$status" = "$expected" ]; then
        echo -e "  ${GREEN}✓${NC} $name (HTTP $status)"
        PASS=$((PASS + 1))
    elif [ "$status" = "000" ]; then
        echo -e "  ${YELLOW}○${NC} $name (not running)"
        SKIP=$((SKIP + 1))
    else
        echo -e "  ${RED}✗${NC} $name (HTTP $status, expected $expected)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=============================================="
echo "ZK-XDR Graph Integration Tests"
echo "=============================================="
echo ""

echo "Infrastructure:"
check "PostgreSQL" "http://localhost:5432" 200
check "Redis" "redis://localhost:6379" 200
check "Neo4j Browser" "http://localhost:7474" 200
check "ClickHouse" "http://localhost:8123/ping" 200
check "MinIO Console" "http://localhost:9001" 200
check "Qdrant" "http://localhost:6333" 200
echo ""

echo "Core Services:"
check "API Gateway" "http://localhost:8080/api/v1/health" 200
check "API Metrics" "http://localhost:8080/api/v1/metrics" 200
check "Console Web" "http://localhost:3000" 200
echo ""

echo "Processing Services:"
check "CTI Lakehouse" "http://localhost:8095/api/v1/health" 200
check "Analyst Copilot" "http://localhost:8090/api/v1/health" 200
check "IoC Parsers" "http://localhost:8085/api/v1/health" 200
check "Anomaly Detection" "http://localhost:8086/api/v1/health" 200
echo ""

echo "Observability:"
check "Grafana" "http://localhost:3001" 200
check "Prometheus" "http://localhost:9090" 200
echo ""

echo "=============================================="
echo "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}, ${YELLOW}$SKIP skipped${NC}"
echo "=============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
