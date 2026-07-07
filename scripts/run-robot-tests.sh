#!/usr/bin/env bash
# ZK-XDR Graph - Robot Framework Test Runner
set -e

ROBOT_DIR="$(cd "$(dirname "$0")/../tests/robot" && pwd)"
RESULTS_DIR="${ROBOT_DIR}/results"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=============================================="
echo "ZK-XDR Graph - Robot Framework Test Suite"
echo "=============================================="
echo ""

mkdir -p "${RESULTS_DIR}"

# Check if services are running
echo "Checking services..."
if ! curl -sf http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: API Gateway not running. Start with: make up${NC}"
fi

# Install Robot Framework if needed
if ! command -v robot &> /dev/null; then
    echo "Installing Robot Framework..."
    pip install -r "${ROBOT_DIR}/requirements.txt"
fi

# Parse arguments
TAGS=""
OUTPUT_FORMAT="--outputdir ${RESULTS_DIR}"

if [ "$1" = "health" ]; then
    TAGS="--include health --include smoke"
elif [ "$1" = "crud" ]; then
    TAGS="--include crud"
elif [ "$1" = "pipeline" ]; then
    TAGS="--include pipeline"
elif [ "$1" = "e2e" ]; then
    TAGS="--include e2e --include demo"
elif [ "$1" = "auth" ]; then
    TAGS="--include auth"
elif [ "$1" = "negative" ]; then
    TAGS="--include negative"
elif [ "$1" = "smoke" ]; then
    TAGS="--include smoke"
elif [ -n "$1" ]; then
    TAGS="--include $1"
fi

echo "Running tests: ${TAGS:-all}"
echo ""

# Run Robot Framework
robot ${TAGS} ${OUTPUT_FORMAT} \
    --loglevel DEBUG \
    --timestampoutputs \
    --name "ZK-XDR-Graph" \
    "${ROBOT_DIR}/tests/"

EXIT_CODE=$?

echo ""
echo "=============================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed (exit code: $EXIT_CODE)${NC}"
fi
echo "Results: ${RESULTS_DIR}/log.html"
echo "Report:  ${RESULTS_DIR}/report.html"
echo "=============================================="

exit $EXIT_CODE
