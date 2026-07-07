#!/usr/bin/env bash
# ZK-XDR Graph - Full Docker Demo Runner
# Starts all services, runs the 6-phase attack, and verifies data flow
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="${PROJECT_ROOT}/infra/docker-compose.local.yml"

echo "=============================================="
echo "ZK-XDR Graph - Full Docker Demo"
echo "=============================================="
echo ""

# Step 1: Start Docker stack
echo -e "${BLUE}Step 1: Starting Docker Compose stack...${NC}"
cd "${PROJECT_ROOT}"
docker compose -f "${COMPOSE_FILE}" up --build -d

# Step 2: Wait for services
echo -e "${BLUE}Step 2: Waiting for services to be ready...${NC}"
MAX_WAIT=120
WAITED=0
SERVICES=(
    "http://localhost:8080/api/v1/health"
    "http://localhost:3000"
    "http://localhost:3001/api/health"
    "http://localhost:9090/-/healthy"
)

while [ $WAITED -lt $MAX_WAIT ]; do
    ALL_UP=true
    for url in "${SERVICES[@]}"; do
        if ! curl -sf "$url" > /dev/null 2>&1; then
            ALL_UP=false
            break
        fi
    done
    if $ALL_UP; then
        echo -e "  ${GREEN}All core services ready${NC}"
        break
    fi
    WAITED=$((WAITED + 5))
    echo "  Waiting... (${WAITED}s/${MAX_WAIT}s)"
    sleep 5
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo -e "${YELLOW}Some services may not be ready yet, continuing anyway...${NC}"
fi

# Step 3: Verify API Gateway
echo -e "${BLUE}Step 3: Verifying API Gateway...${NC}"
HEALTH=$(curl -sf http://localhost:8080/api/v1/health 2>/dev/null)
if echo "$HEALTH" | grep -q "ok\|healthy\|status"; then
    echo -e "  ${GREEN}✓ API Gateway healthy${NC}"
else
    echo -e "  ${RED}✗ API Gateway not responding${NC}"
fi

# Step 4: Run 6-Phase Attack
echo ""
echo -e "${BLUE}Step 4: Executing 6-Phase Attack Scenario${NC}"
echo ""

# Phase 1: DNS Reconnaissance
echo "  Phase 1: DNS Reconnaissance"
for domain in company.com internal.dev research.company.com; do
    curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"ddi\",\"event_type\":\"dns.query.normal\",\"severity\":\"info\",\"confidence\":50,\"risk_score\":200,\"source_ip\":\"10.0.0.50\",\"domain\":\"${domain}\",\"tenant_id\":\"demo\"}" > /dev/null 2>&1
done
# Suspicious DNS
for domain in strange-domain.xyz login-verify.top; do
    curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"ddi\",\"event_type\":\"dns.query.suspicious\",\"severity\":\"high\",\"confidence\":80,\"risk_score\":750,\"source_ip\":\"10.0.0.50\",\"domain\":\"${domain}\",\"tenant_id\":\"demo\"}" > /dev/null 2>&1
done
echo -e "  ${GREEN}✓ 5 DNS events ingested${NC}"

# Phase 2: Phishing Attack
echo "  Phase 2: Phishing Email Campaign"
curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{"source":"mail","event_type":"email.phishing.detected","severity":"high","confidence":92,"risk_score":850,"source_ip":"203.0.113.50","domain":"malicious-domain.xyz","tenant_id":"demo"}' > /dev/null 2>&1
curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{"source":"mail","event_type":"email.suspicious_attachment","severity":"high","confidence":75,"risk_score":700,"tenant_id":"demo"}' > /dev/null 2>&1
echo -e "  ${GREEN}✓ 2 phishing events ingested${NC}"

# Phase 3: Credential Stuffing
echo "  Phase 3: Credential Stuffing (7 attempts)"
for i in $(seq 1 7); do
    curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"waf\",\"event_type\":\"waf.auth.failure\",\"severity\":\"high\",\"confidence\":75,\"risk_score\":700,\"source_ip\":\"203.0.113.50\",\"tenant_id\":\"demo\"}" > /dev/null 2>&1
done
echo -e "  ${GREEN}✓ 7 auth failure events ingested${NC}"

# Phase 4: Device Compromise (ZK Attestation Failure)
echo "  Phase 4: IoT Device Compromise"
curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
    -H "Content-Type: application/json" \
    -d '{"source":"zk","event_type":"zk.attestation.failed","severity":"critical","confidence":95,"risk_score":900,"asset_id":"iot-camera-001","asset_name":"IoT Camera Hub","asset_type":"iot","tenant_id":"demo"}' > /dev/null 2>&1
echo -e "  ${GREEN}✓ ZK attestation failure event ingested${NC}"

# Phase 5: DGA C2 Communication
echo "  Phase 5: DGA C2 Domains (4 queries)"
for i in $(seq 1 4); do
    curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"ddi\",\"event_type\":\"dns.query.dga\",\"severity\":\"critical\",\"confidence\":85,\"risk_score\":900,\"source_ip\":\"192.168.1.100\",\"domain\":\"xkrjfmalwpqtop.com\",\"tenant_id\":\"demo\"}" > /dev/null 2>&1
done
echo -e "  ${GREEN}✓ 4 DGA domain events ingested${NC}"

# Phase 6: DDoS Attack
echo "  Phase 6: DDoS Attack (12 requests)"
for i in $(seq 1 12); do
    curl -sf -X POST http://localhost:8080/api/v1/events/ingest \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"waf\",\"event_type\":\"waf.rate_limit.exceeded\",\"severity\":\"critical\",\"confidence\":90,\"risk_score\":800,\"source_ip\":\"203.0.113.50\",\"tenant_id\":\"demo\"}" > /dev/null 2>&1
done
echo -e "  ${GREEN}✓ 12 rate limit events ingested${NC}"

# Step 5: Create CTI Indicators
echo ""
echo -e "${BLUE}Step 5: Creating CTI Indicators...${NC}"
for ioc in '{"type":"ip","value":"203.0.113.50","threat":"Known Attacker IP","severity":"critical","confidence":95,"source":"manual","tlp":"amber"}' \
           '{"type":"domain","value":"malicious-domain.xyz","threat":"Phishing Domain","severity":"high","confidence":88,"source":"manual","tlp":"amber"}' \
           '{"type":"hash","value":"e3b0c44298fc1c149afbf4c8996fb924","threat":"Ransomware Sample","severity":"critical","confidence":92,"source":"manual","tlp":"red"}'; do
    curl -sf -X POST http://localhost:8095/api/v1/cti/indicators \
        -H "Content-Type: application/json" \
        -d "$ioc" > /dev/null 2>&1
done
echo -e "  ${GREEN}✓ 3 CTI indicators created${NC}"

# Step 6: Wait for processing
echo ""
echo -e "${BLUE}Step 6: Waiting for event processing (60s)...${NC}"
sleep 60

# Step 7: Verify Data Flow
echo ""
echo -e "${BLUE}Step 7: Verifying Data Flow${NC}"

# Check events
EVENTS=$(curl -sf http://localhost:8080/api/v1/incidents 2>/dev/null)
echo -e "  Incidents: ${GREEN}$(echo "$EVENTS" | grep -o '"id"' | wc -l | tr -d ' ')${NC} created"

# Check playbooks
PLAYBOOKS=$(curl -sf http://localhost:8080/api/v1/playbooks 2>/dev/null)
echo -e "  Playbooks: ${GREEN}$(echo "$PLAYBOOKS" | grep -o '"id"' | wc -l | tr -d ' ')${NC} available"

# Check metrics
METRICS=$(curl -sf http://localhost:8080/api/v1/metrics 2>/dev/null)
if echo "$METRICS" | grep -q "xdr_events_total"; then
    echo -e "  Prometheus: ${GREEN}✓${NC} metrics flowing"
else
    echo -e "  Prometheus: ${RED}✗${NC} no metrics"
fi

# Check Grafana
if curl -sf http://localhost:3001/api/health > /dev/null 2>&1; then
    echo -e "  Grafana: ${GREEN}✓${NC} accessible at http://localhost:3001"
else
    echo -e "  Grafana: ${RED}✗${NC} not accessible"
fi

# Check Prometheus
if curl -sf http://localhost:9090/-/healthy > /dev/null 2>&1; then
    echo -e "  Prometheus: ${GREEN}✓${NC} accessible at http://localhost:9090"
else
    echo -e "  Prometheus: ${RED}✗${NC} not accessible"
fi

echo ""
echo "=============================================="
echo -e "${GREEN}Demo Complete!${NC}"
echo ""
echo "Access Points:"
echo "  SOC Console:     http://localhost:3000"
echo "  Grafana:         http://localhost:3001 (admin/admin)"
echo "  Prometheus:      http://localhost:9090"
echo "  API Gateway:     http://localhost:8080"
echo "  Neo4j Browser:   http://localhost:7474 (neo4j/changeme)"
echo "  ClickHouse:      http://localhost:8123"
echo "  MinIO Console:   http://localhost:9001 (minioadmin/minioadmin)"
echo ""
echo "To stop: docker compose -f ${COMPOSE_FILE} down"
echo "=============================================="
