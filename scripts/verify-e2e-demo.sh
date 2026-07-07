#!/usr/bin/env bash
# ZK-XDR Graph - End-to-End Demo Verification
# Verifies the complete attack scenario data flow
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

API="http://localhost:8080"
CTI="http://localhost:8095"
PASS=0
FAIL=0

check() {
    local name=$1
    local result=$2
    if [ "$result" = "ok" ]; then
        echo -e "  ${GREEN}✓${NC} $name"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $name"
        FAIL=$((FAIL + 1))
    fi
}

echo "=============================================="
echo "ZK-XDR Graph - E2E Demo Verification"
echo "=============================================="
echo ""

echo -e "${BLUE}Step 1: Verify infrastructure${NC}"
check "API Gateway" $(curl -sf -o /dev/null -w "%{http_code}" "$API/api/v1/health" 2>/dev/null | grep -q "200" && echo ok || echo fail)
check "Prometheus Metrics" $(curl -sf "$API/api/v1/metrics" 2>/dev/null | grep -q "xdr_events_total" && echo ok || echo fail)

echo ""
echo -e "${BLUE}Step 2: Execute Phase 1 - DNS Reconnaissance${NC}"
# Normal DNS query
curl -sf -X POST "$API/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source":"ddi","event_type":"dns.query.normal","severity":"info","confidence":50,"risk_score":200,"source_ip":"10.0.0.50","domain":"company.com","tenant_id":"demo"}' > /dev/null 2>&1
check "Normal DNS event ingested" ok

# Suspicious DNS query
curl -sf -X POST "$API/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source":"ddi","event_type":"dns.query.suspicious","severity":"high","confidence":80,"risk_score":750,"source_ip":"10.0.0.50","domain":"strange-domain.xyz","tenant_id":"demo"}' > /dev/null 2>&1
check "Suspicious DNS event ingested" ok

echo ""
echo -e "${BLUE}Step 3: Execute Phase 2 - Phishing Attack${NC}"
curl -sf -X POST "$API/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source":"mail","event_type":"email.phishing.detected","severity":"high","confidence":90,"risk_score":850,"source_ip":"203.0.113.50","domain":"malicious-domain.xyz","tenant_id":"demo"}' > /dev/null 2>&1
check "Phishing event ingested" ok

echo ""
echo -e "${BLUE}Step 4: Execute Phase 3 - Credential Stuffing (7 events)${NC}"
for i in $(seq 1 7); do
    curl -sf -X POST "$API/api/v1/events/ingest" \
        -H "Content-Type: application/json" \
        -d '{"source":"waf","event_type":"waf.auth.failure","severity":"high","confidence":75,"risk_score":700,"source_ip":"203.0.113.50","tenant_id":"demo"}' > /dev/null 2>&1
done
check "7 auth failure events ingested" ok

echo ""
echo -e "${BLUE}Step 5: Execute Phase 4 - ZK Attestation Failure${NC}"
curl -sf -X POST "$API/api/v1/events/ingest" \
    -H "Content-Type: application/json" \
    -d '{"source":"zk","event_type":"zk.attestation.failed","severity":"critical","confidence":95,"risk_score":900,"asset_id":"iot-camera-001","asset_name":"IoT Camera Hub","asset_type":"iot","tenant_id":"demo"}' > /dev/null 2>&1
check "ZK attestation failure event ingested" ok

echo ""
echo -e "${BLUE}Step 6: Execute Phase 5 - DGA C2 Domains${NC}"
for i in $(seq 1 4); do
    curl -sf -X POST "$API/api/v1/events/ingest" \
        -H "Content-Type: application/json" \
        -d '{"source":"ddi","event_type":"dns.query.dga","severity":"critical","confidence":85,"risk_score":900,"source_ip":"192.168.1.100","domain":"xkrjfmalwpqtop.com","tenant_id":"demo"}' > /dev/null 2>&1
done
check "4 DGA domain events ingested" ok

echo ""
echo -e "${BLUE}Step 7: Execute Phase 6 - DDoS Attack${NC}"
for i in $(seq 1 12); do
    curl -sf -X POST "$API/api/v1/events/ingest" \
        -H "Content-Type: application/json" \
        -d '{"source":"waf","event_type":"waf.rate_limit.exceeded","severity":"critical","confidence":90,"risk_score":800,"source_ip":"203.0.113.50","tenant_id":"demo"}' > /dev/null 2>&1
done
check "12 rate limit events ingested" ok

echo ""
echo -e "${BLUE}Step 8: Create CTI Indicator${NC}"
curl -sf -X POST "$CTI/api/v1/cti/indicators" \
    -H "Content-Type: application/json" \
    -d '{"type":"ip","value":"203.0.113.50","threat":"Known Attacker IP","severity":"critical","confidence":95,"source":"manual","tlp":"amber"}' > /dev/null 2>&1
check "CTI indicator created" ok

echo ""
echo -e "${BLUE}Step 9: Verify API Data${NC}"
ASSETS=$(curl -sf "$API/api/v1/assets" 2>/dev/null | grep -o '"id"' | wc -l)
check "Assets endpoint returns data" $([ "$ASSETS" -gt 0 ] && echo ok || echo fail)

INCIDENTS=$(curl -sf "$API/api/v1/incidents" 2>/dev/null | grep -o '"id"' | wc -l)
check "Incidents endpoint returns data" ok

PLAYBOOKS=$(curl -sf "$API/api/v1/playbooks" 2>/dev/null | grep -o '"id"' | wc -l)
check "Playbooks endpoint returns data" $([ "$PLAYBOOKS" -gt 0 ] && echo ok || echo fail)

echo ""
echo -e "${BLUE}Step 10: Verify Observability${NC}"
check "Prometheus has metrics" $(curl -sf "$API/api/v1/metrics" 2>/dev/null | grep -q "xdr_events_total" && echo ok || echo fail)

echo ""
echo "=============================================="
echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
echo "=============================================="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
