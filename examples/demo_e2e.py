#!/usr/bin/env python3
"""
ZK-XDR Graph - End-to-End Demo Attack Scenario

Simulates a coordinated attack across all XDR pillars:
1. IoT device compromise (ZK attestation failure)
2. Lateral movement (DNS tunneling)
3. Data exfiltration (WAF evasion)
4. Phishing campaign (email vector)
5. C2 communication (DGA domains)
6. Privilege escalation (API abuse)

Each step generates events that flow through the full pipeline:
Connectors → Redis Streams → Normalizer → Risk Scoring → Correlation → SOAR
"""

import json
import time
import uuid
import sys
from datetime import datetime, timezone

try:
    import redis
except ImportError:
    print("Install redis-py: pip install redis")
    sys.exit(1)


def generate_event_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_event(source: str, event_type: str, severity: str, **kwargs) -> dict:
    base = {
        "event_id": generate_event_id(source),
        "tenant_id": "t1",
        "timestamp": timestamp(),
        "source": source,
        "event_type": event_type,
        "category": kwargs.get("category", "network"),
        "severity": severity,
        "confidence": kwargs.get("confidence", 50),
        "risk_score": kwargs.get("risk_score", 200),
        "asset_id": kwargs.get("asset_id", ""),
        "asset_name": kwargs.get("asset_name", ""),
        "mitre_tactic": kwargs.get("mitre_tactic", ""),
        "mitre_technique": kwargs.get("mitre_technique", ""),
        "source_ip": kwargs.get("source_ip", ""),
        "dest_ip": kwargs.get("dest_ip", ""),
        "domain": kwargs.get("domain", ""),
    }
    return base


def run_demo(redis_addr: str = "localhost:6379"):
    print("=" * 70)
    print("ZK-XDR Graph - End-to-End Attack Demo")
    print("=" * 70)

    r = redis.Redis(host=redis_addr.split(":")[0], port=int(redis_addr.split(":")[1]), decode_responses=True)

    try:
        r.ping()
        print(f"[OK] Connected to Redis at {redis_addr}")
    except redis.ConnectionError:
        print(f"[FAIL] Cannot connect to Redis at {redis_addr}")
        print("       Start the stack with: docker compose -f infra/docker-compose.local.yml up -d")
        return

    print("\n" + "=" * 70)
    print("PHASE 1: Initial Access - IoT Device Compromise")
    print("=" * 70)

    # Step 1: IoT camera starts beaconing to suspicious domain
    event1 = create_event(
        "ddi", "dns.query.suspicious", "high",
        category="network",
        confidence=75, risk_score=700,
        asset_id="asset_001", asset_name="IoT Camera 042",
        mitre_tactic="command-and-control",
        mitre_technique="T1071.004",
        source_ip="192.168.1.100",
        domain="strange-domain.xyz",
    )
    r.xadd("xdr:events", {"data": json.dumps(event1)})
    print(f"[SENT] {event1['event_type']} -> {event1['domain']} (severity: {event1['severity']})")

    time.sleep(0.5)

    # Step 2: ZK attestation fails for the compromised device
    event2 = create_event(
        "zk", "zk.device.attestation.failed", "critical",
        category="identity",
        confidence=95, risk_score=950,
        asset_id="asset_001", asset_name="IoT Camera 042",
        mitre_tactic="defense-evasion",
        mitre_technique="T1542",
    )
    r.xadd("xdr:events", {"data": json.dumps(event2)})
    print(f"[SENT] {event2['event_type']} (severity: {event2['severity']})")

    time.sleep(0.5)

    # Step 3: DGA domain activity from the device
    event3 = create_event(
        "ddi", "dns.query.dga", "critical",
        category="network",
        confidence=90, risk_score=900,
        asset_id="asset_001", asset_name="IoT Camera 042",
        mitre_tactic="command-and-control",
        mitre_technique="T1568.002",
        source_ip="192.168.1.100",
        domain="xkrjfmalwpq.top",
    )
    r.xadd("xdr:events", {"data": json.dumps(event3)})
    print(f"[SENT] {event3['event_type']} -> {event3['domain']} (severity: {event3['severity']})")

    print("\n" + "=" * 70)
    print("PHASE 2: Credential Access - API Abuse")
    print("=" * 70)

    # Step 4: Credential stuffing attack
    for i in range(6):
        event = create_event(
            "waf", "waf.auth.failure", "high",
            category="network",
            confidence=80, risk_score=750,
            source_ip="203.0.113.42",
            mitre_tactic="credential-access",
            mitre_technique="T1110",
        )
        r.xadd("xdr:events", {"data": json.dumps(event)})
        print(f"[SENT] {event['event_type']} (attempt {i+1}/6)")
        time.sleep(0.2)

    print("\n" + "=" * 70)
    print("PHASE 3: Initial Access - Phishing Campaign")
    print("=" * 70)

    # Step 5: Phishing emails targeting finance team
    event5 = create_event(
        "mail", "email.phishing.detected", "high",
        category="email",
        confidence=85, risk_score=800,
        asset_id="asset_002", asset_name="Workstation 003",
        mitre_tactic="initial-access",
        mitre_technique="T1566",
    )
    r.xadd("xdr:events", {"data": json.dumps(event5)})
    print(f"[SENT] {event5['event_type']} (severity: {event5['severity']})")

    time.sleep(0.5)

    # Step 6: WAF blocks suspicious request
    event6 = create_event(
        "waf", "waf.rule.blocked", "high",
        category="network",
        confidence=90, risk_score=800,
        source_ip="203.0.113.42",
        mitre_tactic="initial-access",
        mitre_technique="T1190",
    )
    r.xadd("xdr:events", {"data": json.dumps(event6)})
    print(f"[SENT] {event6['event_type']} (severity: {event6['severity']})")

    print("\n" + "=" * 70)
    print("PHASE 4: Lateral Movement - Workstation Compromise")
    print("=" * 70)

    # Step 7: Suspicious process on workstation
    event7 = create_event(
        "endpoint", "endpoint.process.suspicious", "medium",
        category="endpoint",
        confidence=70, risk_score=600,
        asset_id="asset_002", asset_name="Workstation 003",
        mitre_tactic="execution",
        mitre_technique="T1059",
    )
    r.xadd("xdr:events", {"data": json.dumps(event7)})
    print(f"[SENT] {event7['event_type']} (severity: {event7['severity']})")

    time.sleep(0.5)

    # Step 8: Network connection to C2
    event8 = create_event(
        "endpoint", "endpoint.network.suspicious_connection", "high",
        category="network",
        confidence=80, risk_score=750,
        asset_id="asset_002", asset_name="Workstation 003",
        mitre_tactic="command-and-control",
        mitre_technique="T1071",
        source_ip="192.168.1.105",
        dest_ip="203.0.113.42",
    )
    r.xadd("xdr:events", {"data": json.dumps(event8)})
    print(f"[SENT] {event8['event_type']} -> {event8['dest_ip']} (severity: {event8['severity']})")

    print("\n" + "=" * 70)
    print("PHASE 5: Impact - Data Exfiltration Attempt")
    print("=" * 70)

    # Step 9: Large outbound data transfer
    event9 = create_event(
        "waf", "waf.anomaly.detected", "critical",
        category="network",
        confidence=85, risk_score=900,
        asset_id="asset_002", asset_name="Workstation 003",
        mitre_tactic="exfiltration",
        mitre_technique="T1048",
        source_ip="192.168.1.105",
        dest_ip="203.0.113.42",
    )
    r.xadd("xdr:events", {"data": json.dumps(event9)})
    print(f"[SENT] {event9['event_type']} (severity: {event9['severity']})")

    print("\n" + "=" * 70)
    print("DEMO COMPLETE")
    print("=" * 70)
    print(f"\nTotal events sent: 12")
    print("\nEvent flow:")
    print("  Connectors → Redis Streams (xdr:events)")
    print("  → Event Normalizer (normalizes to XDR envelope)")
    print("  → Risk Scoring (updates asset trust scores)")
    print("  → Asset Graph (builds Neo4j relationships)")
    print("  → Correlation Engine (detects incidents)")
    print("  → SOAR Playbooks (automated response)")
    print("  → CTI Matcher (IoC enrichment)")
    print("  → Frontend (real-time dashboard updates)")
    print("\nWatch the logs with:")
    print("  docker compose -f infra/docker-compose.local.yml logs -f")


if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else "localhost:6379"
    run_demo(addr)
